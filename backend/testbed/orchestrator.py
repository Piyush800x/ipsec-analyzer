"""Run one labelled testbed session end to end.

Implementation-plan step 2.8, LLD section 10.2.

The order of operations in ``run_session`` is not arbitrary and each step is
load-bearing:

1. Start the capture *before* initiating, so the IKE negotiation is inside it.
   A capture that opens mid-tunnel is a legitimate analyst scenario (step 11.1
   tests for it) and the wrong thing to label as a complete session.
2. Assert the SA is established before generating traffic. LLD section 10.2
   calls this non-negotiable: without it a failed negotiation yields a PCAP of
   retries carrying a label that describes a working tunnel.
3. Tear the tunnel down *inside* the capture window, so the DELETE exchange is
   recorded. Real captures contain them.
4. Only then stop the capture and write the labels.

Nothing is written to the output directory until the capture has been proven
non-empty, so a failed session leaves no half-written row behind for the batch
runner to mistake for a completed one.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from testbed.capture import Capture, start_tcpdump
from testbed.config import SessionConfig
from testbed.peers import PeerHandle, TestbedError, peer_pair
from testbed.traffic import generate_traffic
from testbed.tunnel import assert_sa_established, bring_up_tunnel, stop_tunnel

log = logging.getLogger(__name__)

PCAP_NAME: Final = "capture.pcap"
LABELS_NAME: Final = "labels.json"

IKE_FILTER: Final = "udp port 500 or udp port 4500"

TEARDOWN_DRAIN_S: Final = 2.0
"""How long to let tcpdump drain after the tunnel is torn down.

Comfortably longer than the one-second poll timeout tcpdump uses to read the
kernel ring buffer. Two seconds per session is a rounding error against a
three-minute capture, and the alternative is a dataset in which no capture
contains the teardown it was designed to contain.
"""


@dataclass(frozen=True)
class SessionResult:
    """What one session produced."""

    config: SessionConfig
    pcap: Path
    labels_path: Path
    labels: dict[str, Any]
    packet_count: int
    duration_s: float

    @property
    def has_ike_delete(self) -> bool:
        observed: dict[str, Any] = self.labels["observed"]
        return bool(observed["has_ike_delete"])


async def run_session(
    cfg: SessionConfig,
    output_dir: Path,
    *,
    snaplen: int = 0,
) -> SessionResult:
    """Build the tunnel described by ``cfg``, capture it, and label it."""
    started = time.monotonic()
    session_dir = output_dir / cfg.name
    pcap_path = session_dir / PCAP_NAME

    async with peer_pair(cfg) as (left, right):
        capture = await start_tcpdump(left, pcap_path, snaplen=snaplen)

        await bring_up_tunnel(left, right, cfg)
        state = await assert_sa_established(left)

        await generate_traffic(left, right, cfg.traffic, cfg.duration_s)

        # Counted before the teardown so that the DELETE exchange can be
        # confirmed to have landed inside the capture rather than assumed.
        ike_before = await _count_matching(capture, IKE_FILTER)
        await stop_tunnel(left)

        # Let the capture drain before counting or closing it. tcpdump reads
        # from the kernel ring buffer on a poll timeout of roughly a second even
        # with -U, and stopping it sooner discards whatever has not been drained
        # yet -- which is precisely the DELETE exchange we just went out of our
        # way to put inside the capture window. It shows up as "N packets
        # captured, N+8 received by filter" and a capture that ends on the last
        # ESP packet.
        await asyncio.sleep(TEARDOWN_DRAIN_S)

        ike_after = await _count_matching(capture, IKE_FILTER)
        log.debug("[%s] IKE packets before=%d after=%d", cfg.name, ike_before, ike_after)

        image_versions = await _image_versions(left)
        pcap = await capture.stop()
        packet_count = await capture.packet_count()

    has_delete = ike_after > ike_before
    if not has_delete:
        # Not fatal: plenty of real captures end without a clean teardown, and
        # the session is otherwise sound. It is recorded either way so that
        # step 3.6 has ground truth for `ike_complete` rather than a guess.
        log.warning(
            "[%s] no IKE packets followed the teardown; capture has no DELETE exchange",
            cfg.name,
        )

    labels = cfg.to_ground_truth(image_versions=image_versions)
    labels["observed"] = {
        "packet_count": packet_count,
        "ike_packets": ike_after,
        "has_ike_delete": has_delete,
        "negotiated_ike": state.ike_algs,
        "negotiated_esp": state.child_algs,
    }

    labels_path = session_dir / LABELS_NAME
    labels_path.write_text(json.dumps(labels, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    elapsed = time.monotonic() - started
    log.info(
        "[%s] session complete: %d packets, %.1fs, delete=%s",
        cfg.name,
        packet_count,
        elapsed,
        has_delete,
    )
    return SessionResult(
        config=cfg,
        pcap=pcap,
        labels_path=labels_path,
        labels=labels,
        packet_count=packet_count,
        duration_s=elapsed,
    )


async def _count_matching(capture: Capture, expression: str) -> int:
    """Count packets in the in-progress capture matching ``expression``.

    Reading a file tcpdump is still writing is safe here because the capture
    runs packet-buffered (``-U``), so every packet already accounted for has
    reached disk. A partial final packet is possible and would be miscounted by
    one, which does not matter for a before-and-after comparison.
    """
    _, output = await capture.peer.exec(
        [
            "sh",
            "-c",
            f"tcpdump -r {capture.container_path} -n '{expression}' 2>/dev/null | wc -l",
        ],
        check=False,
        timeout_s=60,
    )
    try:
        return int(output.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


async def _image_versions(peer: PeerHandle) -> dict[str, str]:
    """Read the build manifest baked into the peer image.

    Recorded per session so a capture generated weeks ago can still say which
    strongSwan produced its packet geometry, without anyone having to reconstruct
    which image tag was current at the time.
    """
    code, output = await peer.exec(["cat", "/etc/testbed-versions.json"], check=False, timeout_s=10)
    if code != 0:
        return {}
    try:
        parsed: dict[str, str] = json.loads(output)
    except json.JSONDecodeError:
        log.warning("[%s] /etc/testbed-versions.json is not valid JSON", peer.name)
        return {}
    return parsed


def load_result(session_dir: Path) -> dict[str, Any]:
    """Read back the labels of a completed session."""
    labels_path = session_dir / LABELS_NAME
    if not labels_path.is_file():
        raise TestbedError(f"{session_dir} has no {LABELS_NAME}")
    parsed: dict[str, Any] = json.loads(labels_path.read_text(encoding="utf-8"))
    return parsed
