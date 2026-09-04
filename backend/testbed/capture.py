"""Packet capture inside a peer container.

Implementation-plan step 2.5.

tcpdump runs in the peer rather than on the bridge from outside, because the
container network namespace is the only place the traffic is guaranteed to be
visible in the form a real analyst would see it: outer IP headers, ESP, and the
IKE exchange that set it up.

The one thing this module must never do is return a PCAP that looks fine and is
not. tcpdump buffers, and a killed-not-signalled tcpdump leaves a truncated file
whose last few hundred packets never reached disk. ``stop`` sends SIGINT, waits
for the process to actually exit, and then refuses to hand back a capture with
no packets in it.
"""

from __future__ import annotations

import asyncio
import io
import logging
import shlex
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from testbed.peers import PeerHandle, TestbedError

log = logging.getLogger(__name__)

CAPTURE_DIR: Final = "/captures"
PID_FILE: Final = "/tmp/tcpdump.pid"
LOG_FILE: Final = "/tmp/tcpdump.log"

DEFAULT_FILTER: Final = "esp or ah or udp port 500 or udp port 4500"
"""What an analyst pointing tcpdump at an IPsec gateway would actually write.

Filtering rather than capturing everything is deliberate. The peers also emit
ARP, IPv6 neighbour discovery and multicast chatter that has nothing to do with
the tunnel, and a model trained on unfiltered captures would have that container
noise available as signal -- signal that does not exist in the deployments this
tool is meant to analyse.
"""

STOP_TIMEOUT_S: Final = 15.0


@dataclass
class Capture:
    """A running tcpdump, and the file it is writing."""

    peer: PeerHandle
    container_path: str
    dest: Path
    interface: str
    _stopped: bool = False

    async def stop(self) -> Path:
        """Stop tcpdump, copy the PCAP out, and return its path on the host.

        Raises if the capture is empty. An empty PCAP paired with a valid
        ``labels.json`` is worse than a failed session: the batch reports
        success and the row poisons whatever is trained on it.
        """
        if self._stopped:
            return self.dest
        self._stopped = True

        # SIGINT, not SIGKILL. tcpdump flushes its buffers and writes the pcap
        # trailer on INT; on KILL it does neither.
        await self.peer.exec(
            ["sh", "-c", f"kill -INT $(cat {PID_FILE}) 2>/dev/null || true"],
            check=False,
            timeout_s=10,
        )

        deadline = time.monotonic() + STOP_TIMEOUT_S
        while time.monotonic() < deadline:
            if await self._tcpdump_finished():
                break
            await asyncio.sleep(0.25)
        else:
            log.warning("[%s] tcpdump did not exit within %ss", self.peer.name, STOP_TIMEOUT_S)

        _, tcpdump_log = await self.peer.exec(
            ["sh", "-c", f"cat {LOG_FILE} 2>/dev/null || true"], check=False
        )
        log.debug("[%s] tcpdump: %s", self.peer.name, tcpdump_log.strip())

        await self._copy_out()

        packets = await self.packet_count()
        if packets == 0:
            raise TestbedError(
                f"[{self.peer.name}] capture on {self.interface} contains no packets.\n"
                f"tcpdump said:\n{tcpdump_log.strip() or '(nothing)'}\n\n"
                "A session that produced no traffic must fail rather than be "
                "written to the dataset with labels describing a tunnel."
            )
        log.info("[%s] captured %d packets to %s", self.peer.name, packets, self.dest)
        return self.dest

    async def _tcpdump_finished(self) -> bool:
        """Has the tcpdump process finished writing?

        A plain ``kill -0`` is not enough. Nothing in the peer container reaps
        children -- charon is PID 1 and does not act as an init -- so the exited
        tcpdump lingers as a zombie, ``kill -0`` keeps succeeding, and the wait
        loop always runs to its timeout. A zombie has written everything it is
        ever going to write, so state ``Z`` counts as finished.
        """
        _, state = await self.peer.exec(
            [
                "sh",
                "-c",
                f"awk '{{print $3}}' /proc/$(cat {PID_FILE})/stat 2>/dev/null || echo GONE",
            ],
            check=False,
            timeout_s=10,
        )
        return state.strip() in {"GONE", "Z", ""}

    async def packet_count(self) -> int:
        """Count packets in the captured file, using tcpdump in the peer.

        Counted inside the container because the peer image is where a pinned
        tcpdump lives; the host may have no capture tooling at all.
        """
        _, output = await self.peer.exec(
            ["sh", "-c", f"tcpdump -r {self.container_path} -n 2>/dev/null | wc -l"],
            check=False,
            timeout_s=60,
        )
        try:
            return int(output.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return 0

    async def _copy_out(self) -> None:
        """Pull the PCAP out of the container into ``dest``."""

        def _fetch() -> bytes:
            stream, _ = self.peer.container.get_archive(self.container_path)
            return b"".join(stream)

        blob = await asyncio.to_thread(_fetch)

        def _extract() -> None:
            self.dest.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
                member = next((m for m in tar.getmembers() if m.isfile()), None)
                if member is None:
                    raise TestbedError(
                        f"[{self.peer.name}] {self.container_path} was not in the archive"
                    )
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise TestbedError(f"[{self.peer.name}] could not read {self.container_path}")
                self.dest.write_bytes(extracted.read())

        await asyncio.to_thread(_extract)


async def start_tcpdump(
    peer: PeerHandle,
    dest: Path,
    *,
    interface: str = "eth0",
    capture_filter: str = DEFAULT_FILTER,
    snaplen: int = 0,
    filename: str = "capture.pcap",
) -> Capture:
    """Start tcpdump in ``peer`` and return a handle that can stop it.

    ``snaplen=0`` captures whole packets. Step 3.6 needs captures truncated to
    96 bytes to exercise the ``truncated`` flag of ``CaptureQuality``, which is
    why it is a parameter rather than a constant.
    """
    container_path = f"{CAPTURE_DIR}/{filename}"

    command = (
        f"tcpdump -i {shlex.quote(interface)} -n -U -s {snaplen} "
        f"-w {shlex.quote(container_path)} {shlex.quote(capture_filter)}"
    )
    # Backgrounded with its PID recorded, so stop() can signal exactly this
    # process. `pkill tcpdump` would be simpler and would also kill a capture
    # belonging to a different session sharing the container.
    await peer.exec(
        [
            "sh",
            "-c",
            f"mkdir -p {CAPTURE_DIR} && rm -f {container_path} && "
            f"{command} >{LOG_FILE} 2>&1 & echo $! > {PID_FILE}",
        ],
        timeout_s=20,
    )

    await _await_listening(peer)
    log.info("[%s] capturing %s on %s", peer.name, capture_filter, interface)
    return Capture(peer=peer, container_path=container_path, dest=dest, interface=interface)


async def _await_listening(peer: PeerHandle, *, timeout_s: float = 10.0) -> None:
    """Wait until tcpdump reports that it is listening.

    Without this, the IKE exchange initiated microseconds later is missed, and
    the capture opens mid-tunnel with no negotiation in it -- which is a
    perfectly valid analyst scenario and exactly the wrong thing to label as a
    complete session.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        _, output = await peer.exec(
            ["sh", "-c", f"cat {LOG_FILE} 2>/dev/null || true"], check=False, timeout_s=10
        )
        if "listening on" in output:
            return
        if "ERROR" in output or "syntax error" in output:
            raise TestbedError(f"[{peer.name}] tcpdump failed to start:\n{output.strip()}")
        await asyncio.sleep(0.2)

    _, output = await peer.exec(["sh", "-c", f"cat {LOG_FILE} 2>/dev/null || true"], check=False)
    raise TestbedError(
        f"[{peer.name}] tcpdump did not report listening within {timeout_s}s:\n{output.strip()}"
    )
