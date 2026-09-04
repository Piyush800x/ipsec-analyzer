"""Bring a tunnel up, prove it is up, and tear it down.

Implementation-plan step 2.4, LLD section 10.2.

The assertion in this module is the reason it exists. LLD section 10.2 puts it
plainly: without ``assert_sa_established`` between bring-up and traffic
generation, a failed negotiation produces a capture full of IKE retries carrying
a label that says it is a working 3DES tunnel. That row is then indistinguishable
from a real one until a model trained on it behaves strangely, at which point the
cause is weeks behind you.

So every failure here raises. Nothing in this module returns a value that a
caller could mistake for success.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import Final

from testbed.config import SessionConfig
from testbed.peers import PeerHandle, TestbedError
from testbed.render import CHILD_NAME, CONNECTION_NAME, render_swanctl_conf

log = logging.getLogger(__name__)

SWANCTL_CONF_PATH: Final = "/etc/swanctl/swanctl.conf"

CHARON_READY_TIMEOUT_S: Final = 30.0
SA_ESTABLISH_TIMEOUT_S: Final = 45.0
POLL_INTERVAL_S: Final = 0.5

_LOAD_FAILURE: Final = re.compile(r"failed to load|loaded 0 of|unable to load", re.IGNORECASE)
_IKE_ESTABLISHED: Final = re.compile(rf"^\s*{CONNECTION_NAME}:.*\bESTABLISHED\b", re.MULTILINE)
_CHILD_INSTALLED: Final = re.compile(rf"^\s*{CHILD_NAME}:.*\bINSTALLED\b", re.MULTILINE)

# `testbed: #1, ESTABLISHED, IKEv2, <spi_i>_i* <spi_r>_r` followed by an
# indented line naming the negotiated IKE algorithms.
_IKE_ALGS: Final = re.compile(
    r"^\s{2,}((?:AES|3DES|DES|CAMELLIA)[A-Z0-9_/-]*(?:/[A-Z0-9_-]+)+)\s*$", re.MULTILINE
)
_CHILD_ALGS: Final = re.compile(r"\b(?:ESP|AH):([A-Z0-9_/-]+)", re.IGNORECASE)


@dataclass(frozen=True)
class TunnelState:
    """What ``swanctl --list-sas`` reported, parsed.

    ``ike_algs`` and ``child_algs`` are recorded rather than merely checked so
    that the session labels can carry what was actually negotiated alongside
    what was configured. If those two ever diverge, the dataset should say so
    rather than assert the configured value and move on.
    """

    established: bool
    child_installed: bool
    ike_algs: str | None
    child_algs: str | None
    raw: str


def parse_sas(listing: str) -> TunnelState:
    """Parse the human-readable output of ``swanctl --list-sas``.

    The ``--raw`` vici dump would be more machine-friendly and considerably
    harder to read in a failure message. strongSwan is version-pinned in the
    peer image, so the human format is stable for our purposes; if that pin
    moves, this is one of the things that has to be rechecked.
    """
    ike_match = _IKE_ALGS.search(listing)
    child_match = _CHILD_ALGS.search(listing)
    return TunnelState(
        established=bool(_IKE_ESTABLISHED.search(listing)),
        child_installed=bool(_CHILD_INSTALLED.search(listing)),
        ike_algs=ike_match.group(1) if ike_match else None,
        child_algs=child_match.group(1) if child_match else None,
        raw=listing,
    )


async def wait_for_charon(peer: PeerHandle, *, timeout_s: float = CHARON_READY_TIMEOUT_S) -> None:
    """Block until the vici socket answers.

    The container is running as soon as Docker says so, but charon takes a
    moment to load its plugins and bind the socket. Loading a config into a
    daemon that is not listening yet fails with a connection error that reads
    like a permissions problem.
    """
    deadline = time.monotonic() + timeout_s
    last_output = ""
    while time.monotonic() < deadline:
        code, output = await peer.exec(["swanctl", "--stats"], check=False, timeout_s=10)
        if code == 0:
            return
        last_output = output
        await asyncio.sleep(POLL_INTERVAL_S)

    logs = await peer.logs(tail=40)
    raise TestbedError(
        f"[{peer.name}] charon did not become ready within {timeout_s}s.\n"
        f"last swanctl error:\n{last_output.strip()}\n\ncontainer log:\n{logs}"
    )


async def load_config(peer: PeerHandle, cfg: SessionConfig) -> None:
    """Render and load the swanctl configuration for one peer.

    Both the exit code and the output are checked. ``swanctl --load-all`` loads
    connections, secrets, pools and authorities in one pass and reports on each
    separately, so the failure that matters here -- a connection discarded --
    must not be able to slip through on an overall success. It is a cheap
    belt-and-braces check against an expensive symptom: a daemon left running
    with no connections reports "CHILD_SA config not found" at the next step,
    which sends you looking in the wrong place entirely.
    """
    await peer.write_file(SWANCTL_CONF_PATH, render_swanctl_conf(cfg, peer.side))
    code, output = await peer.exec(["swanctl", "--load-all"], check=False, timeout_s=30)

    if code != 0 or _LOAD_FAILURE.search(output):
        raise TestbedError(
            f"[{peer.name}] strongSwan rejected the rendered configuration "
            f"(swanctl --load-all exited {code}):\n"
            f"{output.strip()}\n\n"
            f"proposals were ike={cfg.ike_proposal} esp={cfg.esp_proposal}"
        )
    log.debug("[%s] loaded config: %s", peer.name, output.strip())


async def bring_up_tunnel(
    initiator: PeerHandle,
    responder: PeerHandle,
    cfg: SessionConfig,
    *,
    responder_cfg: SessionConfig | None = None,
) -> None:
    """Load both sides and initiate the Child SA from ``initiator``.

    Both peers are configured before either initiates, otherwise the initiator
    races a responder that has no connection loaded yet and the exchange fails
    on a config error rather than on anything real.

    ``responder_cfg`` configures the far end differently from the near end. A
    normal session never uses it -- deriving both sides from one config is what
    stops the two ends disagreeing -- but a deliberate disagreement is the only
    way to exercise the guard of step 2.4, and it is how step 4.4 will build a
    peer that offers 3DES alongside AES-256 so that ``downgrade_available`` has
    something to detect.
    """
    await asyncio.gather(wait_for_charon(initiator), wait_for_charon(responder))
    await load_config(responder, responder_cfg or cfg)
    await load_config(initiator, cfg)

    code, output = await initiator.exec(
        ["swanctl", "--initiate", "--child", CHILD_NAME, "--timeout", "30"],
        check=False,
        timeout_s=60,
    )
    if code != 0:
        responder_log = await responder.logs(tail=40)
        raise TestbedError(
            f"[{initiator.name}] failed to establish the tunnel "
            f"(ike={cfg.ike_proposal}, esp={cfg.esp_proposal}, mode={cfg.mode.value}):\n"
            f"{output.strip()}\n\nresponder log:\n{responder_log}"
        )


async def assert_sa_established(
    peer: PeerHandle,
    *,
    timeout_s: float = SA_ESTABLISH_TIMEOUT_S,
) -> TunnelState:
    """Poll until both the IKE SA and its Child SA are up, or raise.

    LLD section 10.2 calls this guard non-negotiable, and step 2.4 exists to
    prove it fires. Both conditions are required: an established IKE SA with no
    installed Child SA still carries no ESP, and a capture of that is a capture
    of a negotiation, not of a tunnel.
    """
    deadline = time.monotonic() + timeout_s
    state = TunnelState(False, False, None, None, "")

    while time.monotonic() < deadline:
        _, listing = await peer.exec(["swanctl", "--list-sas"], check=False, timeout_s=15)
        state = parse_sas(listing)
        if state.established and state.child_installed:
            log.info(
                "[%s] SA up: ike=%s child=%s",
                peer.name,
                state.ike_algs,
                state.child_algs,
            )
            return state
        await asyncio.sleep(POLL_INTERVAL_S)

    logs = await peer.logs(tail=60)
    detail = (
        "no IKE SA reached ESTABLISHED"
        if not state.established
        else "the IKE SA is up but no CHILD_SA reached INSTALLED"
    )
    raise TestbedError(
        f"[{peer.name}] {detail} within {timeout_s}s.\n\n"
        f"swanctl --list-sas:\n{state.raw.strip() or '(empty)'}\n\n"
        f"container log:\n{logs}"
    )


async def stop_tunnel(peer: PeerHandle) -> None:
    """Terminate the IKE SA, and with it the Child SA underneath.

    Called inside the capture window on purpose (LLD section 10.2): the DELETE
    exchange is part of what a real analyst capture contains, and step 2.8
    asserts it is present. Terminating the IKE SA rather than the child gets
    both deletes in one go.
    """
    code, output = await peer.exec(
        ["swanctl", "--terminate", "--ike", CONNECTION_NAME, "--timeout", "20"],
        check=False,
        timeout_s=45,
    )
    if code != 0:
        # Not fatal. The traffic is already captured; a tunnel that failed to
        # tear down cleanly costs us the DELETE exchange, not the session. The
        # containers are destroyed moments later regardless.
        log.warning("[%s] terminate returned %d: %s", peer.name, code, output.strip())
