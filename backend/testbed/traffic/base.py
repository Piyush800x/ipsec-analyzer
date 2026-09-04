"""Shared plumbing for the traffic generators.

Implementation-plan step 2.6.

Every generator has the same shape: something listens on the right peer,
something sends from the left, both stop when the duration is up, and whatever
was left running gets killed even if the sender raised. That last part is why
this module exists -- an ffmpeg left streaming into a torn-down network keeps a
container alive past its session and turns a clean batch into a slow leak.

The classes exist to be *separable*. Step 2.6 is done when their packet-rate and
size profiles visibly differ, because two classes that look alike to the eye
will look alike to the classifier as well. So each generator commits to the
distinguishing shape of its class rather than approximating all of them with a
parameterised stream:

===========  ==============================================================
class        the shape it commits to
===========  ==============================================================
icmp         tiny, near-perfectly periodic, symmetric
web          short request, large reply, bursts separated by think time
voip         constant bitrate, small packets, symmetric, ~50 packets/second
video        one-directional, high bitrate, MTU-sized, bursty per frame
email        a few large one-directional transfers, long gaps
filexfer     sustained MTU-sized packets in one direction, no gaps
messaging    small packets, long irregular gaps, reply follows request
===========  ==============================================================
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final

from analyzer.core.enums import TrafficClass
from testbed.peers import PeerHandle

log = logging.getLogger(__name__)

Generator = Callable[[PeerHandle, PeerHandle, int], Awaitable[None]]

SETTLE_S: Final = 1.0
"""Grace period after starting a listener before the sender starts.

A sender that beats its listener produces a burst of ICMP port-unreachable
replies, which are themselves encrypted and end up in the capture as a feature
of the traffic class rather than of the race.
"""


@dataclass
class BackgroundProcess:
    """A process started with ``&`` inside a peer, and its PID file."""

    peer: PeerHandle
    pid_file: str
    description: str

    async def stop(self) -> None:
        """Terminate it, and do not raise if it is already gone."""
        await self.peer.exec(
            ["sh", "-c", f"kill $(cat {self.pid_file}) 2>/dev/null || true"],
            check=False,
            timeout_s=10,
        )


async def start_background(
    peer: PeerHandle,
    command: str,
    *,
    name: str,
    description: str = "",
) -> BackgroundProcess:
    """Start ``command`` in the background inside ``peer``.

    The PID is recorded so it can be signalled precisely. Killing by process
    name would also reach the identically-named process the other traffic class
    started, which is the kind of bug that shows up as one class in the dataset
    being quietly short of packets.
    """
    pid_file = f"/tmp/{name}.pid"
    log_file = f"/tmp/{name}.log"
    await peer.exec(
        ["sh", "-c", f"{command} >{log_file} 2>&1 & echo $! > {pid_file}"],
        timeout_s=20,
    )
    log.debug("[%s] started %s: %s", peer.name, name, description or command)
    return BackgroundProcess(peer=peer, pid_file=pid_file, description=description or name)


async def run_for(peer: PeerHandle, command: str, duration_s: int, *, name: str) -> None:
    """Run ``command`` in ``peer``, giving up shortly after ``duration_s``.

    The generators are told how long to run and mostly honour it; the timeout is
    the backstop for the ones that do not, such as an ffmpeg waiting on an input
    that never arrives.
    """
    await peer.exec(
        ["sh", "-c", f"timeout {duration_s + 5} {command} >/tmp/{name}.log 2>&1 || true"],
        check=False,
        timeout_s=duration_s + 30,
    )


async def with_listener(
    listener_peer: PeerHandle,
    listener_command: str,
    *,
    name: str,
    body: Callable[[], Awaitable[None]],
) -> None:
    """Start a listener, run ``body``, then always stop the listener."""
    process = await start_background(listener_peer, listener_command, name=f"{name}-listen")
    try:
        await asyncio.sleep(SETTLE_S)
        await body()
    finally:
        await process.stop()


def udp_sink(port: int) -> str:
    """A command that swallows UDP on ``port`` for as long as it runs.

    Present so that a one-directional media stream does not provoke a matching
    stream of ICMP unreachables back down the tunnel.
    """
    return f"sh -c 'while true; do nc -u -l -p {port} >/dev/null 2>&1; done'"


def quote(value: str) -> str:
    return shlex.quote(value)


def registry() -> dict[TrafficClass, Generator]:
    """Every traffic class mapped to its generator.

    Imported lazily so that a syntax error in one generator does not stop the
    whole testbed from importing, and so that the module list stays in one
    place -- ``tests/test_traffic_generators.py`` asserts this covers every
    member of ``TrafficClass``.
    """
    from testbed.traffic import email, filexfer, icmp, messaging, video, voip, web

    return {
        TrafficClass.ICMP: icmp.generate,
        TrafficClass.WEB: web.generate,
        TrafficClass.VOIP: voip.generate,
        TrafficClass.VIDEO: video.generate,
        TrafficClass.EMAIL: email.generate,
        TrafficClass.FILE_TRANSFER: filexfer.generate,
        TrafficClass.MESSAGING: messaging.generate,
    }


async def generate_traffic(
    left: PeerHandle,
    right: PeerHandle,
    traffic_class: TrafficClass,
    duration_s: int,
) -> None:
    """Dispatch to the generator for ``traffic_class``."""
    generator = registry()[traffic_class]
    log.info("generating %s traffic for %ss", traffic_class.value, duration_s)
    await generator(left, right, duration_s)
