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

Generator = Callable[[PeerHandle, PeerHandle, int, int], Awaitable[None]]

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


def quote(value: str) -> str:
    return shlex.quote(value)


def is_ipv6(addr: str) -> bool:
    """Whether *addr* is an IPv6 literal.

    A colon is sufficient and unambiguous here: every address the testbed hands
    a generator is a bare literal from ``SessionConfig.addressing``, never a
    hostname and never a host:port pair.
    """
    return ":" in addr


def host_for_url(addr: str) -> str:
    """*addr* as it must appear inside a URL: bracketed when it is IPv6.

    ``http://fd00:10:10::3:8080`` is not a URL with a port -- it is a parse
    error, or worse, silently the wrong host. Every generator that builds a
    URL or a ``host:port`` string goes through this, because the failure it
    prevents is invisible: the command exits non-zero, ``run_for`` swallows it,
    and the session is recorded as successful with an empty capture.
    """
    return f"[{addr}]" if is_ipv6(addr) else addr


def bind_address(peer_addr: str) -> str:
    """The wildcard address a listener must bind for *peer_addr*'s family.

    ``0.0.0.0`` is IPv4-only. Every listener in the testbed bound it, so on an
    IPv6 session the client connected to ``fd00:...`` and found nothing
    listening -- silently, because ``run_for`` swallows the failure. That is
    what made every IPv6 row of the pilot batch an empty capture wearing a
    traffic label.
    """
    return "::" if is_ipv6(peer_addr) else "0.0.0.0"


def ping_command(source: str, target: str, *, count: int, interval: float, size: int) -> str:
    """A ping command for either address family.

    iputils' ``ping`` dispatches on the address it is given, but ``-I`` with an
    IPv6 source needs ``-6`` to be unambiguous, and being explicit costs
    nothing.
    """
    family = "-6" if is_ipv6(target) else "-4"
    return f"ping {family} -c {count} -i {interval} -s {size} -I {quote(source)} {quote(target)}"


def udp_sink(port: int) -> str:
    """A command that swallows UDP on ``port`` for as long as it runs.

    Present so that a one-directional media stream does not provoke a matching
    stream of ICMP unreachables back down the tunnel.

    ``-6`` is not passed: busybox nc binds the wildcard address, which accepts
    both families, and a v6-only bind would break every IPv4 session.
    """
    return f"sh -c 'while true; do nc -u -l -p {port} >/dev/null 2>&1; done'"


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
    seed: int,
) -> None:
    """Dispatch to the generator for ``traffic_class``.

    *seed* is what makes a second run of the same configuration a second
    *session* rather than a copy of the first. Step 8.3 needs several traffic
    runs per configuration to reach PRD section 9.3's 200, and 62 sampled
    configurations replayed with identical generator parameters would be 62
    distinct feature rows and 138 duplicates of them -- a dataset that counts
    to 200 without knowing 200 things. Every generator draws its own
    within-class parameters from this, so the runs differ in what a classifier
    reads while staying unmistakably the same traffic class (MT-13).
    """
    generator = registry()[traffic_class]
    log.info("generating %s traffic for %ss (seed %d)", traffic_class.value, duration_s, seed)
    await generator(left, right, duration_s, seed)
