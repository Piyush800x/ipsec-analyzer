"""VoIP call traffic. Implementation-plan step 2.6, PRD section 9.2.

A G.711 call is the most recognisable shape in the whole matrix: 160 bytes of
audio every 20ms, in both directions, for the length of the call. Constant
bitrate, small packets, near-perfect symmetry.

It is also the shape that breaks the cipher-family detector, which is why both
PRD section 16 demo tunnels carry it. Every packet is the same size, so a VoIP
capture offers the congruence sieve of LLD section 7.2 one distinct ESP length
and the ``sufficient_for_lattice`` gate of step 3.6 correctly refuses to run.
That is the honest-failure case the demo is built around, and it only exists in
the dataset if this generator really does emit constant-size packets -- so it
does, rather than varying them to look busier.
"""

from __future__ import annotations

import asyncio
import random

from testbed.peers import PeerHandle
from testbed.traffic.base import SETTLE_S, host_for_url, start_background, udp_sink

RTP_PORT_LEFT = 5004
RTP_PORT_RIGHT = 5006

PACKET_BYTES = 172
"""12 bytes of RTP header plus 160 bytes of G.711 payload: one 20ms frame."""

PTIME_CHOICES = (20, 30, 40)
"""Packetisation intervals in milliseconds, varied per run (step 8.3).

Real deployments differ on ptime, and it moves both axes a classifier reads --
20ms gives 50 packets/second of 172 bytes, 40ms gives 25 of 332. What does not
change is the defining property: one constant-rate stream in each direction
with a single packet size. That is still nothing like any other class here.

Frequency is deliberately *not* varied. A different sine tone through G.711
produces identical packet geometry, so it would add a label the features cannot
see -- variation that looks like diversity in the manifest and is not."""


def _payload_bytes(ptime_ms: int) -> int:
    """RTP header plus one G.711 frame of *ptime_ms*, at 8000 samples/second."""
    return 12 + 8 * ptime_ms


def _stream(target: str, port: int, ptime_ms: int) -> str:
    """An ffmpeg command emitting a G.711 RTP stream at 50 packets/second.

    ``-re`` paces the encoder at real time; without it ffmpeg emits the whole
    stream as fast as the CPU allows, which produces a burst that looks nothing
    like a phone call. ``pkt_size`` fixes the payload at one 20ms frame.
    """
    return (
        "ffmpeg -hide_banner -loglevel error -re "
        "-f lavfi -i sine=frequency=440:sample_rate=8000 "
        "-ar 8000 -ac 1 -c:a pcm_mulaw -payload_type 0 "
        f"-f rtp rtp://{host_for_url(target)}:{port}?pkt_size={_payload_bytes(ptime_ms)}"
    )


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int, seed: int) -> None:
    """Run a bidirectional call between the peers for ``duration_s``."""
    ptime_ms = random.Random(seed).choice(PTIME_CHOICES)
    sinks = [
        await start_background(right, udp_sink(RTP_PORT_RIGHT), name="voip-sink-right"),
        await start_background(left, udp_sink(RTP_PORT_LEFT), name="voip-sink-left"),
    ]
    await asyncio.sleep(SETTLE_S)

    streams = [
        await start_background(
            left, _stream(right.traffic_addr, RTP_PORT_RIGHT, ptime_ms), name="voip-left"
        ),
        await start_background(
            right, _stream(left.traffic_addr, RTP_PORT_LEFT, ptime_ms), name="voip-right"
        ),
    ]
    try:
        await asyncio.sleep(duration_s)
    finally:
        for process in streams + sinks:
            await process.stop()
