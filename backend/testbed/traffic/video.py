"""Video streaming traffic. Implementation-plan step 2.6, PRD section 9.2.

Where VoIP is small and even, video is large and lumpy. Each encoded frame is
fragmented across several MTU-sized packets sent back to back, then nothing
until the next frame, and a keyframe is several times the size of the frames
that follow it. That burst-then-pause structure at 25 frames per second, in one
direction only, is what separates video from both VoIP and bulk file transfer.

The keyframe interval is set explicitly rather than left to the encoder, because
periodic large bursts are a feature the classifier can use and one that a
default ``-g`` would vary between ffmpeg builds.
"""

from __future__ import annotations

import asyncio

from testbed.peers import PeerHandle
from testbed.traffic.base import SETTLE_S, start_background, udp_sink

RTP_PORT = 5008
BITRATE = "1500k"
FRAMERATE = 25
KEYFRAME_INTERVAL = 50
"""One keyframe every two seconds at 25fps."""

PACKET_BYTES = 1200
"""Under a 1500-byte MTU with room for the ESP overhead on top, so that the
tunnel does not fragment the stream and blur the size profile."""


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int) -> None:
    """Stream video from ``left`` to ``right`` for ``duration_s``."""
    sink = await start_background(right, udp_sink(RTP_PORT), name="video-sink")
    await asyncio.sleep(SETTLE_S)

    stream = (
        "ffmpeg -hide_banner -loglevel error -re "
        f"-f lavfi -i testsrc2=size=640x480:rate={FRAMERATE} "
        f"-t {duration_s} "
        "-c:v libx264 -preset ultrafast -tune zerolatency "
        f"-b:v {BITRATE} -maxrate {BITRATE} -bufsize 3000k "
        f"-g {KEYFRAME_INTERVAL} -keyint_min {KEYFRAME_INTERVAL} "
        f"-f rtp rtp://{right.traffic_addr}:{RTP_PORT}?pkt_size={PACKET_BYTES}"
    )
    sender = await start_background(left, stream, name="video-send")
    try:
        await asyncio.sleep(duration_s)
    finally:
        await sender.stop()
        await sink.stop()
