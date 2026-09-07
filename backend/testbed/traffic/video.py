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
import random

from testbed.peers import PeerHandle
from testbed.traffic.base import SETTLE_S, host_for_url, start_background, udp_sink

RTP_PORT = 5008

PROFILE_CHOICES = (
    ("640x480", 25, "1500k", 50),
    ("640x480", 15, "800k", 30),
    ("1280x720", 25, "2500k", 50),
)
"""(resolution, framerate, bitrate, keyframe interval), varied per run.

Step 8.3's repeats need video sessions that differ the way two real streams
differ -- a different resolution and bitrate, and therefore a different packet
rate and a different keyframe rhythm. Each tuple keeps one keyframe every two
seconds, which is what gives video its periodic large-frame burst and what
separates it from the flat-rate VoIP stream."""

PACKET_BYTES = 1200
"""Under a 1500-byte MTU with room for the ESP overhead on top, so that the
tunnel does not fragment the stream and blur the size profile."""


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int, seed: int) -> None:
    """Stream video from ``left`` to ``right`` for ``duration_s``."""
    size, framerate, bitrate, keyframe_interval = random.Random(seed).choice(PROFILE_CHOICES)
    sink = await start_background(right, udp_sink(RTP_PORT), name="video-sink")
    await asyncio.sleep(SETTLE_S)

    stream = (
        "ffmpeg -hide_banner -loglevel error -re "
        f"-f lavfi -i testsrc2=size={size}:rate={framerate} "
        f"-t {duration_s} "
        "-c:v libx264 -preset ultrafast -tune zerolatency "
        f"-b:v {bitrate} -maxrate {bitrate} -bufsize 3000k "
        f"-g {keyframe_interval} -keyint_min {keyframe_interval} "
        f"-f rtp rtp://{host_for_url(right.traffic_addr)}:{RTP_PORT}?pkt_size={PACKET_BYTES}"
    )
    sender = await start_background(left, stream, name="video-send")
    try:
        await asyncio.sleep(duration_s)
    finally:
        await sender.stop()
        await sink.stop()
