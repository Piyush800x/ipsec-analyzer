"""ICMP echo traffic. Implementation-plan step 2.6, PRD section 9.2.

The simplest class, and the one every other class has to look unlike: tiny
packets, one every 200ms, perfectly symmetric because every request draws
exactly one reply of the same size.

Two payload sizes rather than one. A single size would give the cipher-family
sieve of LLD section 7.2 exactly one distinct ESP length to work with, and
``sufficient_for_lattice`` would be false for every ICMP capture in the dataset
-- which is a real degradation case worth having, but not worth having as the
only ICMP case there is.
"""

from __future__ import annotations

import random

from testbed.peers import PeerHandle
from testbed.traffic.base import ping_command, run_for

INTERVAL_CHOICES = (0.1, 0.2, 0.5)
SIZE_CHOICES = ((56, 512), (64, 1024), (56, 128, 512))
"""Within-class variation for repeat runs (step 8.3).

ICMP's signature is a fixed-rate exchange of a couple of distinct sizes, and
every combination here keeps it: the rate stays regular and the size set stays
small. What moves is the rate itself and which sizes, which is what a repeat
run needs to contribute a genuinely different feature vector rather than a
duplicate. Ping's own payload sizes are still exact, so the geometry stays
crisp rather than smeared."""


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int, seed: int) -> None:
    """Ping ``right`` from ``left`` for ``duration_s``."""
    rng = random.Random(seed)
    interval_s = rng.choice(INTERVAL_CHOICES)
    sizes = rng.choice(SIZE_CHOICES)

    target = right.traffic_addr
    source = left.traffic_addr
    slice_s = max(duration_s // len(sizes), 1)

    for size in sizes:
        count = max(int(slice_s / interval_s), 1)
        await run_for(
            left,
            ping_command(source, target, count=count, interval=interval_s, size=size),
            slice_s,
            name=f"icmp-{size}",
        )
