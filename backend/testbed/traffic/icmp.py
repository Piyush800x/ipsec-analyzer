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

from testbed.peers import PeerHandle
from testbed.traffic.base import quote, run_for

INTERVAL_S = 0.2
SIZES = (56, 512)


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int) -> None:
    """Ping ``right`` from ``left`` for ``duration_s``."""
    target = quote(right.traffic_addr)
    source = quote(left.traffic_addr)
    slice_s = max(duration_s // len(SIZES), 1)

    for size in SIZES:
        count = max(int(slice_s / INTERVAL_S), 1)
        await run_for(
            left,
            f"ping -c {count} -i {INTERVAL_S} -s {size} -I {source} {target}",
            slice_s,
            name=f"icmp-{size}",
        )
