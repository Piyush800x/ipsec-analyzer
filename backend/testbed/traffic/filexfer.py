"""Bulk file transfer traffic. Implementation-plan step 2.6, PRD section 9.2.

The saturating case: MTU-sized packets, one directly after another, in one
direction, with no gaps and no size variation once the transfer is in flight.
It is the opposite extreme from ``messaging`` and the thing ``web`` must not be
mistaken for.

Bandwidth is capped rather than left to fill the link. On a bridge network an
uncapped iperf3 will move gigabytes in three minutes, producing a capture too
large to be convenient and a bitrate no real VPN would carry. The cap keeps the
class realistic and the dataset a sane size.
"""

from __future__ import annotations

import random

from testbed.peers import PeerHandle
from testbed.traffic.base import is_ipv6, run_for, with_listener

PORT = 5201

BANDWIDTH_CHOICES = ("20M", "10M", "40M")
"""Offered rate, varied per run (step 8.3).

File transfer's signature is a sustained, saturating, strongly one-directional
flow at MTU-sized packets, and it holds at every rate here -- what changes is
the packets-per-second a classifier sees, which is one of the strongest columns
in the feature matrix and would otherwise be identical across every repeat."""


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int, seed: int) -> None:
    """Transfer from ``left`` to a server on ``right`` for ``duration_s``."""
    bandwidth = random.Random(seed).choice(BANDWIDTH_CHOICES)
    # iperf3 needs the family stated: `--client <v6 literal>` without `-6`
    # resolves as IPv4 and fails, which run_for would swallow.
    family = "-6" if is_ipv6(right.traffic_addr) else "-4"
    serve = f"iperf3 --server --port {PORT} --one-off"

    async def transfer() -> None:
        await run_for(
            left,
            (
                f"iperf3 {family} --client {right.traffic_addr} --port {PORT} "
                f"--time {duration_s} --bitrate {bandwidth} --format m"
            ),
            duration_s,
            name="filexfer-client",
        )

    await with_listener(right, serve, name="filexfer", body=transfer)
