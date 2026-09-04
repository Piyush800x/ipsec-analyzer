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

from testbed.peers import PeerHandle
from testbed.traffic.base import run_for, with_listener

PORT = 5201
BANDWIDTH = "20M"


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int) -> None:
    """Transfer from ``left`` to a server on ``right`` for ``duration_s``."""
    serve = f"iperf3 --server --port {PORT} --one-off"

    async def transfer() -> None:
        await run_for(
            left,
            (
                f"iperf3 --client {right.traffic_addr} --port {PORT} "
                f"--time {duration_s} --bitrate {BANDWIDTH} --format m"
            ),
            duration_s,
            name="filexfer-client",
        )

    await with_listener(right, serve, name="filexfer", body=transfer)
