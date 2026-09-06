"""Instant-messaging traffic. Implementation-plan step 2.6, PRD section 9.2.

Messaging is defined by its silences. Small payloads, gaps measured in seconds
rather than milliseconds, and a reply that arrives shortly after an incoming
message because somebody is typing an answer. That request-then-pause-then-reply
pairing is the signature, and no other class in the matrix has it.

The generator is ``image/messaging_peer.py``, which lives in the peer image
rather than here because it has to run inside the container. Its timing model is
seeded, so a session replays identically.
"""

from __future__ import annotations

from testbed.peers import PeerHandle
from testbed.traffic.base import bind_address, quote, run_for, with_listener

PORT = 5222


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int, seed: int) -> None:
    """Exchange messages between the peers for ``duration_s``.

    The session seed goes straight through to ``messaging_peer.py``, which
    already drives its whole timing model from one. This is the only generator
    that needed no new variation of its own for step 8.3 -- it had the seam,
    it was just being handed a constant.
    """
    serve = (
        f"python3 /usr/local/bin/messaging_peer.py serve "
        f"--host {bind_address(right.traffic_addr)} "
        f"--port {PORT} --duration {duration_s} --seed {seed}"
    )

    async def send() -> None:
        await run_for(
            left,
            (
                f"python3 /usr/local/bin/messaging_peer.py send "
                f"--host {quote(right.traffic_addr)} --port {PORT} "
                f"--duration {duration_s} --seed {seed}"
            ),
            duration_s,
            name="messaging-client",
        )

    await with_listener(right, serve, name="messaging", body=send)
