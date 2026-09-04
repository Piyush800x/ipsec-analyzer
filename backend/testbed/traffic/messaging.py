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
from testbed.traffic.base import quote, run_for, with_listener

PORT = 5222
SEED = 0x1D1E


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int) -> None:
    """Exchange messages between the peers for ``duration_s``."""
    serve = (
        f"python3 /usr/local/bin/messaging_peer.py serve --host 0.0.0.0 "
        f"--port {PORT} --duration {duration_s} --seed {SEED}"
    )

    async def send() -> None:
        await run_for(
            left,
            (
                f"python3 /usr/local/bin/messaging_peer.py send "
                f"--host {quote(right.traffic_addr)} --port {PORT} "
                f"--duration {duration_s} --seed {SEED}"
            ),
            duration_s,
            name="messaging-client",
        )

    await with_listener(right, serve, name="messaging", body=send)
