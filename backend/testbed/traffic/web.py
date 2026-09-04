"""HTTP browsing traffic. Implementation-plan step 2.6, PRD section 9.2.

The shape that defines web traffic is asymmetry followed by silence: a short
request, a much larger reply, several more replies as the page pulls in its
assets, and then a pause while a human reads. Getting the think time in is what
separates this class from ``filexfer``, which moves the same bytes with no gaps
at all.

Resources of several sizes are generated on the server so that the reply sizes
vary the way a real page load does, rather than producing one ESP length
repeated a thousand times.
"""

from __future__ import annotations

import random

from testbed.peers import PeerHandle
from testbed.traffic.base import quote, run_for, with_listener

PORT = 8080
RESOURCE_BYTES = (1_024, 8_192, 65_536, 262_144)
PAGE_ASSETS = 5
"""Requests per simulated page view, issued back to back before the think time."""

THINK_S = (0.8, 3.5)


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int) -> None:
    """Fetch pages from a server on ``right`` for ``duration_s``."""
    sizes = " ".join(str(n) for n in RESOURCE_BYTES)
    serve = (
        "sh -c 'mkdir -p /srv/web && cd /srv/web && "
        f"for n in {sizes}; do head -c $n /dev/urandom > $n.bin; done && "
        f"python3 -m http.server {PORT} --bind 0.0.0.0'"
    )

    async def fetch() -> None:
        rng = random.Random(0xC0FFEE)
        base = f"http://{right.traffic_addr}:{PORT}"
        script_lines = []
        elapsed = 0.0
        while elapsed < duration_s:
            for _ in range(PAGE_ASSETS):
                resource = rng.choice(RESOURCE_BYTES)
                script_lines.append(f"curl -s -o /dev/null {base}/{resource}.bin")
            think = rng.uniform(*THINK_S)
            script_lines.append(f"sleep {think:.2f}")
            # A page view costs roughly its think time; the transfers themselves
            # are near-instant on a bridge network.
            elapsed += think
        script = "; ".join(script_lines)
        await run_for(left, f"sh -c {quote(script)}", duration_s, name="web-client")

    await with_listener(right, serve, name="web", body=fetch)
