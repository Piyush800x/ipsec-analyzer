"""SMTP mail traffic. Implementation-plan step 2.6, PRD section 9.2.

Mail is transactional and lumpy: a short negotiation, then one large
one-directional push of the message body, then nothing at all for a long time.
The gaps are much longer than web think time and the transfers much larger,
which is what keeps the two classes apart.

Attachment sizes vary by an order of magnitude, because a dataset in which every
message is the same size teaches the classifier that email means exactly one ESP
length.
"""

from __future__ import annotations

import random

from testbed.peers import PeerHandle
from testbed.traffic.base import bind_address, host_for_url, quote, run_for, with_listener

PORT = 2525
ATTACHMENT_CHOICES = (
    (4_096, 65_536, 512_000),
    (2_048, 16_384, 131_072),
    (4_096, 65_536, 512_000, 2_048_000),
)
GAP_CHOICES = ((4.0, 15.0), (2.0, 8.0), (10.0, 30.0))
"""Attachment sizes and send gaps, varied per run (step 8.3).

Mail is defined by long silences broken by a single large mostly-one-directional
transfer, and every combination keeps that: the gaps stay measured in seconds
and the attachments stay large relative to every interactive class. What varies
is how large and how often -- a mailbox that receives a photo every half minute
against one that receives a document every few seconds."""


async def generate(left: PeerHandle, right: PeerHandle, duration_s: int, seed: int) -> None:
    """Send mail from ``left`` to a sink on ``right`` for ``duration_s``."""
    sink = f"python3 /usr/local/bin/smtp_sink.py {bind_address(right.traffic_addr)} {PORT}"

    async def send() -> None:
        rng = random.Random(seed)
        attachment_bytes = rng.choice(ATTACHMENT_CHOICES)
        gap_s = rng.choice(GAP_CHOICES)
        server = f"{host_for_url(right.traffic_addr)}:{PORT}"
        lines = ["mkdir -p /tmp/mail"]
        elapsed = 0.0
        index = 0
        while elapsed < duration_s:
            size = rng.choice(attachment_bytes)
            body = f"/tmp/mail/body-{index}.txt"
            lines.append(f"head -c {size} /dev/urandom | base64 > {body}")
            lines.append(
                f"swaks --to user@testbed.local --from sender@testbed.local "
                f"--server {server} --body {body} --silent 3 || true"
            )
            gap = rng.uniform(*gap_s)
            lines.append(f"sleep {gap:.2f}")
            elapsed += gap
            index += 1
        script = "; ".join(lines)
        await run_for(left, f"sh -c {quote(script)}", duration_s, name="email-client")

    await with_listener(right, sink, name="email", body=send)
