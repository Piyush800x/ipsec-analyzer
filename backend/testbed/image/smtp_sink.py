#!/usr/bin/env python3
"""Minimal SMTP sink for the `email` traffic class (step 2.6).

`swaks` on the far peer needs something to talk to. aiosmtpd's own
``Sink`` handler accepts a message and drops it, which is all we want: the
packet exchange is the artefact, the mail body is not.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink


async def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2525
    controller = Controller(Sink(), hostname=host, port=port)
    controller.start()
    print(f"smtp sink listening on {host}:{port}", file=sys.stderr, flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        controller.stop()


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
