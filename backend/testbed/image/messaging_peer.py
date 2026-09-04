#!/usr/bin/env python3
"""Instant-messaging traffic for the `messaging` class (step 2.6).

Messaging is defined by its silences. Short payloads, long and irregular gaps,
and a reply that follows an incoming message closely enough to look like a
person typing. A constant-rate generator would land in the same feature region
as `web` and the classifier would never learn the difference, so the timing
model here is deliberate rather than incidental.

Deterministic for a given seed: dataset generation must be reproducible.
"""

from __future__ import annotations

import argparse
import random
import socket
import sys
import time

_MIN_MSG = 8
_MAX_MSG = 220
_TYPING_PAUSE = (0.4, 2.5)
_IDLE_GAP = (1.0, 12.0)


def _payload(rng: random.Random) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(rng.randint(_MIN_MSG, _MAX_MSG)))


def serve(host: str, port: int, duration_s: float, seed: int) -> None:
    rng = random.Random(seed + 1)
    srv = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    srv.settimeout(max(duration_s, 1.0))
    try:
        conn, _ = srv.accept()
    except TimeoutError:
        print("messaging: no client connected", file=sys.stderr)
        return
    deadline = time.monotonic() + duration_s
    conn.settimeout(5.0)
    with conn:
        while time.monotonic() < deadline:
            try:
                data = conn.recv(4096)
            except TimeoutError:
                continue
            if not data:
                break
            # A reply follows an incoming message after a typing pause, which is
            # what gives messaging its burst-pair signature.
            time.sleep(rng.uniform(*_TYPING_PAUSE))
            try:
                conn.sendall(_payload(rng))
            except OSError:
                break
    srv.close()


def send(host: str, port: int, duration_s: float, seed: int) -> None:
    rng = random.Random(seed)
    deadline = time.monotonic() + duration_s
    sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((host, port))
    with sock:
        while time.monotonic() < deadline:
            try:
                sock.sendall(_payload(rng))
            except OSError:
                break
            time.sleep(rng.uniform(*_IDLE_GAP))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("role", choices=("serve", "send"))
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=5222)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    (serve if args.role == "serve" else send)(args.host, args.port, args.duration, args.seed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
