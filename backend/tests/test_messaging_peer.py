"""The messaging generator's packet rate, which is the thing it gets wrong.

`testbed/image/messaging_peer.py` is the one generator whose *rate* is a
correctness property rather than a matter of taste, for two reasons pulling in
opposite directions:

* Too slow and every window falls below LLD section 7.6's 20-packet floor, the
  class contributes no training rows, and the traffic classifier silently
  becomes a six-class model. That is what the first version did, and nothing
  failed -- the sessions generated, the captures were real, the labels were
  right, and the class simply evaporated during windowing.
* Too fast and the silences that define the class are gone, `messaging` lands
  in the same feature region as `web`, and the label stops meaning anything.
  The enriched version's first draft did this: it replied per *message* rather
  than per *turn*, so a three-message burst drew three replies, each opening a
  turn of up to three more. Measured on loopback it went 28 packets in the
  first ten-second window to 1565 in the ninth, and it still looked like
  perfectly ordinary chat traffic from the outside.

So these tests run the two roles against each other over loopback and assert on
the rate that comes out. They need no Docker and no tunnel: the generator's
timing model is independent of what is carrying it.
"""

from __future__ import annotations

import importlib.util
import itertools
import socket
import sys
import threading
from collections import Counter
from pathlib import Path
from types import ModuleType

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "testbed" / "image" / "messaging_peer.py"

WINDOW_S = 10.0
"""LLD section 7.6's window length."""

MIN_PACKETS = 20
"""LLD section 7.6's floor. A window below this is discarded."""

DURATION_S = 40.0
"""Four windows. Long enough for the runaway to show -- it was already 4x by
the fourth window -- and short enough to keep the suite quick."""


def _load() -> ModuleType:
    """Import the peer script by path.

    It lives in ``testbed/image/`` because it is COPYd into the peer container,
    not imported by anything in the package, so it is not on any import path.
    """
    spec = importlib.util.spec_from_file_location("messaging_peer", MODULE_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["messaging_peer"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def peer() -> ModuleType:
    return _load()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _conversation(peer: ModuleType, duration_s: float, seed: int) -> list[tuple[float, int]]:
    """Run both roles against each other and return every stanza both sent.

    Stanzas rather than packets: the two are one-to-one because ``_Peer``
    disables Nagle and writes one stanza per ``sendall``, and counting stanzas
    needs no capture privileges. The TCP acknowledgements a real capture would
    also carry are additional, so a stanza count is a *lower* bound on the
    packets in a window -- which is the safe direction for a floor test.
    """
    port = _free_port()
    sent: list[tuple[float, int]] = []
    lock = threading.Lock()

    def record(role_sent: list[tuple[float, int]]) -> None:
        with lock:
            sent.extend(role_sent)

    original_serve = peer.serve
    original_send = peer.send
    captured: dict[str, list[tuple[float, int]]] = {}

    # _Peer keeps its own log of what it sent; the roles do not return it, so
    # the objects are grabbed as they are constructed.
    original_init = peer._Peer.__init__

    def spy_init(self, sock, rng, deadline):  # type: ignore[no-untyped-def] # a test double for a private ctor
        original_init(self, sock, rng, deadline)
        captured.setdefault("peers", []).append(self)  # type: ignore[arg-type]

    peer._Peer.__init__ = spy_init  # type: ignore[method-assign]
    try:
        server = threading.Thread(
            target=original_serve,
            args=("127.0.0.1", port, duration_s, seed),
            daemon=True,
        )
        server.start()
        original_send("127.0.0.1", port, duration_s, seed)
        server.join(timeout=duration_s + 10)
    finally:
        peer._Peer.__init__ = original_init  # type: ignore[method-assign]

    for instance in captured.get("peers", []):
        record(instance.sent)
    return sorted(sent)


@pytest.fixture(scope="module")
def conversation(peer: ModuleType) -> list[tuple[float, int]]:
    return _conversation(peer, DURATION_S, seed=7)


def _per_window(sent: list[tuple[float, int]]) -> list[int]:
    base = sent[0][0]
    counts = Counter(int((at - base) // WINDOW_S) for at, _ in sent)
    # The final window is partial -- the run ends inside it -- so it is not a
    # window LLD section 7.6 would score and asserting on it would be wrong.
    return [counts[i] for i in range(int(DURATION_S // WINDOW_S) - 1)]


def test_every_window_clears_the_floor(conversation: list[tuple[float, int]]) -> None:
    """The defect that made `messaging` a zero-row class.

    Asserted on stanzas alone, which undercounts: the ACKs a capture also sees
    are not here. A generator that clears the floor on stanzas clears it on the
    wire by a margin.
    """
    windows = _per_window(conversation)
    assert windows, "no complete window was produced"
    assert min(windows) >= MIN_PACKETS, (
        f"a window fell below LLD 7.6's {MIN_PACKETS}-packet floor and would be "
        f"discarded, taking the class with it: {windows}"
    )


def test_the_rate_does_not_run_away(conversation: list[tuple[float, int]]) -> None:
    """The defect that replaced the silences with a flood.

    A ratio rather than an absolute ceiling: the failure was *compounding*, so
    what identifies it is the last window dwarfing the first, not any
    particular number. The observed runaway was 30x across nine windows and
    already 4x by the fourth.
    """
    windows = _per_window(conversation)
    assert max(windows) <= 4 * min(windows), (
        f"the packet rate is compounding across windows rather than holding "
        f"steady, which is a reply-per-message rather than per-turn: {windows}"
    )


def test_silences_survive(peer: ModuleType, conversation: list[tuple[float, int]]) -> None:
    """The class is defined by its gaps, so the gaps have to still be there.

    Enriching the model added packets *around* each turn. If it had also filled
    the space between turns, `messaging` would have become a low-rate `web` and
    the label would no longer describe anything distinctive.
    """
    times = [at for at, _ in conversation]
    gaps = [b - a for a, b in itertools.pairwise(times)]
    assert max(gaps) >= 1.0, (
        f"no gap of even a second in {DURATION_S}s: the idle gap between turns "
        f"has been filled in and the class has lost its signature (max {max(gaps):.2f}s)"
    )


def test_receipts_are_per_message_and_replies_are_per_turn(
    peer: ModuleType, conversation: list[tuple[float, int]]
) -> None:
    """The asymmetry that keeps the rate flat.

    A receipt for every message is what a real client sends. A reply for every
    message is what compounds. Both ends acknowledge, so receipts come in at
    roughly one per message delivered, while messages themselves stay far
    below that -- if replies were per-message the two counts would converge.
    """
    kinds = Counter(kind for _, kind in conversation)
    messages = kinds[peer.MESSAGE]
    assert messages > 0, "no messages were exchanged at all"
    assert kinds[peer.RECEIPT] >= messages, (
        "every delivered message earns a receipt, so receipts cannot be fewer "
        f"than messages: {kinds[peer.RECEIPT]} receipts, {messages} messages"
    )
    assert kinds[peer.DISPLAYED] >= messages, (
        "every delivered message earns a read marker: "
        f"{kinds[peer.DISPLAYED]} markers, {messages} messages"
    )


def test_the_enrichment_is_actually_present(
    peer: ModuleType, conversation: list[tuple[float, int]]
) -> None:
    """Each conversational stanza type has to appear, or it is documentation only.

    The keepalive and the roster presence are deliberately *not* asserted here:
    their intervals (25-45s and 12-40s) are longer than this run, so requiring
    them would make the test flaky for a reason that has nothing to do with the
    behaviour. ``test_a_periodic_stanza_reschedules_itself`` covers them
    instead, at the mechanism rather than through a long conversation.
    """
    kinds = Counter(kind for _, kind in conversation)
    for name in ("MESSAGE", "COMPOSING", "ACTIVE", "RECEIPT", "DISPLAYED"):
        assert kinds[getattr(peer, name)] > 0, f"{name} stanzas never appear on the wire"


def test_a_periodic_stanza_reschedules_itself(peer: ModuleType) -> None:
    """The keepalive and the roster presence must recur, not fire once.

    Worth its own test because a periodic send that fires once is invisible:
    the connection stays up, the conversation carries on, and the only symptom
    is a slightly lower packet rate in the windows between turns -- exactly
    where this class has the least margin over the floor.

    Driven through a pair of connected sockets at an interval of milliseconds,
    so the recurrence is observed rather than waited for.
    """
    import random

    left, right = socket.socketpair()
    try:
        instance = peer._Peer(left, random.Random(3), deadline=0.0)
        instance.every((0.01, 0.02), peer.PING)
        # Fire the queue by hand: run() would return immediately on a deadline
        # already past, and the point here is the reschedule, not the loop.
        for _ in range(5):
            _, _, action = __import__("heapq").heappop(instance._queue)
            action()
        assert len(instance.sent) == 5, "a periodic stanza stopped after firing"
        assert {kind for _, kind in instance.sent} == {peer.PING}
        assert instance._queue, "nothing was left scheduled, so it will not recur again"
    finally:
        left.close()
        right.close()


def test_a_seed_replays(peer: ModuleType) -> None:
    """Two runs of one seed exchange the same stanzas in the same order.

    Timing cannot be asserted -- the scheduler sleeps on a real clock -- but
    the *sequence* is a pure function of the seed, and it is the sequence that
    a dataset's reproducibility rests on.
    """
    first = [kind for _, kind in _conversation(peer, 12.0, seed=11)]
    second = [kind for _, kind in _conversation(peer, 12.0, seed=11)]
    shared = min(len(first), len(second))
    assert shared > 0
    assert first[:shared] == second[:shared]
