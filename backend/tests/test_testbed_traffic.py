"""Step 8.3: repeat runs of a configuration must differ from each other.

PRD section 9.3 wants at least 200 sessions; the pairwise sample is 62
configurations, so most of the dataset is repeat traffic runs. A repeat is only
worth generating if it is a different session -- 62 distinct feature rows plus
138 copies of them would satisfy the count and not the requirement. These tests
hold the two halves of that: the sampler gives every repeat its own seed, and
every generator actually reads it.

Nothing here needs Docker. The generators are driven against a peer stand-in
that records the commands they would have run, which is enough to see whether
two seeds produce two different sessions -- and is a sharper check than
inspecting the resulting capture would be, because it names the parameter that
changed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from analyzer.core.enums import TrafficClass
from testbed.sampler import load_matrix, sample_configs, with_repeats
from testbed.traffic import registry

DURATION_S = 1
"""Short: these tests assert on the commands, never on their output."""


class RecordingPeer:
    """A stand-in for ``PeerHandle`` that records rather than executes.

    Duck-typed instead of a ``PeerHandle`` subclass because a real one needs a
    docker ``Container``, and the generators only ever use ``exec``, ``name``
    and ``traffic_addr``.
    """

    def __init__(self, name: str, addr: str) -> None:
        self.name = name
        self.addr = addr
        self.traffic_addr = addr
        self.commands: list[str] = []

    async def exec(
        self,
        cmd: Sequence[str],
        *,
        check: bool = True,
        detach: bool = False,
        timeout_s: float | None = None,
    ) -> tuple[int, str]:
        self.commands.append(" ".join(cmd))
        return 0, ""


async def _commands_for(traffic_class: TrafficClass, seed: int) -> str:
    left = RecordingPeer("left", "10.10.0.2")
    right = RecordingPeer("right", "10.10.0.3")
    generator = registry()[traffic_class]
    await generator(left, right, DURATION_S, seed)  # type: ignore[arg-type] # RecordingPeer duck-types PeerHandle; see class docstring
    return "\n".join(left.commands + right.commands)


@pytest.mark.parametrize("traffic_class", list(TrafficClass))
def test_every_generator_accepts_a_seed(traffic_class: TrafficClass) -> None:
    """The signature check. A generator that ignored the seed would still pass
    this one -- ``test_seed_changes_the_traffic`` below is what catches that."""
    assert asyncio.run(_commands_for(traffic_class, seed=1))


@pytest.mark.parametrize("traffic_class", list(TrafficClass))
def test_seed_changes_the_traffic(traffic_class: TrafficClass) -> None:
    """Two seeds must produce two different sessions.

    Seeds are searched rather than fixed at two arbitrary values: each generator
    draws from a small set of within-class variants, so a specific pair can
    collide on the same draw without the generator being broken. What would be
    broken is a generator where *no* seed changes anything, which is precisely
    what this fails on.
    """
    baseline = asyncio.run(_commands_for(traffic_class, seed=0))
    assert any(
        asyncio.run(_commands_for(traffic_class, seed=candidate)) != baseline
        for candidate in range(1, 12)
    ), f"{traffic_class.value} ignores its seed, so its repeat runs would be duplicates"


@pytest.mark.parametrize("traffic_class", list(TrafficClass))
def test_same_seed_replays_identically(traffic_class: TrafficClass) -> None:
    """``SessionConfig.seed`` promises a session replays identically, and
    ``labels.json`` records the seed on that basis."""
    assert asyncio.run(_commands_for(traffic_class, seed=7)) == asyncio.run(
        _commands_for(traffic_class, seed=7)
    )


# ===========================================================================
# The sampler half: repeats are distinct sessions of the same configuration
# ===========================================================================


def _configs() -> list[Any]:
    return sample_configs(load_matrix())


def test_repeats_of_one_is_unchanged() -> None:
    """So that an existing batch manifest still resumes against the new flag."""
    configs = _configs()
    assert with_repeats(configs, 1) == configs


def test_repeats_reach_the_prd_target() -> None:
    """PRD section 9.3: at least 200 sessions."""
    assert len(with_repeats(_configs(), 4)) >= 200


def test_every_repeat_has_its_own_name_and_seed() -> None:
    expanded = with_repeats(_configs(), 4)

    assert len({config.name for config in expanded}) == len(expanded)
    by_name = {config.name: config for config in expanded}
    base = _configs()[0]
    seeds = {by_name[base.name].seed} | {by_name[f"{base.name}-r{run}"].seed for run in (2, 3, 4)}
    assert len(seeds) == 4


def test_repeats_share_the_tunnel_configuration() -> None:
    """The point of a repeat is different *traffic*, same tunnel.

    Step 9.5 splits by configuration to stop a model memorising one, which only
    means anything if a configuration's repeats really are the same
    configuration. A repeat that changed the crypto would be a different
    configuration wearing a suffix.
    """
    base = _configs()[0]
    expanded = {config.name: config for config in with_repeats(_configs(), 3)}

    for run in (2, 3):
        repeat = expanded[f"{base.name}-r{run}"]
        for field in ("mode", "ike", "esp", "dh", "pfs", "ip", "traffic", "lifetime_s"):
            assert getattr(repeat, field) == getattr(base, field), field


def test_repeats_below_one_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        with_repeats(_configs(), 0)


# ===========================================================================
# Step 8.3's sharding: concurrent batches must cover the matrix exactly once
# ===========================================================================


def _shard(configs: list[Any], index: int, count: int) -> list[Any]:
    """The slice ``--shard I/N`` takes, mirroring ``testbed.batch.main``."""
    return configs[index - 1 :: count]


def test_shards_are_disjoint_and_complete() -> None:
    """A session generated twice wastes an hour; one generated never leaves a
    hole in the dataset that only shows up as a missing configuration later."""
    configs = with_repeats(_configs(), 4)

    names = [config.name for shard in range(1, 4) for config in _shard(configs, shard, 3)]

    assert len(names) == len(configs)
    assert set(names) == {config.name for config in configs}


def test_shards_are_interleaved_not_contiguous() -> None:
    """Contiguous shards would hand one worker every IPv6 row.

    The matrix is ordered, so a contiguous split correlates each shard with a
    region of it -- and the shard that draws the slow traffic classes finishes
    hours after the others, which defeats the point of sharding.
    """
    configs = with_repeats(_configs(), 4)
    first = _shard(configs, 1, 3)

    positions = [configs.index(config) for config in first]
    assert positions[:3] == [0, 3, 6]


def test_each_shard_keeps_its_own_manifest(tmp_path: Path) -> None:
    """Concurrent shards must not overwrite each other's progress.

    One shared manifest would have every shard rewriting the same file after
    every session with only its own third of the picture, and the last writer
    would erase the others -- so a resume after a crash would re-run sessions
    that had already completed, which on an eight-hour job is the difference
    between finishing and not.
    """
    from testbed.batch import Manifest

    first = Manifest.load_or_create(tmp_path, name="manifest-1-of-3.json")
    first.record_success("s000", packet_count=10, duration_s=1.0)
    first.save()

    second = Manifest.load_or_create(tmp_path, name="manifest-2-of-3.json")
    second.record_success("s001", packet_count=10, duration_s=1.0)
    second.save()

    assert "s000" not in Manifest.load_or_create(tmp_path, name="manifest-2-of-3.json").sessions
    assert "s000" in Manifest.load_or_create(tmp_path, name="manifest-1-of-3.json").sessions


# ===========================================================================
# IPv6: every generator must build command lines for the family it is given
# ===========================================================================


IPV6_LEFT = "fd00:10:10::2"
IPV6_RIGHT = "fd00:10:10::3"


async def _ipv6_commands(traffic_class: TrafficClass) -> str:
    left = RecordingPeer("left", IPV6_LEFT)
    right = RecordingPeer("right", IPV6_RIGHT)
    generator = registry()[traffic_class]
    await generator(left, right, DURATION_S, 1)  # type: ignore[arg-type] # see RecordingPeer
    return "\n".join(left.commands + right.commands)


@pytest.mark.parametrize("traffic_class", list(TrafficClass))
def test_listeners_bind_the_right_family(traffic_class: TrafficClass) -> None:
    """``0.0.0.0`` is IPv4-only, so an IPv6 session finds nothing listening.

    This is the bug that made every IPv6 row of the pilot batch an empty
    capture carrying a traffic label: the tunnel came up, the generator's
    command failed instantly, ``run_for`` swallowed the non-zero exit, and the
    session was recorded as 180 seconds of the traffic it did not contain.
    """
    commands = asyncio.run(_ipv6_commands(traffic_class))

    assert "0.0.0.0" not in commands, (
        f"{traffic_class.value} binds an IPv4 wildcard on an IPv6 session"
    )


@pytest.mark.parametrize("traffic_class", list(TrafficClass))
def test_urls_bracket_ipv6_literals(traffic_class: TrafficClass) -> None:
    """``http://fd00:10:10::3:8080`` is not a URL with a port on the end.

    It is a parse error at best. Every generator that builds a URL or a
    ``host:port`` pair has to bracket the host.
    """
    commands = asyncio.run(_ipv6_commands(traffic_class))

    for scheme in ("http://", "rtp://"):
        for line in commands.splitlines():
            index = line.find(scheme)
            if index == -1:
                continue
            rest = line[index + len(scheme) :]
            assert rest.startswith("["), f"{traffic_class.value}: unbracketed IPv6 in {scheme} URL"


def test_ipv4_sessions_are_unchanged() -> None:
    """The family handling must not have quietly broken the working half."""
    for traffic_class in TrafficClass:
        commands = asyncio.run(_commands_for(traffic_class, seed=1))
        assert "[10.10.0" not in commands, f"{traffic_class.value} bracketed an IPv4 address"


def test_a_failed_session_prunes_only_its_own_containers(tmp_path: Path) -> None:
    """The property that makes concurrent shards possible.

    An unrestricted prune force-removes every container carrying the testbed
    label -- including the live peers of the other shards. One unrelated
    failure would take down two healthy sessions, which would fail, which would
    prune again: three shards cascade each other to a standstill.
    """
    import asyncio as _asyncio

    from testbed.batch import run_batch
    from testbed.orchestrator import session_token
    from testbed.peers import TestbedError
    from testbed.sampler import load_matrix, sample_configs

    cfg = sample_configs(load_matrix())[0]
    pruned: list[str | None] = []

    async def _fail(*args: object, **kwargs: object) -> object:
        raise TestbedError("negotiation failed")

    async def _prune(session: str | None = None) -> tuple[int, int]:
        pruned.append(session)
        return 0, 0

    async def _noop() -> None:
        return None

    import testbed.batch as batch_module

    original = (batch_module.run_session, batch_module.prune_orphans, batch_module.preflight)
    batch_module.run_session = _fail  # type: ignore[assignment] # restored below
    batch_module.prune_orphans = _prune  # type: ignore[assignment]
    batch_module.preflight = _noop  # type: ignore[assignment]
    try:
        _asyncio.run(run_batch([cfg], tmp_path, prune_before=False))
    finally:
        batch_module.run_session, batch_module.prune_orphans, batch_module.preflight = original

    assert pruned == [session_token(cfg)], (
        "a failure must sweep only its own session; None means an unrestricted sweep"
    )
