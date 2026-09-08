"""The two PRD section 16 demo captures. Implementation-plan step 11.5.

Step 11.5's **Done when** has two halves and this file holds both:

1. The two tunnels are the ones PRD section 16 specifies -- asserted parameter
   by parameter, because "deliberately weak" is a claim about a cipher suite
   and a demo that quietly hardened tunnel A would show a contrast that was
   not there.
2. **Neither appears in any training split.** This is the half that is easy to
   believe and hard to keep true: the matrix's own reference fixtures carry
   identical parameters and *are* in the dataset, so the demo is one careless
   ``--output-dir ../dataset/sessions`` away from being calibrated on the
   capture it is about to be demonstrated with.

The split assertion runs against the real ``split_configs`` over a window set
containing every configuration the sampler produces, rather than against a
directory listing, because the property that matters is that the demo names are
not *splittable* -- there is no fold for them to land in. A listing would pass
the day someone regenerated the demo into the corpus and the split then placed
it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from analyzer.core.enums import (
    EncryptionAlg,
    IkeExchangeMode,
    IkeVersion,
    IntegrityAlg,
    OperatingMode,
    TrafficClass,
)
from analyzer.track_b.windows import Window, split_configs
from testbed.config import EspSuite, IkeFlavour
from testbed.demo_captures import (
    DEMO_NAMES,
    DEMO_SEED,
    TUNNEL_A,
    TUNNEL_B,
    build_configs,
)
from testbed.sampler import load_matrix, sample_configs, with_repeats

REPEATS = 4
"""What the dataset was generated with (step 8.3), so the configuration names
here are the ones a split actually sees."""


@pytest.fixture(scope="module")
def demo_configs() -> dict[str, object]:
    return {cfg.name: cfg for cfg in build_configs()}


# ---------------------------------------------------------------------------
# 1. The tunnels are PRD section 16's tunnels
# ---------------------------------------------------------------------------


def test_tunnel_a_is_the_weak_one(demo_configs: dict) -> None:  # type: ignore[type-arg] # SessionConfig values, keyed by name
    """PRD section 16: IKEv1 aggressive, 3DES-CBC, HMAC-SHA1-96, DH group 2,
    PFS disabled, 24-hour lifetime, transport mode, VoIP."""
    cfg = demo_configs[TUNNEL_A]
    assert cfg.ike is IkeFlavour.IKEV1_AGGRESSIVE
    assert cfg.ike_version is IkeVersion.IKEV1
    assert cfg.exchange_mode is IkeExchangeMode.AGGRESSIVE
    assert cfg.esp is EspSuite.TRIPLE_DES_SHA1
    assert cfg.suite.encryption_alg is EncryptionAlg.TRIPLE_DES_CBC
    assert cfg.suite.integrity_alg is IntegrityAlg.HMAC_SHA1_96
    assert cfg.dh == 2
    assert cfg.pfs is False
    assert cfg.lifetime_s == 86400, "PRD section 16 says a 24-hour SA lifetime"
    assert cfg.mode is OperatingMode.TRANSPORT
    assert cfg.traffic is TrafficClass.VOIP


def test_tunnel_b_is_the_hardened_one(demo_configs: dict) -> None:  # type: ignore[type-arg] # see above
    """PRD section 16: IKEv2, AES-256-GCM, DH group 19, PFS enabled, 1-hour
    lifetime, tunnel mode, the same VoIP call."""
    cfg = demo_configs[TUNNEL_B]
    assert cfg.ike is IkeFlavour.IKEV2
    assert cfg.ike_version is IkeVersion.IKEV2
    assert cfg.exchange_mode is None
    assert cfg.esp is EspSuite.AES256GCM16
    assert cfg.suite.encryption_alg is EncryptionAlg.AES_GCM_16
    assert cfg.suite.encryption_keylen == 256
    assert cfg.dh == 19
    assert cfg.pfs is True
    assert cfg.lifetime_s == 3600, "PRD section 16 says a 1-hour SA lifetime"
    assert cfg.mode is OperatingMode.TUNNEL
    assert cfg.traffic is TrafficClass.VOIP


def test_both_tunnels_carry_the_same_traffic_class(demo_configs: dict) -> None:  # type: ignore[type-arg] # see above
    """The demo's whole argument is that the score changed and the metadata
    exposure did not. That only holds if the inner traffic is the same."""
    assert demo_configs[TUNNEL_A].traffic is demo_configs[TUNNEL_B].traffic


def test_they_run_on_distinct_subnets(demo_configs: dict) -> None:  # type: ignore[type-arg] # see above
    """Two sessions cannot share a Docker bridge subnet -- the second gets
    "Pool overlaps with other one on this address space" and fails outright."""
    indices = {cfg.address_index for cfg in demo_configs.values()}
    assert len(indices) == len(demo_configs)


# ---------------------------------------------------------------------------
# 2. Neither appears in any training split
# ---------------------------------------------------------------------------


def _windows_for_every_dataset_configuration() -> list[Window]:
    """One window per configuration the dataset generator produces.

    ``split_configs`` only ever reads a window's configuration name and traffic
    class, so one window per configuration is a faithful stand-in for the real
    corpus and needs none of its 14 GB.
    """
    configs = with_repeats(sample_configs(load_matrix()), REPEATS)
    return [
        Window(
            config_name=cfg.name,
            session_name=cfg.name,
            traffic_class=cfg.traffic.value,
            start_ts=0.0,
            features={},
            sequence=[],
        )
        for cfg in configs
    ]


def test_the_demo_names_are_not_dataset_configurations() -> None:
    """The names cannot collide, which is what makes the split assertion hold.

    Checked against the sampler rather than a directory, so it stays true for a
    dataset regenerated tomorrow with a different pairwise draw.
    """
    produced = {cfg.name for cfg in with_repeats(sample_configs(load_matrix()), REPEATS)}
    for name in DEMO_NAMES:
        assert name not in produced, (
            f"{name} is a configuration the dataset generator produces, so the "
            f"demo capture would be trained, calibrated or tested on"
        )


def test_neither_demo_tunnel_lands_in_any_fold() -> None:
    """Step 11.5's Done when, asserted against the real splitter."""
    split = split_configs(_windows_for_every_dataset_configuration())
    for name in DEMO_NAMES:
        assert split.fold_of(name) is None, (
            f"{name} was placed in the {split.fold_of(name)} fold: the demo "
            f"would be run on a capture the models had already seen"
        )


def test_the_reference_fixtures_do_land_in_a_fold() -> None:
    """The control, and the reason the demo needs its own configurations.

    Without this the previous test would pass just as well against a splitter
    that placed nothing at all, and the danger it guards would be invisible.
    The matrix's reference fixtures carry PRD section 16's exact parameters and
    they *are* split -- which is precisely why the demo cannot reuse them.
    """
    split = split_configs(_windows_for_every_dataset_configuration())
    folds = {name: split.fold_of(name) for name in ("weak-reference", "hardened-reference")}
    assert all(fold is not None for fold in folds.values()), folds


def test_the_demo_seed_differs_from_the_dataset() -> None:
    """A different call inside the tunnel, not a re-run of a seen one."""
    dataset_seeds = {cfg.seed for cfg in with_repeats(sample_configs(load_matrix()), REPEATS)}
    assert DEMO_SEED not in dataset_seeds


# ---------------------------------------------------------------------------
# 3. The frozen artefacts, when they are present
# ---------------------------------------------------------------------------

DEMO_DIR = Path(__file__).resolve().parents[2] / "dataset" / "demo"
SESSIONS_DIR = Path(__file__).resolve().parents[2] / "dataset" / "sessions"


@pytest.mark.skipif(not DEMO_DIR.is_dir(), reason="demo captures have not been generated")
def test_the_frozen_captures_are_outside_the_corpus() -> None:
    """A capture the corpus loader cannot walk cannot be trained on later."""
    assert SESSIONS_DIR not in DEMO_DIR.parents
    for name in DEMO_NAMES:
        assert (DEMO_DIR / name / "capture.pcap").is_file(), f"{name} has not been frozen"
        assert not (SESSIONS_DIR / name).exists(), (
            f"{name} exists inside dataset/sessions/, so the corpus loader will "
            f"walk it and the split will place it"
        )
