"""Matrix loading and pairwise sampling. Implementation-plan step 2.9.

The done-when is precise: 40 to 60 configurations, every value of every
dimension appearing at least once, and an identical list on a re-run with the
same seed.
"""

from __future__ import annotations

import itertools

import pytest

from analyzer.core.enums import TrafficClass
from testbed.config import DH_GROUP_KEYWORDS, TRAFFIC_LABELS
from testbed.sampler import (
    _all_pairs,
    _pairs_in,
    coverage_report,
    fixture_configs,
    load_matrix,
    pairwise_rows,
    sample_configs,
)


@pytest.fixture(scope="module")
def matrix():  # type: ignore[no-untyped-def]  # module-scoped fixture, inferred Matrix
    return load_matrix()


@pytest.fixture(scope="module")
def rows(matrix):  # type: ignore[no-untyped-def]
    return pairwise_rows(matrix)


class TestMatrixFile:
    def test_dimensions_match_lld_10_1(self, matrix) -> None:  # type: ignore[no-untyped-def]
        assert set(matrix.dimensions) == {"mode", "ike", "esp", "dh", "pfs", "ip", "traffic"}

    def test_cross_product_is_3360(self, matrix) -> None:  # type: ignore[no-untyped-def]
        """LLD 10.1 states 2x3x5x4x2x2x7. If this changes, so does the sample
        size the plan expects."""
        assert matrix.cross_product_size == 3360

    def test_every_dh_group_has_a_strongswan_keyword(self, matrix) -> None:  # type: ignore[no-untyped-def]
        """Caught at load rather than forty sessions into an unattended batch."""
        for group in matrix.dimensions["dh"]:
            assert group in DH_GROUP_KEYWORDS

    def test_every_traffic_keyword_has_a_generator(self, matrix) -> None:  # type: ignore[no-untyped-def]
        from testbed.traffic import registry

        available = registry()
        for keyword in matrix.dimensions["traffic"]:
            assert TRAFFIC_LABELS[keyword] in available


class TestSampling:
    def test_sample_size_is_within_the_planned_range(self, rows) -> None:  # type: ignore[no-untyped-def]
        assert 40 <= len(rows) <= 60, f"sampled {len(rows)}, plan step 2.9 expects 40-60"

    def test_every_value_of_every_dimension_appears(self, matrix, rows) -> None:  # type: ignore[no-untyped-def]
        missing = {
            dimension: [value for value, count in values.items() if count == 0]
            for dimension, values in coverage_report(matrix, rows).items()
        }
        assert not any(missing.values()), f"values never sampled: {missing}"

    def test_every_pair_is_covered(self, matrix, rows) -> None:  # type: ignore[no-untyped-def]
        """The point of a pairwise sample: no pair of values goes untested."""
        names = sorted(matrix.dimensions)
        covered: set[tuple[str, object, str, object]] = set()
        for row in rows:
            covered |= _pairs_in(row, names)
        assert covered == _all_pairs(matrix.dimensions)

    def test_guaranteed_dimensions_are_covered_exhaustively(self, matrix, rows) -> None:  # type: ignore[no-untyped-def]
        """`guarantee_full_coverage` means full strength among those dimensions.

        These four are what Track A parses and the policy scores, so a missing
        combination is a gap in what the product can be shown to handle.
        """
        names = sorted(matrix.guarantee_full_coverage)
        sampled = {tuple(row[name] for name in names) for row in rows}
        expected = set(itertools.product(*(matrix.dimensions[name] for name in names)))
        assert sampled == expected

    def test_the_same_seed_produces_an_identical_list(self, matrix, rows) -> None:  # type: ignore[no-untyped-def]
        """A dataset you cannot regenerate is one you cannot defend -- and the
        resume manifest of step 2.10 keys on these names."""
        assert pairwise_rows(matrix) == rows

    def test_a_different_seed_produces_a_different_list(self, matrix, rows) -> None:  # type: ignore[no-untyped-def]
        """Guards against a sampler that ignores its seed and only looks
        deterministic."""
        shifted = matrix.__class__(
            dimensions=matrix.dimensions,
            defaults=matrix.defaults,
            fixtures=matrix.fixtures,
            seed=matrix.seed + 1,
            guarantee_full_coverage=matrix.guarantee_full_coverage,
        )
        assert pairwise_rows(shifted) != rows


class TestConfigs:
    def test_configs_have_unique_names(self, matrix) -> None:  # type: ignore[no-untyped-def]
        """Names key the resume manifest and the output directory. A collision
        would silently overwrite one session with another."""
        names = [cfg.name for cfg in sample_configs(matrix)]
        assert len(names) == len(set(names))

    def test_reference_fixtures_are_always_included(self, matrix) -> None:  # type: ignore[no-untyped-def]
        """The demo depends on both, and neither is guaranteed to fall out of a
        pairwise sample."""
        names = {cfg.name for cfg in sample_configs(matrix)}
        assert {"weak-reference", "hardened-reference"} <= names

    def test_fixture_configs_match_the_lld_values(self, matrix) -> None:  # type: ignore[no-untyped-def]
        fixtures = {cfg.name: cfg for cfg in fixture_configs(matrix)}
        weak = fixtures["weak-reference"]
        assert weak.lifetime_s == 86400
        assert weak.dh == 2
        assert weak.pfs is False
        assert weak.traffic is TrafficClass.VOIP

        hardened = fixtures["hardened-reference"]
        assert hardened.dh == 19
        assert hardened.pfs is True
        assert hardened.lifetime_s == 3600

    def test_sampled_configs_are_constructible(self, matrix) -> None:  # type: ignore[no-untyped-def]
        """Every sampled row must survive SessionConfig validation.

        A row the sampler can produce but the config rejects is a batch that
        dies partway through, and pairwise sampling is exactly the technique
        that finds those combinations.
        """
        configs = sample_configs(matrix)
        assert len(configs) >= 40
        for cfg in configs:
            assert cfg.ike_proposal
            assert cfg.esp_proposal
            assert cfg.to_ground_truth()["expected"]
