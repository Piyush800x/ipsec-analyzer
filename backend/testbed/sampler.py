"""Load the matrix and sample it pairwise.

Implementation-plan step 2.9, LLD section 10.1.

Pairwise (all-pairs) covering is the standard answer to a combinatorial space
too large to enumerate: most defects and most interactions involve two factors,
so covering every pair of values from every pair of dimensions finds nearly what
the full cross-product would, in a fortieth of the runs.

The sampler is deterministic. Re-running with the same seed produces the same
list in the same order, because a dataset you cannot regenerate is a dataset you
cannot defend -- and because step 2.10 resumes a partial batch by name, which
requires the names to be stable across invocations.
"""

from __future__ import annotations

import itertools
import logging
import random
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

from analyzer.core.enums import OperatingMode
from testbed.config import (
    DH_GROUP_KEYWORDS,
    TRAFFIC_LABELS,
    EspSuite,
    IkeFlavour,
    IpVersion,
    SessionConfig,
)

log = logging.getLogger(__name__)

MATRIX_PATH: Final = Path(__file__).parent / "matrix.yaml"

CANDIDATES_PER_ROW: Final = 60
"""Random candidates evaluated per greedy step.

Greedy all-pairs picks, at each step, the row covering the most still-uncovered
pairs. Evaluating every possible row is 3360 evaluations per step; sampling a
few dozen candidates gets within a row or two of the same answer for a fraction
of the work, and the seed keeps it reproducible.
"""

Row = dict[str, Any]


@dataclass(frozen=True)
class Matrix:
    """The parsed matrix file."""

    dimensions: dict[str, list[Any]]
    defaults: dict[str, Any]
    fixtures: list[Row]
    seed: int
    guarantee_full_coverage: list[str]

    @property
    def cross_product_size(self) -> int:
        total = 1
        for values in self.dimensions.values():
            total *= len(values)
        return total


def load_matrix(path: Path = MATRIX_PATH) -> Matrix:
    """Read and validate ``matrix.yaml``."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    dimensions: dict[str, list[Any]] = dict(raw["dimensions"])
    sampling = raw.get("sampling", {})

    for name in sampling.get("guarantee_full_coverage", []):
        if name not in dimensions:
            raise ValueError(
                f"{path}: guarantee_full_coverage names {name!r}, which is not a dimension"
            )

    # Validated at load rather than at container-start time. A dh group with no
    # strongSwan keyword, or a traffic keyword with no generator, would
    # otherwise surface as a failure forty sessions into an unattended batch.
    for group in dimensions.get("dh", []):
        if group not in DH_GROUP_KEYWORDS:
            raise ValueError(f"{path}: dh group {group} has no keyword in DH_GROUP_KEYWORDS")
    for keyword in dimensions.get("traffic", []):
        if keyword not in TRAFFIC_LABELS:
            raise ValueError(f"{path}: traffic {keyword!r} has no TrafficClass mapping")

    return Matrix(
        dimensions=dimensions,
        defaults=dict(raw.get("defaults", {})),
        fixtures=list(raw.get("fixtures", [])),
        seed=int(sampling.get("seed", 0)),
        guarantee_full_coverage=list(sampling.get("guarantee_full_coverage", [])),
    )


def _all_pairs(dimensions: dict[str, list[Any]]) -> set[tuple[str, Any, str, Any]]:
    """Every (dimension, value, dimension, value) pair that must be covered."""
    pairs: set[tuple[str, Any, str, Any]] = set()
    for left, right in itertools.combinations(sorted(dimensions), 2):
        for lv, rv in itertools.product(dimensions[left], dimensions[right]):
            pairs.add((left, lv, right, rv))
    return pairs


def _pairs_in(row: Row, names: Sequence[str]) -> set[tuple[str, Any, str, Any]]:
    return {
        (left, row[left], right, row[right]) for left, right in itertools.combinations(names, 2)
    }


def pairwise_rows(matrix: Matrix) -> list[Row]:
    """Cover the matrix: exhaustively across the guaranteed dimensions, pairwise
    across the rest.

    ``guarantee_full_coverage`` is read the way covering-array tools read it --
    as a request for full-strength coverage among those dimensions, rather than
    the pairwise strength applied everywhere else. So every combination of mode,
    ESP suite, PFS and IKE flavour is generated, and DH group, IP version and
    traffic class are filled in to cover their pairs.

    That is a deliberate reading, and it matters. Plain greedy all-pairs covers
    this matrix in 37 rows, below the 40-60 the plan expects, and it does so by
    covering the dimensions the assessment engine cares about most only in
    pairs: there would be no 3DES-with-PFS-on-IKEv2 row unless the greedy step
    happened to want one. Those four dimensions are exactly the ones Track A
    parses and the policy scores, so a gap in their combinations is a gap in
    what the product can be shown to handle.

    Deterministic for a given seed. Rows come back sorted, so a change in greedy
    tie-breaking cannot reorder an otherwise identical sample and invalidate a
    resume manifest.
    """
    names = sorted(matrix.dimensions)
    uncovered = _all_pairs(matrix.dimensions)
    rng = random.Random(matrix.seed)
    rows: list[Row] = []

    guaranteed = [name for name in names if name in matrix.guarantee_full_coverage]
    free = [name for name in names if name not in guaranteed]

    for combination in sorted(
        itertools.product(*(matrix.dimensions[name] for name in guaranteed)), key=repr
    ):
        fixed = dict(zip(guaranteed, combination, strict=True))
        best: Row | None = None
        best_gain = -1
        for _ in range(CANDIDATES_PER_ROW):
            candidate = fixed | {name: rng.choice(matrix.dimensions[name]) for name in free}
            gain = len(_pairs_in(candidate, names) & uncovered)
            if gain > best_gain:
                best, best_gain = candidate, gain
        assert best is not None
        uncovered -= _pairs_in(best, names)
        rows.append(best)

    while uncovered:
        extra: Row | None = None
        extra_gain = -1
        for _ in range(CANDIDATES_PER_ROW):
            candidate = {name: rng.choice(matrix.dimensions[name]) for name in names}
            gain = len(_pairs_in(candidate, names) & uncovered)
            if gain > extra_gain:
                extra, extra_gain = candidate, gain

        if extra is None or extra_gain <= 0:
            # No random candidate helped, which happens once the residue is a
            # handful of awkward pairs. Cover one directly rather than looping.
            left, lv, right, rv = sorted(uncovered, key=repr)[0]
            extra = {name: rng.choice(matrix.dimensions[name]) for name in names}
            extra[left], extra[right] = lv, rv

        uncovered -= _pairs_in(extra, names)
        rows.append(extra)

    rows.sort(key=lambda row: tuple(str(row[name]) for name in names))
    return rows


def _row_to_config(row: Row, index: int, defaults: dict[str, Any]) -> SessionConfig:
    """Turn one sampled row into a ``SessionConfig``."""
    return SessionConfig(
        name=(
            f"s{index:03d}-{row['ike']}-{row['esp']}-dh{row['dh']}"
            f"-{'pfs' if row['pfs'] else 'nopfs'}-{row['mode']}-{row['ip']}-{row['traffic']}"
        ),
        mode=OperatingMode(row["mode"]),
        ike=IkeFlavour(row["ike"]),
        esp=EspSuite(row["esp"]),
        dh=int(row["dh"]),
        pfs=bool(row["pfs"]),
        ip=IpVersion(row["ip"]),
        traffic=TRAFFIC_LABELS[row["traffic"]],
        duration_s=int(defaults.get("duration_s", 180)),
        lifetime_s=int(defaults.get("lifetime_s", 3600)),
    )


def fixture_configs(matrix: Matrix) -> list[SessionConfig]:
    """The named reference configurations from the matrix file."""
    configs = []
    for fixture in matrix.fixtures:
        row = dict(fixture)
        name = str(row.pop("name"))
        lifetime = int(row.pop("lifetime_s", matrix.defaults.get("lifetime_s", 3600)))
        row.setdefault("ip", "v4")
        configs.append(
            SessionConfig(
                name=name,
                mode=OperatingMode(row["mode"]),
                ike=IkeFlavour(row["ike"]),
                esp=EspSuite(row["esp"]),
                dh=int(row["dh"]),
                pfs=bool(row["pfs"]),
                ip=IpVersion(row["ip"]),
                traffic=TRAFFIC_LABELS[row["traffic"]],
                duration_s=int(matrix.defaults.get("duration_s", 180)),
                lifetime_s=lifetime,
            )
        )
    return configs


def sample_configs(
    matrix: Matrix | None = None,
    *,
    include_fixtures: bool = True,
) -> list[SessionConfig]:
    """The full list of configurations a batch should run.

    The reference fixtures come first and are never dropped: the demo depends on
    both existing, and neither is guaranteed to fall out of a pairwise sample.
    """
    matrix = matrix or load_matrix()
    rows = pairwise_rows(matrix)
    configs = [_row_to_config(row, i, matrix.defaults) for i, row in enumerate(rows)]

    if include_fixtures:
        fixtures = fixture_configs(matrix)
        configs = fixtures + configs

    log.info(
        "sampled %d configurations from a cross-product of %d",
        len(configs),
        matrix.cross_product_size,
    )
    return configs


def with_repeats(configs: Sequence[SessionConfig], repeats: int) -> list[SessionConfig]:
    """Expand each configuration into *repeats* traffic runs. Step 8.3.

    PRD section 9.3 wants at least 200 sessions and the pairwise sample is 62
    configurations, so the remainder has to come from running each one more than
    once -- which is only worth doing if the runs actually differ. Each repeat
    gets its own ``seed``, and every traffic generator draws its within-class
    parameters from that (see ``traffic/base.generate_traffic``), so run 2 of a
    configuration is a different VoIP call rather than a copy of run 1. The
    tunnel configuration is deliberately *identical* across a config's repeats:
    that is what makes "split by configuration" (step 9.5) a meaningful
    boundary, and a repeat that changed the crypto would be a different
    configuration wearing the same name.

    Run 1 keeps the base name and seed, so a batch run with ``repeats=1`` is
    byte-identical to one that never passed the flag and an existing manifest
    still resumes.
    """
    if repeats < 1:
        msg = f"repeats must be at least 1, got {repeats}"
        raise ValueError(msg)

    expanded: list[SessionConfig] = []
    for config in configs:
        expanded.append(config)
        for run in range(2, repeats + 1):
            expanded.append(
                config.model_copy(
                    update={"name": f"{config.name}-r{run}", "seed": config.seed + run - 1}
                )
            )
    return expanded


def coverage_report(matrix: Matrix, rows: Iterable[Row]) -> dict[str, dict[Any, int]]:
    """How many times each value of each dimension appears in ``rows``.

    Step 2.9 requires that every value of every dimension appears at least once.
    Returning the counts rather than a boolean means a failure says which value
    is missing.
    """
    rows = list(rows)
    return {
        name: {value: sum(1 for row in rows if row[name] == value) for value in values}
        for name, values in matrix.dimensions.items()
    }
