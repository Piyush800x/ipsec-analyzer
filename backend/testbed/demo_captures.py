"""Freeze the two PRD section 16 demo captures. Step 11.5.

``python -m testbed.demo_captures <output-dir>``

The demo runs two prepared tunnels through the tool live: one deliberately weak
and one hardened, both carrying the same VoIP call, so the contrast in the score
is a contrast in the configuration and nothing else. These are the two captures
that get loaded on stage, and step 11.5's **Done when** is that both are
committed and that *neither appears in any training split*.

**Why these are not just the matrix's two reference fixtures.** The matrix
already contains ``weak-reference`` and ``hardened-reference`` with exactly the
PRD section 16 parameters, and the sampler generates them regardless of what
pairwise picks -- but they are *dataset* sessions, and step 9.5 splits the
dataset three ways. Measured on the real split, ``weak-reference`` landed in the
test fold and ``hardened-reference`` in the calibration fold, which fitted the
classifier's confidence. Demoing a model's confidence on the capture that
calibrated it is exactly the circularity the step exists to prevent.

So the demo captures are their own configurations, generated into their own
directory, with their own seed:

* **Their own names.** ``demo-tunnel-a`` and ``demo-tunnel-b`` are not
  configuration names in the dataset, so ``split_configs`` cannot place them in
  a fold -- there is nothing to place. ``tests/test_demo_captures.py`` asserts
  that against the real split rather than trusting it.
* **Their own directory.** ``dataset/demo/`` rather than ``dataset/sessions/``,
  so ``load_dataset`` never walks them. A capture that is not in the corpus
  cannot be trained on by accident later either.
* **Their own seed.** ``DEMO_SEED`` differs from the dataset's, so the VoIP call
  inside is a different call, not a re-run of one the model has seen.

**What is still shared, stated plainly.** The tunnel *parameters* are dictated
by PRD section 16 and are therefore identical to those two dataset
configurations -- that is the point of a reference fixture. The demo shows a
tool analysing a capture, not a held-out evaluation, and the honest reading is
that the traffic classifier has seen this cipher suite and this traffic class
before, as it has for every class in the matrix. What it has not seen is this
capture, this call, or this configuration name.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from testbed.orchestrator import run_session
from testbed.sampler import fixture_configs, load_matrix

if TYPE_CHECKING:
    from testbed.config import SessionConfig

log = logging.getLogger(__name__)

TUNNEL_A: Final = "demo-tunnel-a"
"""PRD section 16's weak tunnel: IKEv1 aggressive, 3DES-CBC, HMAC-SHA1-96,
DH group 2, PFS off, 24-hour lifetime, transport mode, VoIP."""

TUNNEL_B: Final = "demo-tunnel-b"
"""PRD section 16's hardened tunnel: IKEv2, AES-256-GCM, DH group 19, PFS on,
1-hour lifetime, tunnel mode, the same VoIP call."""

DEMO_NAMES: Final = (TUNNEL_A, TUNNEL_B)

BASE_FIXTURES: Final = {TUNNEL_A: "weak-reference", TUNNEL_B: "hardened-reference"}
"""Which matrix fixture each demo tunnel takes its parameters from.

Derived rather than restated so that the demo cannot drift away from PRD
section 16 while the matrix stays faithful to it, or the reverse. If the two
tunnels are ever wrong, they are wrong in `matrix.yaml`, in one place.
"""

DEMO_SEED: Final = 20261105
"""Not the dataset's seed. Every generator draws its within-class parameters
from this, so the call inside these captures is a different call."""

DURATION_S: Final = 120
"""Long enough for a comfortable number of 10-second windows to score and for
the SPI and sequence behaviour to be visible, short enough that both captures
stay a few megabytes and can live in git."""

ADDRESS_INDEX: Final[dict[str, int]] = {TUNNEL_A: 6, TUNNEL_B: 7}
"""Clear of generation shards 1-6 (indices 0-5) and the rekey probe (index 3),
so this can run alongside either. Two sessions cannot share a Docker bridge
subnet."""

MANIFEST_NAME: Final = "demo.json"


def build_configs() -> list[SessionConfig]:
    """The two demo configurations, derived from the matrix's reference rows."""
    fixtures = {cfg.name: cfg for cfg in fixture_configs(load_matrix())}
    configs = []
    for name in DEMO_NAMES:
        base = fixtures[BASE_FIXTURES[name]]
        configs.append(
            base.model_copy(
                update={
                    "name": name,
                    "seed": DEMO_SEED,
                    "duration_s": DURATION_S,
                    "address_index": ADDRESS_INDEX[name],
                }
            )
        )
    return configs


def write_manifest(output_dir: Path, results: dict[str, int]) -> Path:
    """Record what was frozen, so the captures are self-describing.

    The demo is the one place a stale artefact is most costly and least
    visible: a capture regenerated after a parser change looks identical in
    `git status` and behaves differently on stage.
    """
    manifest = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "seed": DEMO_SEED,
        "duration_s": DURATION_S,
        "purpose": (
            "PRD section 16 demo captures, implementation-plan step 11.5. Held "
            "outside dataset/sessions/ so that no training, calibration or test "
            "fold can contain them."
        ),
        "tunnels": {
            name: {
                "packet_count": results[name],
                "derived_from_matrix_fixture": BASE_FIXTURES[name],
            }
            for name in DEMO_NAMES
            if name in results
        },
    }
    path = output_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "--only",
        choices=DEMO_NAMES,
        default=None,
        help="regenerate just one of the two tunnels",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    for noisy in ("docker", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    configs = [c for c in build_configs() if args.only is None or c.name == args.only]
    args.output_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, int] = {}
    for cfg in configs:
        log.info("%s: %s", cfg.name, cfg.model_dump_json())
        result = asyncio.run(run_session(cfg, args.output_dir))
        results[cfg.name] = result.packet_count
        sys.stdout.write(f"{result.pcap} — {result.packet_count} packets\n")

    manifest = write_manifest(args.output_dir, results)
    sys.stdout.write(f"{manifest}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
