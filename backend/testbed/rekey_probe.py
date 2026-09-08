"""Generate the one session that rekeys inside its own capture. Step 9.3.

``python -m testbed.rekey_probe <output-dir>``

Step 9.3's **Done when** is "observed rekey interval on a capture with a
300-second lifetime lands within 10% of 300", and nothing in the sampled matrix
can demonstrate it. Every matrix row runs a 3600-second lifetime for 90 or 180
seconds, so no session in the dataset ever rekeys while the capture is open --
which is correct for a *dataset* (a rekey mid-session would split one flow into
two SPIs and complicate every label) and useless for *this* measurement.

So this is deliberately not a matrix row. It is one configuration built to make
the thing step 9.3 measures actually happen:

* **300-second lifetime**, the figure the Done-when names.
* **700 seconds of capture**, long enough for two rotations rather than one. A
  single rotation cannot distinguish "rekeyed on time" from "rekeyed once, for
  some other reason" -- an interval needs two events to be an interval at all.
* **IKEv2 and a hardened suite**, because `observed_rekey_s` measures SPI
  rotation timing and has no dependence on the cipher; borrowing the existing
  hardened reference keeps one fewer thing invented here.
* **A subnet index outside the generation shards' range**, so this can run
  alongside a batch. Two sessions cannot share a Docker bridge subnet.

The output is an ordinary session directory. `analyzer.track_b.replay
.observed_rekey_s` reads it like any other capture.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from testbed.orchestrator import run_session
from testbed.sampler import fixture_configs, load_matrix

LIFETIME_S: Final = 300
"""The lifetime step 9.3's Done when names."""

DURATION_S: Final = 700
"""Long enough for two rotations at that lifetime, plus room for the second to
land inside the capture rather than on its edge."""

ADDRESS_INDEX: Final = 3
"""Clear of shards 1-3, which take indices 0, 1 and 2."""

BASE_FIXTURE: Final = "hardened-reference"


def build_config(name: str = "rekey-300s"):  # type: ignore[no-untyped-def] # SessionConfig, imported lazily by the sampler
    """The probe configuration, derived from the hardened reference tunnel."""
    base = next(c for c in fixture_configs(load_matrix()) if c.name == BASE_FIXTURE)
    return base.model_copy(
        update={
            "name": name,
            "lifetime_s": LIFETIME_S,
            "duration_s": DURATION_S,
            "address_index": ADDRESS_INDEX,
        }
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--name", default="rekey-300s")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    for noisy in ("docker", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    result = asyncio.run(run_session(build_config(args.name), args.output_dir))
    sys.stdout.write(f"{result.pcap} — {result.packet_count} packets\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
