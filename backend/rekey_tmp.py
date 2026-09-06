"""Step 9.3's Done when: an observed rekey interval within 10% of a 300s lifetime.

The sampled matrix uses a 3600-second lifetime and 180-second sessions, so no
configuration in it ever rekeys inside its own capture. This generates the one
session that does: a 300-second lifetime captured for 700 seconds, long enough
for two rotations rather than one, because a single rotation cannot distinguish
"rekeyed on time" from "rekeyed once, for some other reason".
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

from testbed.sampler import fixture_configs, load_matrix
from testbed.orchestrator import run_session

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
for noisy in ("docker", "urllib3"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

out = Path(sys.argv[1])
matrix = load_matrix()
base = next(c for c in fixture_configs(matrix) if c.name == "hardened-reference")
# address_index 3 keeps this off the three generation shards' subnets, which
# are 0, 1 and 2 -- two sessions cannot share a Docker bridge subnet.
cfg = base.model_copy(
    update={
        "name": "rekey-300s",
        "lifetime_s": 300,
        "duration_s": 700,
        "address_index": 3,
    }
)

result = asyncio.run(run_session(cfg, out))
print("SESSION", result.pcap, result.packet_count)
