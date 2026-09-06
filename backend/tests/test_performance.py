"""Step 11.3: performance validation against NFR-1.

NFR-1 budgets 60 seconds end to end for a 10-minute, 100 MB capture. This
builds one, runs the pipeline over it, and asserts the budget.

**What this does not measure.** Track A shells out to tshark, which is not
installed in the environment this was written in, so the Track A stage raises
and is skipped. The measured time is ingest + Track B + assess. tshark on a
100 MB capture filtered to `isakmp` is not free, and this number will move
when it is included -- see CHANGELOG's Phase 11 "Not verified".

Marked slow: it writes 100 MB and is not worth paying for on every run.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from analyzer.api.pipeline import analyse_capture
from analyzer.assess.engine import AssessmentEngine
from analyzer.assess.policy import load_policy
from analyzer.core.ids import new_id
from tests._pcap import DLT_EN10MB, esp_payload, eth_frame, ipv4_packet, write_pcap

BASELINE = Path(__file__).resolve().parents[1] / "src/analyzer/assess/policies/baseline.yaml"

TARGET_BYTES = 100 * 1024 * 1024
NFR1_BUDGET_S = 60.0


def _build_capture(path: Path) -> int:
    """A busy bidirectional tunnel with varied payload sizes."""
    frames: list[bytes] = []
    size = 0
    index = 0
    while size < TARGET_BYTES:
        body = b"X" * (48 + (index % 64) * 16)
        if index % 2 == 0:
            frame = eth_frame(
                ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, index // 2 + 1, body))
            )
        else:
            frame = eth_frame(
                ipv4_packet("10.0.0.2", "10.0.0.1", 50, esp_payload(2, index // 2 + 1, body))
            )
        frames.append(frame)
        size += len(frame) + 16
        index += 1
    write_pcap(path, DLT_EN10MB, frames)
    return len(frames)


@pytest.mark.slow
def test_hundred_megabyte_capture_within_nfr1_budget(tmp_path: Path) -> None:
    """Step 11.3 Done-when: under 60 seconds, or the bottleneck is named."""
    pcap = tmp_path / "perf.pcap"
    packet_count = _build_capture(pcap)
    engine = AssessmentEngine(load_policy(BASELINE))

    started = time.perf_counter()
    document = analyse_capture(
        pcap,
        engine,
        capture_id=new_id(),
        engine_version="perf",
        generated_at=datetime.now(tz=UTC),
    )
    elapsed = time.perf_counter() - started

    assert document.capture_quality.packet_count == packet_count
    assert elapsed < NFR1_BUDGET_S, (
        f"{pcap.stat().st_size / 1024 / 1024:.0f} MB took {elapsed:.1f}s, "
        f"over the {NFR1_BUDGET_S}s NFR-1 budget"
    )
