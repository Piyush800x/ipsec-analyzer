"""Step 3.6: CaptureQuality computation.

Both Done-when assertions from the implementation plan are covered directly:
a snaplen-truncated capture sets ``truncated``, and a VoIP-shaped capture (few
distinct ESP lengths) sets ``sufficient_for_lattice = False``. The second one
matters more than the first -- LLD section 7.2 calls it the guard against a
confident wrong cipher-family answer.
"""

from __future__ import annotations

from analyzer.core.schema import MIN_DISTINCT_LENGTHS_FOR_LATTICE, MIN_ESP_PACKETS_FOR_LATTICE
from analyzer.ingest.flow import assemble_flows
from analyzer.ingest.quality import compute_quality
from analyzer.ingest.reader import IngestResult, PacketRecord


def _esp_record(
    index: int, src: str, dst: str, spi: int, esp_len: int, *, truncated: bool = False
) -> PacketRecord:
    orig_len = 100
    return PacketRecord(
        index=index,
        ts=float(index),
        ip_version=4,
        src=src,
        dst=dst,
        proto="esp",
        spi=spi,
        seq=index,
        ip_payload_len=esp_len + 8,
        esp_payload_len=esp_len,
        captured_len=40 if truncated else orig_len,
        orig_len=orig_len,
    )


def test_truncated_capture_is_flagged() -> None:
    """Mirrors ``tcpdump -s 96`` cutting packets short."""
    packets = [_esp_record(0, "10.0.0.1", "10.0.0.2", spi=1, esp_len=64, truncated=True)]
    result = IngestResult(packets=packets, ike_message_ids=[])

    quality = compute_quality(result, assemble_flows(packets))

    assert quality.truncated is True
    assert quality.sufficient_for_lattice is False
    assert any("truncated" in w for w in quality.warnings)


def test_voip_like_capture_is_insufficient_for_lattice() -> None:
    """A handful of packets at one or two lengths -- the VoIP degenerate case."""
    packets = [
        _esp_record(i, "10.0.0.1", "10.0.0.2", spi=1, esp_len=64 if i % 2 == 0 else 68)
        for i in range(40)
    ]
    result = IngestResult(packets=packets, ike_message_ids=[])

    quality = compute_quality(result, assemble_flows(packets))

    assert quality.sufficient_for_lattice is False
    assert quality.esp_sa_count == 1


def test_diverse_capture_is_sufficient_for_lattice() -> None:
    packets = [
        _esp_record(
            i,
            "10.0.0.1",
            "10.0.0.2",
            spi=1,
            esp_len=64 + 16 * (i % MIN_DISTINCT_LENGTHS_FOR_LATTICE),
        )
        for i in range(MIN_ESP_PACKETS_FOR_LATTICE)
    ]
    result = IngestResult(packets=packets, ike_message_ids=[])

    quality = compute_quality(result, assemble_flows(packets))

    assert quality.sufficient_for_lattice is True
    assert quality.truncated is False


def test_ike_complete_true_when_sa_init_observed() -> None:
    packets = [
        PacketRecord(0, 0.0, 4, "10.0.0.1", "10.0.0.2", "isakmp", None, None, 36, None, 60, 60),
    ]
    result = IngestResult(packets=packets, ike_message_ids=[0])

    quality = compute_quality(result, assemble_flows(packets))

    assert quality.has_ike is True
    assert quality.ike_complete is True


def test_ike_complete_false_when_joined_mid_stream() -> None:
    packets = [
        PacketRecord(0, 0.0, 4, "10.0.0.1", "10.0.0.2", "isakmp", None, None, 36, None, 60, 60),
    ]
    result = IngestResult(packets=packets, ike_message_ids=[7])

    quality = compute_quality(result, assemble_flows(packets))

    assert quality.has_ike is True
    assert quality.ike_complete is False
    assert any("mid-stream" in w for w in quality.warnings)


def test_no_ike_at_all() -> None:
    packets = [_esp_record(0, "10.0.0.1", "10.0.0.2", spi=1, esp_len=64)]
    result = IngestResult(packets=packets, ike_message_ids=[])

    quality = compute_quality(result, assemble_flows(packets))

    assert quality.has_ike is False
    assert quality.ike_complete is False


def test_empty_capture() -> None:
    result = IngestResult(packets=[], ike_message_ids=[])

    quality = compute_quality(result, assemble_flows([]))

    assert quality.packet_count == 0
    assert quality.duration_s == 0.0
    assert quality.sufficient_for_lattice is False
