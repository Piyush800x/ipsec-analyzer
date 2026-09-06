"""Step 3.5: flow assembly and SA pairing."""

from __future__ import annotations

from analyzer.ingest.flow import assemble_flows
from analyzer.ingest.reader import PacketRecord


def _record(
    index: int, ts: float, src: str, dst: str, spi: int, proto: str = "esp"
) -> PacketRecord:
    return PacketRecord(
        index=index,
        ts=ts,
        ip_version=4,
        src=src,
        dst=dst,
        proto=proto,  # type: ignore[arg-type] # test helper; always a valid literal in practice
        spi=spi,
        seq=index,
        ip_payload_len=40,
        esp_payload_len=32,
        captured_len=60,
        orig_len=60,
    )


def test_bidirectional_capture_yields_exactly_one_sa_pair() -> None:
    """Done when (3.5): a bidirectional capture yields exactly one SAPair."""
    packets = [
        _record(0, 0.0, "10.0.0.1", "10.0.0.2", spi=1),
        _record(1, 1.0, "10.0.0.1", "10.0.0.2", spi=1),
        _record(2, 0.5, "10.0.0.2", "10.0.0.1", spi=2),
        _record(3, 1.5, "10.0.0.2", "10.0.0.1", spi=2),
    ]

    pairs = assemble_flows(packets)

    assert len(pairs) == 1
    (pair,) = pairs
    assert pair.paired is True
    assert pair.reverse is not None
    assert {pair.forward.key.spi, pair.reverse.key.spi} == {1, 2}


def test_one_directional_capture_yields_one_flagged_unpaired_sa() -> None:
    """Done when (3.5): a one-directional capture flags rather than errors."""
    packets = [
        _record(0, 0.0, "10.0.0.1", "10.0.0.2", spi=1),
        _record(1, 1.0, "10.0.0.1", "10.0.0.2", spi=1),
    ]

    pairs = assemble_flows(packets)

    assert len(pairs) == 1
    (pair,) = pairs
    assert pair.paired is False
    assert pair.reverse is None
    assert pair.forward.key.spi == 1


def test_non_overlapping_reverse_flow_is_not_paired() -> None:
    """Same endpoints reversed, same proto, but the two SAs never coexist."""
    packets = [
        _record(0, 0.0, "10.0.0.1", "10.0.0.2", spi=1),
        _record(1, 1.0, "10.0.0.1", "10.0.0.2", spi=1),
        _record(2, 100.0, "10.0.0.2", "10.0.0.1", spi=2),
        _record(3, 101.0, "10.0.0.2", "10.0.0.1", spi=2),
    ]

    pairs = assemble_flows(packets)

    assert len(pairs) == 2
    assert all(not pair.paired for pair in pairs)


def test_isakmp_packets_do_not_form_flows() -> None:
    packets = [
        _record(0, 0.0, "10.0.0.1", "10.0.0.2", spi=1, proto="esp"),
        _record(1, 0.5, "10.0.0.1", "10.0.0.2", spi=0, proto="isakmp"),
    ]

    pairs = assemble_flows(packets)

    assert len(pairs) == 1
    assert pairs[0].forward.key.proto == "esp"
