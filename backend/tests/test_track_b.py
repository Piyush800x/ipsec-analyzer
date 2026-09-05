"""Phase 9's deterministic half: steps 9.1-9.4 and 9.11.

Steps 9.6-9.10 and 9.12 train models on the Phase 8 dataset, which needs
Docker and does not exist. What is tested here is everything that does not:
the congruence sieve, sequence and rekey analysis, PFS size inference, the
feature extractor, and the service that must degrade honestly without a model.
"""

from __future__ import annotations

import math

import pytest

from analyzer.core.enums import Provenance
from analyzer.core.schema import CaptureQuality
from analyzer.ingest.flow import Flow, SAPair
from analyzer.ingest.reader import FlowKey, PacketRecord
from analyzer.track_b import cipher_family, features, replay
from analyzer.track_b.pfs import DH_PUBLIC_SIZE, KE_PAYLOAD_HEADER, infer_pfs
from analyzer.track_b.service import InferenceService


def _quality(**overrides: object) -> CaptureQuality:
    base: dict[str, object] = {
        "packet_count": 500,
        "duration_s": 60.0,
        "truncated": False,
        "has_ike": True,
        "ike_complete": True,
        "esp_sa_count": 2,
        "sufficient_for_lattice": True,
        "warnings": [],
    }
    base.update(overrides)
    return CaptureQuality(**base)  # type: ignore[arg-type]


def _packet(
    index: int, ts: float, src: str, dst: str, spi: int, length: int, seq: int | None = None
) -> PacketRecord:
    return PacketRecord(
        index=index,
        ts=ts,
        ip_version=4,
        src=src,
        dst=dst,
        proto="esp",
        spi=spi,
        seq=index if seq is None else seq,
        ip_payload_len=length + 8,
        esp_payload_len=length,
        captured_len=length + 42,
        orig_len=length + 42,
    )


def _pair(forward_packets: list[PacketRecord], reverse_packets: list[PacketRecord] | None = None):
    forward = Flow(
        key=FlowKey("10.0.0.1", "10.0.0.2", 1, "esp"),
        packets=tuple(forward_packets),
        start_ts=forward_packets[0].ts,
        end_ts=forward_packets[-1].ts,
    )
    reverse = (
        Flow(
            key=FlowKey("10.0.0.2", "10.0.0.1", 2, "esp"),
            packets=tuple(reverse_packets),
            start_ts=reverse_packets[0].ts,
            end_ts=reverse_packets[-1].ts,
        )
        if reverse_packets
        else None
    )
    return SAPair(forward=forward, reverse=reverse, paired=reverse is not None)


# ===========================================================================
# Step 9.2: the cipher-family sieve
# ===========================================================================


def _lengths_for(iv: int, icv: int, block: int, count: int = 40) -> list[int]:
    """Payload lengths a suite with this geometry would actually produce."""
    return [iv + icv + block * multiple for multiple in range(1, count + 1)]


def test_identifies_aes_cbc_sha1() -> None:
    """Step 9.2 Done-when: an AES-CBC-SHA1 capture is identified."""
    lengths = _lengths_for(16, 12, 16)
    result = cipher_family.detect(lengths, _quality())

    assert result.provenance is Provenance.INFERRED
    assert result.value == "AES-CBC + HMAC-SHA1-96"
    assert result.evidence is not None
    assert "survivors" in result.evidence.measured


def test_identifies_aes_gcm_16() -> None:
    """Step 9.2 Done-when: an AES-GCM-16 capture is identified."""
    lengths = _lengths_for(8, 16, 4)
    result = cipher_family.detect(lengths, _quality())

    assert result.provenance is Provenance.INFERRED
    # GCM-16 and ChaCha20-Poly1305 share their geometry exactly, so both
    # survive and the confidence must reflect that rather than pretending.
    assert result.value in {"AES-GCM-16", "ChaCha20-Poly1305"}
    assert result.confidence is not None
    assert result.confidence < 1.0


def test_voip_style_capture_returns_unavailable() -> None:
    """Step 9.2 Done-when, and the one that matters most: a VoIP-only capture
    must refuse to answer rather than guess."""
    result = cipher_family.detect([120] * 400, _quality(sufficient_for_lattice=False))

    assert result.provenance is Provenance.UNAVAILABLE
    assert result.value is None
    assert "length diversity" in (result.note or "")


def test_truncated_capture_returns_unavailable() -> None:
    result = cipher_family.detect(
        _lengths_for(16, 12, 16), _quality(truncated=True, sufficient_for_lattice=False)
    )
    assert result.provenance is Provenance.UNAVAILABLE
    assert "truncated" in (result.note or "")


def test_one_counterexample_eliminates_a_candidate() -> None:
    """A sieve, not a vote: 399 agreeing packets do not outvote one that does not."""
    clean = _lengths_for(16, 12, 16)
    assert any(c.name.startswith("AES-CBC + HMAC-SHA1") for c in cipher_family.survivors(clean))

    assert not any(
        c.name.startswith("AES-CBC + HMAC-SHA1")
        for c in cipher_family.survivors([*clean, clean[0] + 1])
    )


def test_no_survivors_is_unavailable_not_a_wrong_answer() -> None:
    # Odd lengths satisfy no candidate's congruence.
    result = cipher_family.detect([31, 33, 35, 37, 39, 41, 43, 45], _quality())

    assert result.provenance is Provenance.UNAVAILABLE
    assert "no candidate" in (result.note or "")


def test_confidence_falls_as_survivors_rise() -> None:
    assert cipher_family.confidence_for(1) == 1.0
    assert cipher_family.confidence_for(len(cipher_family.CANDIDATES)) == 0.0
    assert cipher_family.confidence_for(2) > cipher_family.confidence_for(4)


def test_survivor_set_is_reported_not_just_the_winner() -> None:
    result = cipher_family.detect(_lengths_for(8, 16, 4), _quality())
    assert result.evidence is not None
    assert result.evidence.measured["survivor_count"] >= 2
    assert "still standing" in (result.note or "")


# ===========================================================================
# Step 9.3: replay and rekey
# ===========================================================================


def test_monotonic_sequences_are_sane() -> None:
    packets = [_packet(i, float(i), "10.0.0.1", "10.0.0.2", 1, 100) for i in range(50)]
    result = replay.replay_sane(packets)

    assert result.provenance is Provenance.INFERRED
    assert result.value is True


def test_duplicate_sequence_numbers_are_not_sane() -> None:
    packets = [_packet(i, float(i), "10.0.0.1", "10.0.0.2", 1, 100, seq=i % 25) for i in range(50)]
    result = replay.replay_sane(packets)

    assert result.value is False
    assert result.evidence is not None
    assert result.evidence.measured["duplicates"] > 0


def test_gaps_are_reported_but_never_called_an_attack() -> None:
    """LLD section 7.5: gaps also arise from capture drops."""
    packets = [_packet(i, float(i), "10.0.0.1", "10.0.0.2", 1, 100, seq=i * 3) for i in range(50)]
    result = replay.replay_sane(packets)

    assert result.value is False
    assert "capture drops" in (result.note or "")
    assert "attack" not in (result.note or "").replace("replay attack", "")


def test_too_few_packets_is_unavailable() -> None:
    packets = [_packet(i, float(i), "10.0.0.1", "10.0.0.2", 1, 100) for i in range(5)]
    assert replay.replay_sane(packets).provenance is Provenance.UNAVAILABLE


def test_anti_replay_window_size_is_always_unavailable() -> None:
    """LLD section 7.5: never transmitted, so never reportable. There is no
    input that changes this answer, which is why it takes none."""
    result = replay.anti_replay_window_size()

    assert result.provenance is Provenance.UNAVAILABLE
    assert "never transmitted" in (result.note or "")


def test_observed_rekey_interval() -> None:
    """Step 9.3 Done-when: a 300-second lifetime lands within 10% of 300."""
    result = replay.observed_rekey_s([(1, 0.0), (2, 298.0), (3, 601.0)])

    assert result.provenance is Provenance.INFERRED
    assert result.value is not None
    assert abs(result.value - 300) <= 30


def test_single_spi_means_no_rekey_observed_not_no_rekeying() -> None:
    result = replay.observed_rekey_s([(1, 0.0)])

    assert result.provenance is Provenance.UNAVAILABLE
    assert "not evidence that the SA never rekeys" in (result.note or "")


# ===========================================================================
# Step 9.4: PFS inference
# ===========================================================================


def test_pfs_detected_for_modp_group() -> None:
    """Step 9.4 Done-when: PFS-on with DH-14 is detected."""
    expected = DH_PUBLIC_SIZE[14] + KE_PAYLOAD_HEADER
    result = infer_pfs([400 + expected] * 3, [400] * 5, 14)

    assert result.value is True
    assert result.confidence == pytest.approx(0.9)


def test_pfs_absent_for_modp_group() -> None:
    """Step 9.4 Done-when: PFS-off with DH-14 is separated from PFS-on."""
    result = infer_pfs([405, 402, 408], [400] * 5, 14)
    assert result.value is False


def test_ecp_group_carries_lower_confidence() -> None:
    """Step 9.4 Done-when: DH-19 returns a correspondingly lower confidence."""
    expected = DH_PUBLIC_SIZE[19] + KE_PAYLOAD_HEADER
    ecp = infer_pfs([400 + expected] * 3, [400] * 5, 19)
    modp = infer_pfs([400 + DH_PUBLIC_SIZE[14] + KE_PAYLOAD_HEADER] * 3, [400] * 5, 14)

    assert ecp.confidence is not None
    assert modp.confidence is not None
    assert ecp.confidence < modp.confidence
    assert "overlap ordinary traffic-selector variation" in (ecp.note or "")


def test_no_create_child_sa_is_unavailable() -> None:
    result = infer_pfs([], [400], 14)
    assert result.provenance is Provenance.UNAVAILABLE
    assert "not evidence either way" in (result.note or "")


def test_unknown_dh_group_is_unavailable() -> None:
    assert infer_pfs([600], [400], None).provenance is Provenance.UNAVAILABLE
    assert infer_pfs([600], [400], 999).provenance is Provenance.UNAVAILABLE


# ===========================================================================
# Step 9.1: features
# ===========================================================================


def test_feature_vector_has_no_nans() -> None:
    """Step 9.1 Done-when: no NaNs, on a flow short enough to produce them."""
    pair = _pair(
        [_packet(i, float(i) * 0.1, "10.0.0.1", "10.0.0.2", 1, 100 + i) for i in range(5)],
        [_packet(i, float(i) * 0.1 + 0.05, "10.0.0.2", "10.0.0.1", 2, 80) for i in range(3)],
    )

    vector = features.extract(pair)

    assert vector
    for name, value in vector.items():
        assert not math.isnan(value), name
        assert not math.isinf(value), name


def test_single_packet_flow_produces_no_nans() -> None:
    """std over one sample is null in Polars; zero is the honest answer."""
    pair = _pair([_packet(0, 0.0, "10.0.0.1", "10.0.0.2", 1, 100)])

    vector = features.extract(pair)

    assert vector["esp_len_std"] == 0.0
    assert all(not math.isnan(v) for v in vector.values())


def test_one_directional_flow_does_not_divide_by_zero() -> None:
    pair = _pair([_packet(i, float(i), "10.0.0.1", "10.0.0.2", 1, 100) for i in range(30)])

    vector = features.extract(pair)

    assert vector["up_down_byte_ratio"] == 0.0
    assert vector["down_packets"] == 0.0


def test_features_are_deterministic() -> None:
    pair = _pair([_packet(i, float(i), "10.0.0.1", "10.0.0.2", 1, 100 + i) for i in range(30)])
    assert features.extract(pair) == features.extract(pair)


def test_sequence_features_are_padded_and_signed() -> None:
    pair = _pair(
        [_packet(i, float(i), "10.0.0.1", "10.0.0.2", 1, 100) for i in range(3)],
        [_packet(i, float(i) + 0.5, "10.0.0.2", "10.0.0.1", 2, 80) for i in range(2)],
    )

    sequence = features.sequence_features(pair)

    assert len(sequence) == features.SEQUENCE_FEATURE_LENGTH
    assert any(value > 0 for value in sequence)
    assert any(value < 0 for value in sequence), "direction must be signed"
    assert sequence[-1] == 0.0, "short flows are zero-padded"


# ===========================================================================
# Step 9.11: the inference service, with no models
# ===========================================================================


def test_service_reports_unavailable_where_a_model_is_missing() -> None:
    """The honest-degradation requirement, asserted."""
    pair = _pair([_packet(i, float(i), "10.0.0.1", "10.0.0.2", 1, 100 + i) for i in range(30)])

    result = InferenceService().analyse(pair, _quality(sufficient_for_lattice=False))

    assert result.operating_mode.provenance is Provenance.UNAVAILABLE
    assert "no trained model" in (result.operating_mode.note or "")
    assert result.inner_traffic == []


def test_service_still_runs_the_deterministic_analyses() -> None:
    """Missing models must not disable the parts that need none."""
    lengths = _lengths_for(16, 12, 16, count=30)
    pair = _pair(
        [
            _packet(i, float(i), "10.0.0.1", "10.0.0.2", 1, length)
            for i, length in enumerate(lengths)
        ]
    )

    result = InferenceService().analyse(pair, _quality())

    assert result.encryption_alg_family.provenance is Provenance.INFERRED
    assert result.replay_sane.provenance is Provenance.INFERRED


def test_service_reports_no_model_versions() -> None:
    """The correct state for a Track A-only assessment, per the contract."""
    assert InferenceService().model_versions == {}
