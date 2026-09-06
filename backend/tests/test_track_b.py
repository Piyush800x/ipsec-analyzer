"""Phase 9's deterministic half: steps 9.1-9.4 and 9.11.

Steps 9.6-9.10 and 9.12 train models on the Phase 8 dataset, which needs
Docker and does not exist. What is tested here is everything that does not:
the congruence sieve, sequence and rekey analysis, PFS size inference, the
feature extractor, and the service that must degrade honestly without a model.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from pathlib import Path

import pytest

from analyzer.core.enums import EncryptionAlg, IntegrityAlg, Provenance
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

    assert result.encryption_alg.provenance is Provenance.INFERRED
    assert result.encryption_alg.value is EncryptionAlg.AES_CBC
    assert result.replay_sane.provenance is Provenance.INFERRED


def test_service_reports_no_model_versions() -> None:
    """The correct state for a Track A-only assessment, per the contract."""
    assert InferenceService().model_versions == {}


# --- the gap that let a suite label reach an enum-typed field --------------


def test_sieve_output_survives_assessment_validation(tmp_path: Path) -> None:
    """A *successful* sieve must produce a document the contract accepts.

    This is the regression test for a defect the rest of the suite could not
    catch. Every other cipher-sieve test asserts on the ``Attribute`` the sieve
    returns, and every degradation test drives a capture where the sieve
    refuses -- so nothing ever carried a successful inference through
    ``SecurityAssociation`` into ``Assessment``. ``model_copy(update=...)`` does
    not validate, so writing the suite label ``"AES-CBC + HMAC-SHA256-128"``
    into ``encryption_alg`` (an ``EncryptionAlg`` field) built a plausible
    object and blew up several layers later, when the API validated the
    finished assessment and returned a 500 to the dashboard.

    The capture below clears both lattice gates -- 200+ packets and 8+ distinct
    ESP payload lengths -- which is the specific path that was untested.
    """
    from analyzer.api.pipeline import analyse_capture
    from analyzer.assess.engine import AssessmentEngine
    from analyzer.assess.policy import load_policy
    from analyzer.core.ids import new_id
    from tests._pcap import DLT_EN10MB, esp_payload, eth_frame, ipv4_packet, write_pcap

    policy = Path(__file__).resolve().parents[1] / "src/analyzer/assess/policies/baseline.yaml"
    pcap = tmp_path / "diverse.pcap"
    write_pcap(
        pcap,
        DLT_EN10MB,
        [
            eth_frame(
                ipv4_packet(
                    "10.0.0.1", "10.0.0.2", 50, esp_payload(1, i, b"X" * (48 + (i % 13) * 16))
                )
            )
            for i in range(1, 150)
        ]
        + [
            eth_frame(
                ipv4_packet(
                    "10.0.0.2", "10.0.0.1", 50, esp_payload(2, i, b"Y" * (48 + (i % 11) * 16))
                )
            )
            for i in range(1, 150)
        ],
    )

    document = analyse_capture(
        pcap,
        AssessmentEngine(load_policy(policy)),
        capture_id=new_id(),
        engine_version="test",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert document.capture_quality.sufficient_for_lattice is True
    sa = document.security_associations[0]
    assert sa.encryption_alg.provenance is Provenance.INFERRED
    assert isinstance(sa.encryption_alg.value, EncryptionAlg)
    assert sa.encryption_alg.confidence is not None
    # FR-4.9: identifying the family says nothing about the AES key length.
    assert sa.encryption_keylen.provenance is Provenance.UNAVAILABLE


def test_confidence_counts_distinct_answers_not_survivors() -> None:
    """Each field's confidence measures *that field*, not the survivor count.

    Lengths starting at 28 in steps of 4 leave four suites standing --
    AES-GCM-16, AES-GCM-8, AES-CTR + HMAC-SHA1-96, ChaCha20-Poly1305 -- which
    name four different ciphers but only two integrity algorithms, because
    three of them are AEAD and take ``none``. So the same evidence pins the
    integrity algorithm down harder than the cipher, and the two confidences
    must differ accordingly. Scoring both off ``len(survivors)`` would have
    reported one number for two different degrees of certainty.
    """
    lengths = [28 + 4 * i for i in range(12)]
    quality = _quality()

    matching = cipher_family.survivors(lengths)
    assert len({c.encryption_alg for c in matching}) == 4
    assert len({c.integrity_alg for c in matching}) == 2

    encryption = cipher_family.detect_encryption(lengths, quality)
    integrity = cipher_family.detect_integrity(lengths, quality)

    assert encryption.confidence is not None
    assert integrity.confidence is not None
    # Two integrity answers out of the 4 the candidate set can produce beats
    # four cipher answers out of 6.
    assert integrity.confidence > encryption.confidence


def test_a_single_surviving_suite_is_certain_about_both_fields() -> None:
    """The other end of the same formula: one survivor, nothing left to doubt."""
    lengths = [20 + 4 * i for i in range(12)]
    quality = _quality()

    assert len(cipher_family.survivors(lengths)) == 1

    encryption = cipher_family.detect_encryption(lengths, quality)
    integrity = cipher_family.detect_integrity(lengths, quality)

    assert encryption.value is EncryptionAlg.AES_GCM_8
    assert integrity.value is IntegrityAlg.NONE
    assert encryption.confidence == pytest.approx(1.0)
    assert integrity.confidence == pytest.approx(1.0)


def test_suite_label_is_not_a_contract_value() -> None:
    """``detect`` returns display prose; it must never reach an enum field.

    Guards the shape of the original defect rather than one instance of it.
    """
    lengths = [20 + 4 * i for i in range(12)]
    label = cipher_family.detect(lengths, _quality()).value

    assert label == "AES-GCM-8"
    assert label not in set(EncryptionAlg)


def test_sieve_never_offers_a_candidate_carrying_a_key_length() -> None:
    """FR-4.9. AES-128 and AES-256 pad identically, so no amount of length
    diversity distinguishes them and no candidate may imply it does."""
    assert EncryptionAlg.AES_CBC in {c.encryption_alg for c in cipher_family.CANDIDATES}
    assert not any(
        "128" in c.encryption_alg.value or "256" in c.encryption_alg.value
        for c in cipher_family.CANDIDATES
    )
