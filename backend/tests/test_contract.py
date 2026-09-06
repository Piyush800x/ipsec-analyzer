"""Step 1.3 -- the full contract renders a JSON schema and round-trips.

The two Done-when conditions:

1. ``Assessment.model_json_schema()`` renders without error. It has to, because
   FastAPI derives the OpenAPI document from it and ``scripts/gen-types.sh``
   derives ``frontend/src/types/generated.ts`` from that. A generic model that
   cannot produce a schema breaks the frontend contract silently.
2. A hand-written fixture ``Assessment`` survives ``model_dump_json`` followed by
   ``model_validate_json`` unchanged. Anything lost in that trip is lost between
   the engine and the dashboard.

The cross-model invariants are exercised alongside, because a contract that
validates each part but not the joins between them is not a contract.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from analyzer.core.enums import (
    AuthMethod,
    EncryptionAlg,
    FindingCategory,
    IkeExchangeMode,
    IkeVersion,
    IntegrityAlg,
    OperatingMode,
    PrfAlg,
    Severity,
    TrafficClass,
)
from analyzer.core.ids import new_id
from analyzer.core.schema import (
    Assessment,
    Attribute,
    CaptureQuality,
    Evidence,
    Finding,
    MetadataExposure,
    ScoreBreakdown,
    SecurityAssociation,
    StandardRef,
    ThreatMatrixEntry,
    TrafficPrediction,
)

T0 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 9, 3, 10, 3, 0, tzinfo=UTC)

# Fixed UUIDv7 values, so the round-trip comparison is not chasing a clock.
ASSESSMENT_ID = UUID("019917d0-0000-7000-8000-000000000001")
CAPTURE_ID = UUID("019917d0-0000-7000-8000-000000000002")


def _sa() -> SecurityAssociation:
    """A hardened IKEv2 SA: everything from IKE observed, mode inferred."""
    return SecurityAssociation(
        spi_initiator="c1d4a90b",
        spi_responder="7e2f0043",
        src="10.10.0.2",
        dst="10.10.0.3",
        ip_version=4,
        protocol="esp",
        first_seen=T0,
        last_seen=T1,
        packet_count=9_012,
        byte_count=1_802_400,
        ike_version=Attribute[IkeVersion].observed(
            IkeVersion.IKEV2,
            evidence=Evidence(method="isakmp_header_version", packet_indices=[3]),
        ),
        ike_exchange_mode=Attribute[IkeExchangeMode].unavailable(
            "IKEv2 has no Phase 1 exchange mode; the concept is IKEv1-only"
        ),
        encryption_alg=Attribute[EncryptionAlg].observed(EncryptionAlg.AES_GCM_16),
        encryption_keylen=Attribute[int].observed(256),
        integrity_alg=Attribute[IntegrityAlg].observed(IntegrityAlg.NONE),
        prf_alg=Attribute[PrfAlg].observed(PrfAlg.HMAC_SHA384),
        dh_group=Attribute[int].observed(19),
        operating_mode=Attribute[OperatingMode].inferred(OperatingMode.TUNNEL, 0.94),
        pfs_enabled=Attribute[bool].observed(True),
        auth_method=Attribute[AuthMethod].unavailable(
            "IKEv2 AUTH payloads travel inside the encrypted IKE_AUTH exchange"
        ),
        negotiated_lifetime_s=Attribute[int].unavailable(
            "RFC 7296 removed lifetime negotiation from IKEv2"
        ),
        observed_rekey_s=Attribute[int].inferred(3_601, 0.88),
        esn_negotiated=Attribute[bool].observed(True),
        replay_sane=Attribute[bool].inferred(True, 0.99),
        nat_traversal=Attribute[bool].observed(False),
        downgrade_available=Attribute[bool].observed(False),
        inner_traffic=[
            TrafficPrediction(
                label=TrafficClass.VOIP,
                probability=0.91,
                window_start=T0,
                window_end=T1,
            )
        ],
    )


def _finding() -> Finding:
    return Finding(
        id="META-HIGH-EXPOSURE",
        title="Inner traffic type is identifiable from metadata",
        severity=Severity.MEDIUM,
        category=FindingCategory.METADATA_EXPOSURE,
        penalty=8,
        description="The traffic classifier identified the inner traffic as VoIP.",
        remediation="Enable padding on the child SA.",
        standards=[StandardRef(ref="NIST SP 800-77 Rev. 1", clause="3.3")],
        attack_techniques=["T1040"],
        sa_spi="c1d4a90b",
        evidence=Evidence(
            method="classifier_confidence",
            measured={"mean_confidence": 0.91},
            packet_indices=[10, 11, 12],
            total_matching=9_012,
        ),
    )


def make_assessment() -> Assessment:
    finding = _finding()
    return Assessment(
        assessment_id=ASSESSMENT_ID,
        capture_id=CAPTURE_ID,
        generated_at=T1,
        engine_version="0.1.0",
        policy_version="1.0",
        model_versions={"ML-1": "cnn-2026.09.03"},
        capture_quality=CaptureQuality(
            packet_count=9_120,
            duration_s=180.0,
            truncated=False,
            has_ike=True,
            ike_complete=True,
            esp_sa_count=2,
            sufficient_for_lattice=True,
            warnings=[],
        ),
        security_associations=[_sa()],
        findings=[finding],
        score=ScoreBreakdown(
            total=92,
            category_penalties={FindingCategory.METADATA_EXPOSURE: 8},
            rating="strong",
        ),
        metadata_exposure=MetadataExposure(
            score=90,
            mean_classifier_confidence=0.91,
            identified_classes=[TrafficClass.VOIP],
            rationale="The classifier identified VoIP with high confidence.",
        ),
        threat_matrix=[
            ThreatMatrixEntry(
                technique_id="T1040",
                technique_name="Network Sniffing",
                tactics=["Credential Access", "Discovery"],
                finding_ids=[finding.id],
                max_severity=Severity.MEDIUM,
            )
        ],
    )


# --------------------------------------------------------------------------
# Done-when 1: the JSON schema renders
# --------------------------------------------------------------------------


def test_assessment_json_schema_renders() -> None:
    schema = Assessment.model_json_schema()
    assert schema["title"] == "Assessment"
    assert "capture_quality" in schema["properties"]
    # It must serialise too -- FastAPI writes it into the OpenAPI document.
    assert json.loads(json.dumps(schema))


def test_generic_attribute_specialisations_appear_in_the_schema() -> None:
    """Each Attribute[T] must render as its own definition, or the generated
    TypeScript collapses them all into one loose type."""
    defs = Assessment.model_json_schema()["$defs"]
    names = set(defs)
    assert any(n.startswith("Attribute_IkeVersion") for n in names), sorted(names)
    assert any(n.startswith("Attribute_int") for n in names), sorted(names)


# --------------------------------------------------------------------------
# Done-when 2: a hand-written fixture round-trips unchanged
# --------------------------------------------------------------------------


def test_assessment_round_trips_unchanged() -> None:
    original = make_assessment()
    dumped = original.model_dump_json()
    restored = Assessment.model_validate_json(dumped)
    assert restored == original
    assert restored.model_dump_json() == dumped


def test_round_trip_preserves_provenance_and_confidence() -> None:
    """The one thing that must never be lost in transit."""
    restored = Assessment.model_validate_json(make_assessment().model_dump_json())
    sa = restored.security_associations[0]
    assert sa.encryption_alg.provenance == "observed"
    assert sa.encryption_alg.confidence is None
    assert sa.operating_mode.provenance == "inferred"
    assert sa.operating_mode.confidence == 0.94
    assert sa.negotiated_lifetime_s.provenance == "unavailable"
    assert sa.negotiated_lifetime_s.note is not None


def test_serialised_timestamps_are_utc_with_a_z() -> None:
    payload = json.loads(make_assessment().model_dump_json())
    assert payload["generated_at"].endswith("Z")
    assert payload["security_associations"][0]["first_seen"] == "2026-09-03T10:00:00Z"


def test_serialisation_is_stable_across_repeated_dumps() -> None:
    """NFR-4 in miniature: nothing in the model is order- or clock-dependent."""
    assessment = make_assessment()
    assert assessment.model_dump_json() == assessment.model_dump_json()
    assert make_assessment().model_dump_json() == make_assessment().model_dump_json()


# --------------------------------------------------------------------------
# Cross-model invariants
# --------------------------------------------------------------------------


def test_finding_referencing_an_unknown_sa_is_rejected() -> None:
    base = make_assessment()
    payload = base.model_dump(mode="json")
    payload["findings"][0]["sa_spi"] = "deadbeef"
    with pytest.raises(ValidationError, match="references unknown SA SPI"):
        Assessment.model_validate(payload)


def test_threat_matrix_referencing_an_unknown_finding_is_rejected() -> None:
    payload = make_assessment().model_dump(mode="json")
    payload["threat_matrix"][0]["finding_ids"] = ["CRYPTO-3DES"]
    with pytest.raises(ValidationError, match="not present in the document"):
        Assessment.model_validate(payload)


def test_duplicate_finding_for_the_same_sa_is_rejected() -> None:
    payload = make_assessment().model_dump(mode="json")
    payload["findings"].append(payload["findings"][0])
    with pytest.raises(ValidationError, match="duplicate finding"):
        Assessment.model_validate(payload)


def test_score_total_must_match_the_penalties() -> None:
    with pytest.raises(ValidationError, match="does not match 100 minus"):
        ScoreBreakdown(
            total=100,
            category_penalties={FindingCategory.KEY_EXCHANGE: 20},
            rating="strong",
        )


def test_category_penalty_above_its_cap_is_rejected() -> None:
    with pytest.raises(ValidationError, match="exceeds its 20-point cap"):
        ScoreBreakdown(
            total=79,
            category_penalties={FindingCategory.KEY_EXCHANGE: 21},
            rating="good",
        )


def test_finding_penalty_above_its_category_cap_is_rejected() -> None:
    with pytest.raises(ValidationError, match="exceeds the 10-point cap"):
        Finding(
            id="META-HIGH-EXPOSURE",
            title="x",
            severity=Severity.HIGH,
            category=FindingCategory.METADATA_EXPOSURE,
            penalty=11,
            description="x",
            remediation="x",
            evidence=Evidence(method="m"),
        )


def test_informational_finding_may_not_cost_points() -> None:
    with pytest.raises(ValidationError, match="must not cost points"):
        Finding(
            id="INFO-NATT",
            title="NAT-T in use",
            severity=Severity.INFORMATIONAL,
            category=FindingCategory.PROTOCOL_VERSION_MODE,
            penalty=1,
            description="x",
            remediation="x",
            evidence=Evidence(method="m"),
        )


def test_ip_version_must_agree_with_the_addresses() -> None:
    payload = make_assessment().model_dump(mode="json")
    payload["security_associations"][0]["ip_version"] = 6
    with pytest.raises(ValidationError, match="disagrees with src"):
        Assessment.model_validate(payload)


def test_last_seen_before_first_seen_is_rejected() -> None:
    payload = make_assessment().model_dump(mode="json")
    payload["security_associations"][0]["last_seen"] = "2026-09-03T09:00:00Z"
    with pytest.raises(ValidationError, match="precedes first_seen"):
        Assessment.model_validate(payload)


def test_ike_complete_without_ike_is_rejected() -> None:
    with pytest.raises(ValidationError, match="ike_complete cannot be true"):
        CaptureQuality(
            packet_count=1,
            duration_s=1.0,
            truncated=False,
            has_ike=False,
            ike_complete=True,
            esp_sa_count=1,
            sufficient_for_lattice=False,
        )


def test_truncated_capture_cannot_support_the_lattice() -> None:
    """LLD section 7.2: a snaplen-limited capture records the snaplen, not the
    real ESP payload length, so the congruence sieve is meaningless."""
    with pytest.raises(ValidationError, match="truncated capture cannot be sufficient"):
        CaptureQuality(
            packet_count=5_000,
            duration_s=180.0,
            truncated=True,
            has_ike=True,
            ike_complete=True,
            esp_sa_count=2,
            sufficient_for_lattice=True,
        )


# --------------------------------------------------------------------------
# Field-level format rules
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad_spi", ["C1D4A90B", "0xc1d4a90b", "c1d4a9", "c1d4a90b1", ""])
def test_spi_must_be_padded_lowercase_hex(bad_spi: str) -> None:
    payload = make_assessment().model_dump(mode="json")
    payload["security_associations"][0]["spi_initiator"] = bad_spi
    with pytest.raises(ValidationError):
        Assessment.model_validate(payload)


@pytest.mark.parametrize("bad_id", ["crypto-3des", "CRYPTO 3DES", "3DES", "CRYPTO_3DES"])
def test_finding_key_format_is_enforced(bad_id: str) -> None:
    payload = make_assessment().model_dump(mode="json")
    payload["findings"][0]["id"] = bad_id
    payload["threat_matrix"] = []
    with pytest.raises(ValidationError):
        Assessment.model_validate(payload)


@pytest.mark.parametrize("bad_technique", ["1040", "T104", "TA0006", "t1040"])
def test_attack_technique_format_is_enforced(bad_technique: str) -> None:
    payload = make_assessment().model_dump(mode="json")
    payload["findings"][0]["attack_techniques"] = [bad_technique]
    with pytest.raises(ValidationError):
        Assessment.model_validate(payload)


def test_non_uuid7_primary_key_is_rejected() -> None:
    """CLAUDE.md: entity keys are UUIDv7. A v4 breaks time ordering silently."""
    payload = make_assessment().model_dump(mode="json")
    payload["assessment_id"] = "6f1b8b1e-1c2e-4a2f-9c1a-2b3c4d5e6f70"  # v4
    with pytest.raises(ValidationError, match="expected a UUIDv7"):
        Assessment.model_validate(payload)


def test_new_id_produces_an_acceptable_key() -> None:
    payload = make_assessment().model_dump(mode="json")
    payload["assessment_id"] = str(new_id())
    assert Assessment.model_validate(payload)


def test_threat_matrix_entry_needs_at_least_one_finding() -> None:
    with pytest.raises(ValidationError):
        ThreatMatrixEntry(
            technique_id="T1040",
            technique_name="Network Sniffing",
            finding_ids=[],
            max_severity=Severity.LOW,
        )
