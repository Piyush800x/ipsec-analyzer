"""Step 1.4 -- the two demo-tunnel fixtures validate and stay honest.

``assessment_weak.json`` and ``assessment_strong.json`` are the PRD section 16
demo tunnels, written by hand. They are not throwaway test data: the frontend
(Phase 7) and the report templates (Phase 10) build against them for weeks
before the engine produces anything, so a fixture that drifts out of shape takes
two workstreams with it.

Beyond "does it validate", these tests pin the properties those workstreams will
rely on -- the score contrast, the provenance mix, the metadata-exposure
arithmetic, and the three ATT&CK techniques step 5.7 must reproduce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from analyzer.core.enums import (
    EncryptionAlg,
    IkeVersion,
    OperatingMode,
    Provenance,
    Severity,
    TrafficClass,
)
from analyzer.core.schema import Assessment, SecurityAssociation

FIXTURE_DIR = Path(__file__).parent / "fixtures"
WEAK = FIXTURE_DIR / "assessment_weak.json"
STRONG = FIXTURE_DIR / "assessment_strong.json"

CHANCE_LEVEL = 1 / 7


def load(path: Path) -> Assessment:
    return Assessment.model_validate_json(path.read_text(encoding="utf-8"))


@pytest.fixture
def weak() -> Assessment:
    return load(WEAK)


@pytest.fixture
def strong() -> Assessment:
    return load(STRONG)


# --------------------------------------------------------------------------
# The Done-when condition
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", [WEAK, STRONG], ids=["weak", "strong"])
def test_fixture_validates(path: Path) -> None:
    assert load(path).schema_version == "1.0"


@pytest.mark.parametrize("path", [WEAK, STRONG], ids=["weak", "strong"])
def test_fixture_round_trips(path: Path) -> None:
    """The frontend reads these files directly; the API serves the same shape."""
    model = load(path)
    assert Assessment.model_validate_json(model.model_dump_json()) == model


@pytest.mark.parametrize("path", [WEAK, STRONG], ids=["weak", "strong"])
def test_fixture_is_valid_json_and_readable(path: Path) -> None:
    """Hand-maintained files, so guard against a stray trailing comma."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)


# --------------------------------------------------------------------------
# PRD section 16 -- the two tunnels are actually the ones described
# --------------------------------------------------------------------------


def test_weak_tunnel_matches_the_prd_demo_configuration(weak: Assessment) -> None:
    """IKEv1 aggressive, 3DES-CBC, HMAC-SHA1-96, DH 2, no PFS, 24 h, transport, VoIP."""
    sa = weak.security_associations[0]
    assert sa.ike_version.value is IkeVersion.IKEV1
    assert sa.ike_exchange_mode.value == "aggressive"
    assert sa.encryption_alg.value is EncryptionAlg.TRIPLE_DES_CBC
    assert sa.integrity_alg.value == "hmac-sha1-96"
    assert sa.dh_group.value == 2
    assert sa.pfs_enabled.value is False
    assert sa.negotiated_lifetime_s.value == 86_400
    assert sa.operating_mode.value is OperatingMode.TRANSPORT
    assert [p.label for p in sa.inner_traffic] == [TrafficClass.VOIP] * 4


def test_strong_tunnel_matches_the_prd_demo_configuration(strong: Assessment) -> None:
    """IKEv2, AES-256-GCM, DH 19, tunnel mode, the same VoIP call."""
    sa = strong.security_associations[0]
    assert sa.ike_version.value is IkeVersion.IKEV2
    assert sa.encryption_alg.value is EncryptionAlg.AES_GCM_16
    assert sa.encryption_keylen.value == 256
    assert sa.dh_group.value == 19
    assert sa.operating_mode.value is OperatingMode.TUNNEL
    assert [p.label for p in sa.inner_traffic] == [TrafficClass.VOIP] * 4


def test_the_two_tunnels_carry_comparable_traffic(weak: Assessment, strong: Assessment) -> None:
    """PRD section 16 runs the same VoIP call through both, so the contrast in
    score is attributable to configuration rather than to workload."""
    w, s = weak.security_associations[0], strong.security_associations[0]
    assert abs(w.packet_count - s.packet_count) / w.packet_count < 0.01
    assert abs(weak.capture_quality.duration_s - strong.capture_quality.duration_s) < 5.0


def test_the_score_contrast_is_stark(weak: Assessment, strong: Assessment) -> None:
    """Demo step 1 versus step 3. If these ever converge, the demo has no story."""
    assert weak.score.total == 15
    assert weak.score.rating == "critical"
    assert strong.score.total == 90
    assert strong.score.rating == "strong"
    assert strong.score.total - weak.score.total >= 50


def test_strong_tunnel_findings_are_near_empty(strong: Assessment) -> None:
    """PRD section 16 step 3. One finding survives, and deliberately so."""
    assert [f.id for f in strong.findings] == ["META-HIGH-EXPOSURE"]


# --------------------------------------------------------------------------
# LLD correctness traps the fixtures must not fall into
# --------------------------------------------------------------------------


def test_ikev2_reports_no_negotiated_lifetime(strong: Assessment) -> None:
    """LLD section 6.4. RFC 7296 removed lifetime negotiation, so emitting a
    value here is a correctness bug a knowledgeable reviewer will catch at once."""
    attr = strong.security_associations[0].negotiated_lifetime_s
    assert attr.provenance is Provenance.UNAVAILABLE
    assert attr.value is None
    assert "7296" in (attr.note or "")


def test_ikev2_child_sa_crypto_is_inferred_not_observed(strong: Assessment) -> None:
    """LLD section 6.4. IKE_AUTH is encrypted, so the Child SA transform set was
    never on the wire in the clear. Marking it OBSERVED would be a fabrication."""
    sa = strong.security_associations[0]
    for attr in (sa.encryption_alg, sa.encryption_keylen, sa.integrity_alg):
        assert attr.provenance is Provenance.INFERRED
        assert attr.confidence is not None
        assert attr.note, "an inference standing in for an observation must say so"


def test_ikev2_auth_method_is_not_fabricated(strong: Assessment) -> None:
    """FR-3.5 and step 4.7: the IKEv2 AUTH payload is inside encrypted IKE_AUTH."""
    assert strong.security_associations[0].auth_method.provenance is Provenance.UNAVAILABLE


def test_operating_mode_is_never_observed(weak: Assessment, strong: Assessment) -> None:
    """PRD section 7: tunnel versus transport is not carried in any cleartext
    field, so it is inferred even when IKE was fully captured."""
    for assessment in (weak, strong):
        attr = assessment.security_associations[0].operating_mode
        assert attr.provenance is Provenance.INFERRED
        assert attr.confidence is not None


def test_voip_capture_cannot_support_the_length_lattice(
    weak: Assessment, strong: Assessment
) -> None:
    """LLD section 7.2, and the failure mode guaranteed to appear on stage.

    A constant-bitrate stream produces one or two ESP lengths, and a single
    length satisfies almost every congruence. Both demo captures carry a VoIP
    call, so both must have the cipher-family sieve disabled.
    """
    for assessment in (weak, strong):
        assert assessment.capture_quality.sufficient_for_lattice is False
        assert any("length-lattice" in w for w in assessment.capture_quality.warnings), (
            "the reason must be visible to the analyst, not just to the code"
        )


def test_replay_sane_wording_does_not_overclaim(weak: Assessment, strong: Assessment) -> None:
    """LLD section 7.5: the anti-replay window size is a receiver-side setting
    that is never transmitted, and the note must not imply otherwise."""
    for assessment in (weak, strong):
        note = assessment.security_associations[0].replay_sane.note or ""
        assert "window size" in note


def test_esn_is_never_claimed_from_the_wire(weak: Assessment, strong: Assessment) -> None:
    """LLD section 7.5: only the low 32 bits are transmitted either way."""
    for assessment in (weak, strong):
        assert (
            assessment.security_associations[0].esn_negotiated.provenance is Provenance.UNAVAILABLE
        )


# --------------------------------------------------------------------------
# Arithmetic the engine will later have to reproduce
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", [WEAK, STRONG], ids=["weak", "strong"])
def test_metadata_exposure_matches_the_chance_scaled_formula(path: Path) -> None:
    """LLD section 8.4, and step 5.6's Done-when in fixture form."""
    assessment = load(path)
    expected = round(
        100
        * max(
            0.0,
            (assessment.metadata_exposure.mean_classifier_confidence - CHANCE_LEVEL)
            / (1 - CHANCE_LEVEL),
        )
    )
    assert assessment.metadata_exposure.score == expected


@pytest.mark.parametrize("path", [WEAK, STRONG], ids=["weak", "strong"])
def test_mean_confidence_matches_the_predictions_it_summarises(path: Path) -> None:
    assessment = load(path)
    probabilities = [
        p.probability for sa in assessment.security_associations for p in sa.inner_traffic
    ]
    mean = sum(probabilities) / len(probabilities)
    assert assessment.metadata_exposure.mean_classifier_confidence == pytest.approx(mean)


@pytest.mark.parametrize("path", [WEAK, STRONG], ids=["weak", "strong"])
def test_category_penalties_are_the_capped_sums_of_the_findings(path: Path) -> None:
    """LLD section 8.3. The fixtures must be reproducible by the scorer built in
    step 5.5, or step 5.4 will be chasing a target that was never achievable."""
    from analyzer.core.enums import CATEGORY_CAPS

    assessment = load(path)
    raw: dict[str, int] = {}
    for finding in assessment.findings:
        raw[finding.category] = raw.get(finding.category, 0) + finding.penalty

    expected = {
        category: min(CATEGORY_CAPS[category], total)  # type: ignore[index]
        for category, total in raw.items()
    }
    assert dict(assessment.score.category_penalties) == expected


# --------------------------------------------------------------------------
# What downstream steps assert against these files
# --------------------------------------------------------------------------


def test_weak_fixture_covers_the_required_attack_techniques(weak: Assessment) -> None:
    """Step 5.7's Done-when: T1040, T1557 and T1600 all present."""
    techniques = {entry.technique_id for entry in weak.threat_matrix}
    assert {"T1040", "T1557", "T1600"} <= techniques


def test_threat_matrix_severities_match_their_contributors(weak: Assessment) -> None:
    order = list(Severity)
    by_id = {f.id: f for f in weak.findings}
    for entry in weak.threat_matrix:
        worst = min(order.index(by_id[fid].severity) for fid in entry.finding_ids)
        assert entry.max_severity == order[worst], entry.technique_id


def test_every_finding_carries_actionable_remediation(weak: Assessment, strong: Assessment) -> None:
    """FR-5.7: name the parameter and the value. "Use stronger crypto" is not
    remediation, and the network-engineer persona cannot act on it."""
    for assessment in (weak, strong):
        for finding in assessment.findings:
            assert len(finding.remediation) > 120, finding.id
            assert finding.standards, finding.id
            assert finding.evidence.measured, finding.id


def test_fixtures_exercise_all_three_provenance_states(strong: Assessment) -> None:
    """Step 7.4 builds AttributeCell against these. All three renderings need
    real data, and the unavailable one needs its explanatory note."""
    sa = strong.security_associations[0]
    attributes = [
        getattr(sa, name)
        for name, field in SecurityAssociation.model_fields.items()
        if name
        not in {
            "spi_initiator",
            "spi_responder",
            "src",
            "dst",
            "ip_version",
            "protocol",
            "first_seen",
            "last_seen",
            "packet_count",
            "byte_count",
            "inner_traffic",
        }
        and field is not None
    ]
    provenances = {a.provenance for a in attributes}
    assert provenances == set(Provenance)
    for attr in attributes:
        if attr.provenance is Provenance.UNAVAILABLE:
            assert attr.note is not None, "a dash is not an explanation"
            assert len(attr.note) > 40, "a dash is not an explanation"


def test_feature_attributions_are_present_for_the_traffic_view(
    weak: Assessment, strong: Assessment
) -> None:
    """FR-4.10 and step 9.10: a prediction returns its top five contributors.
    Step 7.10 renders them, so at least one window must carry a full set."""
    for assessment in (weak, strong):
        predictions = assessment.security_associations[0].inner_traffic
        assert any(len(p.top_features) >= 5 for p in predictions)
