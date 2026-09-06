"""Steps 5.4-5.9: rule evaluation, scoring, exposure, threat matrix, determinism.

The engine is a pure function of its inputs (LLD section 8.2), so these run
against the fixture assessments from step 1.4 with no PCAP anywhere in sight.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from analyzer.assess.engine import AssessmentEngine, capped_evidence
from analyzer.assess.policy import load_policy
from analyzer.assess.scoring import CHANCE_LEVEL, exposure, rating_for, score
from analyzer.core.enums import CATEGORY_CAPS, FindingCategory, Severity, TrafficClass
from analyzer.core.ids import new_id
from analyzer.core.schema import (
    MAX_PACKET_INDICES,
    Assessment,
    Evidence,
    Finding,
    SecurityAssociation,
    TrafficPrediction,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BASELINE = Path(__file__).resolve().parents[1] / "src/analyzer/assess/policies/baseline.yaml"

T0 = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
FIXED_ASSESSMENT_ID = UUID("01930000-0000-7000-8000-000000000001")
FIXED_CAPTURE_ID = UUID("01930000-0000-7000-8000-000000000002")


def _fixture(name: str) -> Assessment:
    return Assessment.model_validate_json((FIXTURES / f"assessment_{name}.json").read_text())


def _engine() -> AssessmentEngine:
    return AssessmentEngine(load_policy(BASELINE))


def _evaluate(fixture_name: str) -> Assessment:
    source = _fixture(fixture_name)
    return _engine().evaluate(
        source.security_associations,
        source.capture_quality,
        assessment_id=FIXED_ASSESSMENT_ID,
        capture_id=FIXED_CAPTURE_ID,
        generated_at=T0,
        engine_version="0.1.0",
    )


def _finding(
    finding_id: str = "CRYPTO-3DES",
    *,
    category: FindingCategory = FindingCategory.CRYPTOGRAPHIC_STRENGTH,
    penalty: int = 30,
    severity: Severity = Severity.CRITICAL,
) -> Finding:
    return Finding(
        id=finding_id,
        title="t",
        severity=severity,
        category=category,
        penalty=penalty,
        description="d",
        remediation="r",
        evidence=Evidence(method="test"),
    )


# --- step 5.4: rule evaluation --------------------------------------------


def test_weak_fixture_produces_exactly_its_expected_findings() -> None:
    """Step 5.4 Done-when, asserted exactly."""
    expected = [f.id for f in _fixture("weak").findings]
    produced = [f.id for f in _evaluate("weak").findings]
    assert sorted(produced) == sorted(expected)


def test_strong_fixture_produces_exactly_its_expected_findings() -> None:
    expected = [f.id for f in _fixture("strong").findings]
    produced = [f.id for f in _evaluate("strong").findings]
    assert sorted(produced) == sorted(expected)


def test_weak_fixture_reproduces_its_score_and_rating() -> None:
    source = _fixture("weak")
    result = _evaluate("weak")
    assert result.score.total == source.score.total
    assert result.score.rating == source.score.rating
    assert result.score.category_penalties == source.score.category_penalties


def test_strong_fixture_reproduces_its_score_and_rating() -> None:
    source = _fixture("strong")
    result = _evaluate("strong")
    assert result.score.total == source.score.total
    assert result.score.rating == source.score.rating


def test_findings_carry_severity_category_and_penalty_from_the_policy() -> None:
    source = {f.id: f for f in _fixture("weak").findings}
    for finding in _evaluate("weak").findings:
        expected = source[finding.id]
        assert finding.severity is expected.severity, finding.id
        assert finding.category is expected.category, finding.id
        assert finding.penalty == expected.penalty, finding.id


def test_every_finding_carries_evidence_and_an_sa_reference() -> None:
    """NFR-7: a finding without evidence is an opinion."""
    for finding in _evaluate("weak").findings:
        assert finding.evidence.method
        assert finding.sa_spi is not None


def test_unavailable_attribute_never_fires_a_rule() -> None:
    """The strong fixture's pfs_enabled is UNAVAILABLE, so KEX-PFS-DISABLED
    must not fire -- reporting a finding against a value the capture never
    showed is exactly the fabrication provenance exists to prevent."""
    assert "KEX-PFS-DISABLED" not in {f.id for f in _evaluate("strong").findings}


def test_low_confidence_inference_does_not_fire_a_guarded_rule() -> None:
    source = _fixture("weak")
    sa = source.security_associations[0]
    weakened = sa.model_copy(
        update={
            "pfs_enabled": sa.pfs_enabled.model_copy(
                update={"provenance": "inferred", "confidence": 0.35, "value": False}
            )
        }
    )
    result = _engine().evaluate(
        [weakened],
        source.capture_quality,
        assessment_id=FIXED_ASSESSMENT_ID,
        capture_id=FIXED_CAPTURE_ID,
        generated_at=T0,
        engine_version="0.1.0",
    )
    assert "KEX-PFS-DISABLED" not in {f.id for f in result.findings}


# --- step 5.5: scoring ------------------------------------------------------


def test_score_is_always_in_range() -> None:
    for findings in ([], [_finding()], [_finding(f"RULE-{i}", penalty=30) for i in range(20)]):
        assert 0 <= score(findings).total <= 100


def test_adding_a_finding_never_raises_the_score() -> None:
    accumulated: list[Finding] = []
    previous = score(accumulated).total
    for index, category in enumerate(FindingCategory):
        accumulated.append(
            _finding(f"RULE-{index}", category=category, penalty=CATEGORY_CAPS[category])
        )
        current = score(accumulated).total
        assert current <= previous
        previous = current


def test_category_caps_are_never_exceeded() -> None:
    findings = [
        _finding(f"CRYPTO-{i}", category=FindingCategory.CRYPTOGRAPHIC_STRENGTH, penalty=30)
        for i in range(5)
    ]
    breakdown = score(findings)
    assert breakdown.category_penalties[FindingCategory.CRYPTOGRAPHIC_STRENGTH] == 30


def test_score_floors_at_zero() -> None:
    findings = [
        _finding(f"RULE-{index}", category=category, penalty=CATEGORY_CAPS[category])
        for index, category in enumerate(FindingCategory)
    ]
    assert score(findings).total == 0


def test_no_findings_scores_one_hundred() -> None:
    breakdown = score([])
    assert breakdown.total == 100
    assert breakdown.rating == "strong"


@pytest.mark.parametrize(
    ("total", "expected"),
    [
        (100, "strong"),
        (90, "strong"),
        (80, "strong"),
        (79, "good"),
        (60, "good"),
        (59, "fair"),
        (40, "fair"),
        (39, "poor"),
        (20, "poor"),
        (19, "critical"),
        (0, "critical"),
    ],
)
def test_rating_bands(total: int, expected: str) -> None:
    assert rating_for(total) == expected


# --- step 5.6: metadata exposure -------------------------------------------


def _sa_with_predictions(
    base: SecurityAssociation, probabilities: list[float]
) -> SecurityAssociation:
    return base.model_copy(
        update={
            "inner_traffic": [
                TrafficPrediction(
                    label=TrafficClass.VOIP, probability=p, window_start=T0, window_end=T0
                )
                for p in probabilities
            ]
        }
    )


def test_exposure_at_chance_level_is_zero() -> None:
    """Step 5.6 Done-when: mean confidence at 1/7 yields exposure 0."""
    base = _fixture("weak").security_associations[0]
    result = exposure([_sa_with_predictions(base, [CHANCE_LEVEL, CHANCE_LEVEL])])
    assert result.score == 0


def test_exposure_at_certainty_is_one_hundred() -> None:
    """Step 5.6 Done-when: mean confidence at 1.0 yields exposure 100."""
    base = _fixture("weak").security_associations[0]
    result = exposure([_sa_with_predictions(base, [1.0, 1.0])])
    assert result.score == 100


def test_exposure_below_chance_level_floors_at_zero() -> None:
    base = _fixture("weak").security_associations[0]
    assert exposure([_sa_with_predictions(base, [0.05])]).score == 0


def test_exposure_with_no_predictions_is_zero_and_says_why() -> None:
    base = _fixture("weak").security_associations[0]
    result = exposure([base.model_copy(update={"inner_traffic": []})])
    assert result.score == 0
    assert "no inner traffic" in result.rationale.lower()


def test_exposure_reproduces_the_fixture_scores() -> None:
    for name in ("weak", "strong"):
        source = _fixture(name)
        assert exposure(source.security_associations).score == source.metadata_exposure.score


# --- step 5.7: threat matrix -----------------------------------------------


def test_weak_fixture_threat_matrix_covers_the_expected_techniques() -> None:
    """Step 5.7 Done-when."""
    techniques = {entry.technique_id for entry in _evaluate("weak").threat_matrix}
    assert {"T1040", "T1557", "T1600"} <= techniques


def test_threat_matrix_entries_name_their_technique_and_cite_findings() -> None:
    for entry in _evaluate("weak").threat_matrix:
        assert entry.technique_name
        assert entry.finding_ids


def test_threat_matrix_groups_multiple_findings_under_one_technique() -> None:
    entry = next(e for e in _evaluate("weak").threat_matrix if e.technique_id == "T1600")
    assert set(entry.finding_ids) == {"CRYPTO-3DES", "KEX-WEAK-DH"}


# --- step 5.8: evidence caps ------------------------------------------------


def test_evidence_caps_packet_indices_and_records_the_total() -> None:
    evidence = capped_evidence("test", packet_indices=list(range(100_000)))
    assert len(evidence.packet_indices) == MAX_PACKET_INDICES
    assert evidence.total_matching == 100_000


def test_a_finding_matching_a_hundred_thousand_packets_stays_small() -> None:
    """Step 5.8 Done-when: under 2 KB serialised."""
    finding = Finding(
        id="REPLAY-SEQ-ANOMALY",
        title="t",
        severity=Severity.HIGH,
        category=FindingCategory.REPLAY_INTEGRITY,
        penalty=10,
        description="d",
        remediation="r",
        evidence=capped_evidence("test", packet_indices=list(range(100_000))),
    )
    assert len(finding.model_dump_json().encode()) < 2048


def test_evidence_below_the_cap_has_no_total_matching() -> None:
    evidence = capped_evidence("test", packet_indices=[1, 2, 3])
    assert evidence.total_matching is None


# --- step 5.9: determinism (NFR-4) -----------------------------------------


def test_evaluation_is_byte_identical_across_runs() -> None:
    """Step 5.9 Done-when, and NFR-4. Identifiers and timestamps are injected
    by the caller precisely so this comparison is possible."""
    first = _evaluate("weak").model_dump_json()
    second = _evaluate("weak").model_dump_json()
    assert first == second


def test_evaluation_differs_only_by_injected_identity() -> None:
    source = _fixture("weak")
    engine = _engine()
    run_a = engine.evaluate(
        source.security_associations,
        source.capture_quality,
        assessment_id=FIXED_ASSESSMENT_ID,
        capture_id=FIXED_CAPTURE_ID,
        generated_at=T0,
        engine_version="0.1.0",
    )
    run_b = engine.evaluate(
        source.security_associations,
        source.capture_quality,
        assessment_id=new_id(),
        capture_id=new_id(),
        generated_at=datetime(2027, 1, 1, tzinfo=UTC),
        engine_version="0.1.0",
    )
    stripped_a = json.loads(run_a.model_dump_json())
    stripped_b = json.loads(run_b.model_dump_json())
    for document in (stripped_a, stripped_b):
        for key in ("assessment_id", "capture_id", "generated_at"):
            document.pop(key)
    assert stripped_a == stripped_b


def test_engine_reads_no_clock_inside_evaluate() -> None:
    """The generated_at that comes out is exactly the one passed in."""
    assert _evaluate("weak").generated_at == T0
