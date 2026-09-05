"""AssessmentEngine (LLD 8.2). Steps 5.4, 5.7, 5.8, 5.9.

A pure function of its inputs. No I/O, no randomness, no wall-clock read
happens inside ``evaluate``: identifiers and timestamps are passed in by the
caller precisely so that NFR-4 -- identical input produces byte-identical
assessment JSON -- is a property the determinism test can actually assert.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Final
from uuid import UUID

from analyzer.assess.policy import DERIVED_ATTRIBUTES, Condition, Policy, Rule
from analyzer.assess.scoring import exposure, score
from analyzer.core.enums import Provenance, Severity
from analyzer.core.schema import (
    MAX_PACKET_INDICES,
    Assessment,
    Attribute,
    CaptureQuality,
    Evidence,
    Finding,
    SecurityAssociation,
    ThreatMatrixEntry,
)

ATTACK_TECHNIQUES: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    "T1040": ("Network Sniffing", ("Credential Access", "Discovery")),
    "T1110": ("Brute Force", ("Credential Access",)),
    "T1557": ("Adversary-in-the-Middle", ("Collection", "Credential Access")),
    "T1600": ("Weaken Encryption", ("Defense Evasion",)),
}
"""PRD section 10.3's working mapping. A technique a rule cites but that is not
listed here still appears in the matrix, with its ID as its name -- an unnamed
technique is better than a silently dropped one."""

_SEVERITY_ORDER: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}
"""Most severe first. Used both to order findings deterministically and to pick
a threat-matrix entry's ``max_severity``."""

NO_REKEY_MIN_OBSERVATION_S: Final = 7200.0
"""Below this, "no rekey was observed" says more about the capture than the
deployment: a three-minute capture of an hourly-rekeying tunnel will never see
one. Used by the ``sa_duration_s`` guard on ``KEYMGMT-NO-REKEY-OBSERVED``."""


def capped_evidence(
    method: str,
    *,
    packet_indices: list[int] | None = None,
    measured: dict[str, Any] | None = None,
) -> Evidence:
    """Build an ``Evidence`` with its packet indices truncated. Step 5.8.

    LLD section 8.4 caps the list at 20 and requires ``total_matching``
    alongside, because "20 packets" and "20 of 412,000 packets" are very
    different findings -- and because an uncapped list serialises a million
    integers into a JSON column.
    """
    indices = packet_indices or []
    truncated = indices[:MAX_PACKET_INDICES]
    return Evidence(
        method=method,
        packet_indices=truncated,
        measured=measured or {},
        total_matching=len(indices) if len(indices) > len(truncated) else None,
    )


class AssessmentEngine:
    """Evaluates a policy against parsed SAs. LLD section 8.2."""

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def evaluate(
        self,
        sas: list[SecurityAssociation],
        quality: CaptureQuality,
        *,
        assessment_id: UUID,
        capture_id: UUID,
        generated_at: datetime,
        engine_version: str,
        model_versions: dict[str, str] | None = None,
    ) -> Assessment:
        findings = self._dedupe([f for sa in sas for f in self._eval_sa(sa)])
        return Assessment(
            assessment_id=assessment_id,
            capture_id=capture_id,
            generated_at=generated_at,
            engine_version=engine_version,
            policy_version=self._policy.version,
            model_versions=model_versions or {},
            capture_quality=quality,
            security_associations=sas,
            findings=findings,
            score=score(findings),
            metadata_exposure=exposure(sas),
            threat_matrix=self._threat_matrix(findings),
        )

    # --- step 5.4: rule evaluation ------------------------------------------

    def _eval_sa(self, sa: SecurityAssociation) -> list[Finding]:
        derived = _derived_attributes(sa)
        findings = []
        for rule in self._policy.rules:
            if _matches(rule.when, sa, derived):
                findings.append(self._finding_for(rule, sa, derived))
        return findings

    def _finding_for(
        self, rule: Rule, sa: SecurityAssociation, derived: dict[str, float | bool]
    ) -> Finding:
        measured: dict[str, Any] = {}
        for name in sorted(rule.when.referenced_attributes()):
            value = _attribute_value(sa, derived, name)
            if value is not None:
                measured[name] = value if isinstance(value, int | float | str) else str(value)
        return Finding(
            id=rule.id,
            title=rule.title,
            severity=rule.severity,
            category=rule.category,
            penalty=rule.penalty,
            description=rule.description,
            remediation=rule.remediation,
            standards=list(rule.standards),
            attack_techniques=list(rule.attack),
            sa_spi=sa.spi_initiator,
            evidence=capped_evidence(f"policy_rule:{rule.id}", measured=measured),
        )

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        """One finding per (rule, SA). Ordered by severity, then penalty, then
        id, so two runs over the same input list findings identically."""
        unique: dict[tuple[str, str | None], Finding] = {}
        for finding in findings:
            unique.setdefault((finding.id, finding.sa_spi), finding)
        return sorted(
            unique.values(),
            key=lambda f: (_SEVERITY_ORDER[f.severity], -f.penalty, f.id, f.sa_spi or ""),
        )

    # --- step 5.7: threat matrix --------------------------------------------

    @staticmethod
    def _threat_matrix(findings: list[Finding]) -> list[ThreatMatrixEntry]:
        by_technique: dict[str, list[Finding]] = {}
        for finding in findings:
            for technique in finding.attack_techniques:
                contributors = by_technique.setdefault(technique, [])
                if all(f.id != finding.id for f in contributors):
                    contributors.append(finding)

        entries = []
        for technique_id in sorted(by_technique):
            name, tactics = ATTACK_TECHNIQUES.get(technique_id, (technique_id, ()))
            contributors = by_technique[technique_id]
            entries.append(
                ThreatMatrixEntry(
                    technique_id=technique_id,
                    technique_name=name,
                    tactics=list(tactics),
                    finding_ids=[f.id for f in contributors],
                    max_severity=min(
                        contributors, key=lambda f: _SEVERITY_ORDER[f.severity]
                    ).severity,
                )
            )
        return entries


# ===========================================================================
# Condition evaluation
# ===========================================================================


def _derived_attributes(sa: SecurityAssociation) -> dict[str, float | bool]:
    """Per-SA values the policy language needs that the contract does not carry.

    See ``policy.DERIVED_ATTRIBUTES`` for why these three exist.
    """
    probabilities = [prediction.probability for prediction in sa.inner_traffic]
    mean_confidence = sum(probabilities) / len(probabilities) if probabilities else 0.0
    return {
        "metadata_exposure_confidence": mean_confidence,
        "rekey_observed": sa.observed_rekey_s.provenance is not Provenance.UNAVAILABLE,
        "sa_duration_s": (sa.last_seen - sa.first_seen).total_seconds(),
    }


def _attribute(sa: SecurityAssociation, name: str) -> Attribute[Any] | None:
    candidate = getattr(sa, name, None)
    return candidate if isinstance(candidate, Attribute) else None


def _attribute_value(sa: SecurityAssociation, derived: dict[str, float | bool], name: str) -> Any:
    if name in DERIVED_ATTRIBUTES:
        return derived.get(name)
    attribute = _attribute(sa, name)
    if attribute is None or attribute.provenance is Provenance.UNAVAILABLE:
        return None
    value = attribute.value
    # StrEnum members compare equal to their string value, but a policy file
    # writes the wire value ("3des-cbc"), so unwrap to that rather than relying
    # on enum-to-literal comparison holding for every enum in the contract.
    return value.value if isinstance(value, Enum) else value


def _confidence_ok(
    sa: SecurityAssociation, derived: dict[str, float | bool], name: str, threshold: float
) -> bool:
    """``confidence_gte`` semantics.

    An ``OBSERVED`` attribute passes any threshold: it is a parsed fact and
    carries no confidence by construction (``Attribute``'s validator forbids
    one). An ``UNAVAILABLE`` one never passes. An ``INFERRED`` one passes only
    if its calibrated confidence clears the bar -- which is the whole point of
    the guard.
    """
    if name in DERIVED_ATTRIBUTES:
        return derived.get(name) is not None
    attribute = _attribute(sa, name)
    if attribute is None or attribute.provenance is Provenance.UNAVAILABLE:
        return False
    if attribute.provenance is Provenance.OBSERVED:
        return True
    return attribute.confidence is not None and attribute.confidence >= threshold


def _matches(
    condition: Condition, sa: SecurityAssociation, derived: dict[str, float | bool]
) -> bool:
    if condition.all_of is not None:
        return all(_matches(branch, sa, derived) for branch in condition.all_of)
    if condition.any_of is not None:
        return any(_matches(branch, sa, derived) for branch in condition.any_of)

    name = condition.attribute
    if name is None:
        return False  # pragma: no cover - the policy validator rejects this shape

    if condition.operator == "confidence_gte":
        return _confidence_ok(sa, derived, name, float(condition.value or 0.0))

    value = _attribute_value(sa, derived, name)
    if value is None:
        # An unavailable attribute matches nothing. Reporting a finding against
        # a value the capture never showed is exactly the fabrication the
        # provenance system exists to prevent.
        return False

    if condition.operator == "eq":
        return bool(value == condition.value)
    if condition.operator == "in":
        return value in (condition.values or [])
    if condition.operator == "lt":
        return _numeric(value) is not None and _numeric(value) < float(condition.value or 0)  # type: ignore[operator] # guarded on the line above
    if condition.operator == "gt":
        return _numeric(value) is not None and _numeric(value) > float(condition.value or 0)  # type: ignore[operator] # guarded on the line above
    return False  # pragma: no cover - the policy validator rejects other operators


def _numeric(value: Any) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None
