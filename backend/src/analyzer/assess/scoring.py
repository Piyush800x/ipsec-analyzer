"""Category-capped scoring (LLD 8.3) and metadata exposure (LLD 8.4).

Steps 5.5 and 5.6. Both are pure functions of their inputs -- no clock, no
randomness, nothing read from disk -- which is what makes NFR-4's
byte-identical output achievable and lets step 5.9 assert it.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Final, Literal

from analyzer.core.enums import CATEGORY_CAPS, FindingCategory, TrafficClass
from analyzer.core.schema import Finding, MetadataExposure, ScoreBreakdown, SecurityAssociation

Rating = Literal["critical", "poor", "fair", "good", "strong"]

RATING_BANDS: Final[tuple[tuple[int, Rating], ...]] = (
    (80, "strong"),
    (60, "good"),
    (40, "fair"),
    (20, "poor"),
    (0, "critical"),
)
"""Lower bound of each band, highest first.

Neither the PRD nor the LLD defines these thresholds -- ``core/schema.py`` says
so explicitly and leaves the decision to this step. Even 20-point bands are the
defensible default: they put the two PRD section 16 demo tunnels (15 and 90) at
opposite ends without the bands having been drawn to flatter them.
"""

CHANCE_LEVEL: Final = 1.0 / len(TrafficClass)
"""1/7. LLD section 8.4 scales exposure from chance rather than from zero: a
classifier at chance has learned nothing about the tunnel, and a deployment
that leaks nothing should score 0 exposure, not 14."""


def rating_for(total: int) -> Rating:
    for lower_bound, rating in RATING_BANDS:
        if total >= lower_bound:
            return rating
    return "critical"  # pragma: no cover - the 0 band already covers this


def score(findings: list[Finding]) -> ScoreBreakdown:
    """Start at 100, subtract capped per-category penalties, floor at zero.

    Sorting by descending penalty within a category means the cap is consumed
    by the most severe finding first, so the attribution that gets reported is
    the meaningful one (LLD section 8.3).
    """
    per_category: dict[FindingCategory, int] = defaultdict(int)
    for finding in sorted(findings, key=lambda f: (f.category.value, -f.penalty, f.id)):
        cap = CATEGORY_CAPS[finding.category]
        per_category[finding.category] = min(cap, per_category[finding.category] + finding.penalty)

    total = max(0, 100 - sum(per_category.values()))
    return ScoreBreakdown(
        total=total,
        category_penalties=dict(sorted(per_category.items(), key=lambda kv: kv[0].value)),
        rating=rating_for(total),
    )


def exposure(sas: list[SecurityAssociation]) -> MetadataExposure:
    """How much a passive observer learns about the inner traffic. LLD 8.4.

    The classifier's own confidence *is* the measurement (PRD section 4.1): a
    well-padded tunnel leaves the classifier uncertain, and that uncertainty is
    a good security outcome rather than a model failure.
    """
    probabilities = [prediction.probability for sa in sas for prediction in sa.inner_traffic]
    if not probabilities:
        return MetadataExposure(
            score=0,
            mean_classifier_confidence=0.0,
            identified_classes=[],
            rationale=(
                "No inner traffic was classified for this capture, so there is no "
                "measurement of what a passive observer could learn. This is an "
                "absence of evidence, not evidence that the tunnel leaks nothing."
            ),
        )

    mean_confidence = statistics.fmean(probabilities)
    scaled = (mean_confidence - CHANCE_LEVEL) / (1.0 - CHANCE_LEVEL)
    exposure_score = round(100 * max(0.0, scaled))

    labels = _dominant_labels(sas)
    return MetadataExposure(
        score=exposure_score,
        mean_classifier_confidence=mean_confidence,
        identified_classes=labels,
        rationale=_rationale(exposure_score, mean_confidence, labels, len(probabilities)),
    )


def _dominant_labels(sas: list[SecurityAssociation]) -> list[TrafficClass]:
    """Distinct predicted labels, in first-seen order.

    Order is deliberate rather than sorted: NFR-4 needs it stable, and the
    order predictions arrive in is already deterministic.
    """
    labels: list[TrafficClass] = []
    for sa in sas:
        for prediction in sa.inner_traffic:
            if prediction.label not in labels:
                labels.append(prediction.label)
    return labels


def _rationale(
    exposure_score: int, mean_confidence: float, labels: list[TrafficClass], windows: int
) -> str:
    named = ", ".join(label.value for label in labels) or "no dominant class"
    if exposure_score == 0:
        return (
            f"Across {windows} scored windows the classifier averaged "
            f"{mean_confidence:.2f} confidence, at or below the {CHANCE_LEVEL:.3f} "
            "chance level for seven classes. It learned nothing about the inner "
            "traffic, which is the outcome a well-padded tunnel should produce."
        )
    return (
        f"The inner traffic was identified as {named} with a mean confidence of "
        f"{mean_confidence:.2f} across {windows} scored windows. Scaled from the "
        f"1-in-7 chance level, that leaves an exposure of {exposure_score} out of "
        "100: the tunnel reveals what it carries without any of its encryption "
        "being broken."
    )
