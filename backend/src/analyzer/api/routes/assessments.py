"""Assessment retrieval, filterable findings, and comparison (LLD 9). Step 6.7.

The findings endpoint reads the ``findings`` table, never the document's JSON.
LLD section 4.1 forbids filtering on a JSON column and the relational rows
exist for exactly this query; a JSON path expression here would also be the
one thing that behaves differently on SQLite and PostgreSQL.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

import sqlalchemy as sa
from fastapi import APIRouter, Query

from analyzer.api.deps import SessionDep
from analyzer.api.errors import NotFoundError, ValidationError
from analyzer.api.schemas import (
    AssessmentSummary,
    AttributeDiff,
    ComparisonResponse,
    FindingSummary,
)
from analyzer.core.enums import Severity
from analyzer.db import models

router = APIRouter(prefix="/assessments", tags=["assessments"])

COMPARED_FIELDS = (
    "ike_version",
    "ike_exchange_mode",
    "encryption_alg",
    "encryption_keylen",
    "integrity_alg",
    "prf_alg",
    "dh_group",
    "operating_mode",
    "pfs_enabled",
    "auth_method",
    "negotiated_lifetime_s",
    "esn_negotiated",
    "replay_sane",
    "nat_traversal",
    "downgrade_available",
)
"""Every provenance-carrying parameter, in contract order. The comparison view
(step 7.12) renders these as its diff rows."""


async def _get(session: SessionDep, assessment_id: UUID) -> models.Assessment:
    row = await session.get(models.Assessment, assessment_id)
    if row is None:
        raise NotFoundError("assessment", assessment_id)
    return row


def _summary(row: models.Assessment) -> AssessmentSummary:
    return AssessmentSummary(
        id=row.id,
        capture_id=row.capture_id,
        run_id=row.run_id,
        score_total=row.score_total,
        rating=row.rating,
        exposure_score=row.exposure_score,
        created_at=row.created_at,
    )


# Registered before /{assessment_id} so "compare" is not parsed as a UUID.
@router.get("/compare", response_model=ComparisonResponse)
async def compare_assessments(
    session: SessionDep,
    a: Annotated[UUID, Query(description="Baseline assessment id")],
    b: Annotated[UUID, Query(description="Assessment to compare against it")],
) -> ComparisonResponse:
    if a == b:
        raise ValidationError("An assessment cannot be compared with itself")

    row_a, row_b = await _get(session, a), await _get(session, b)
    doc_a, doc_b = row_a.document, row_b.document

    findings_a = {f["id"] for f in doc_a.get("findings", [])}
    findings_b = {f["id"] for f in doc_b.get("findings", [])}

    sas_a = doc_a.get("security_associations") or [{}]
    sas_b = doc_b.get("security_associations") or [{}]
    first_a, first_b = sas_a[0], sas_b[0]

    diffs = []
    for field in COMPARED_FIELDS:
        left = first_a.get(field) or {}
        right = first_b.get(field) or {}
        diffs.append(
            AttributeDiff(
                field=field,
                a_value=left.get("value"),
                a_provenance=left.get("provenance"),
                b_value=right.get("value"),
                b_provenance=right.get("provenance"),
                changed=(
                    left.get("value") != right.get("value")
                    or left.get("provenance") != right.get("provenance")
                ),
            )
        )

    return ComparisonResponse(
        a=_summary(row_a),
        b=_summary(row_b),
        score_delta=row_b.score_total - row_a.score_total,
        findings_only_in_a=sorted(findings_a - findings_b),
        findings_only_in_b=sorted(findings_b - findings_a),
        findings_in_both=sorted(findings_a & findings_b),
        attribute_diffs=diffs,
    )


@router.get("/{assessment_id}")
async def get_assessment(session: SessionDep, assessment_id: UUID) -> dict[str, Any]:
    """The full ``Assessment`` document, served as stored.

    Returned as the raw stored mapping rather than re-serialised through the
    Pydantic model: the document is the immutable artefact (LLD section 4.3),
    and round-tripping it would let a later contract change silently rewrite
    an assessment that was already issued.
    """
    row = await _get(session, assessment_id)
    return row.document


@router.get("/{assessment_id}/findings", response_model=list[FindingSummary])
async def list_findings(
    session: SessionDep,
    assessment_id: UUID,
    severity: Annotated[list[Severity] | None, Query()] = None,
    sort: Annotated[Literal["penalty", "severity"], Query()] = "penalty",
    order: Annotated[Literal["asc", "desc"], Query()] = "desc",
) -> list[FindingSummary]:
    await _get(session, assessment_id)

    query = sa.select(models.Finding).where(models.Finding.assessment_id == assessment_id)
    if severity:
        query = query.where(models.Finding.severity.in_(severity))

    column = models.Finding.penalty if sort == "penalty" else models.Finding.severity
    query = query.order_by(column.desc() if order == "desc" else column.asc())

    rows = (await session.scalars(query)).all()
    return [
        FindingSummary(
            finding_key=row.finding_key,
            severity=row.severity,
            category=row.category,
            penalty=row.penalty,
            sa_spi=row.sa_spi,
            title=str(row.detail.get("title", row.finding_key)),
            detail=row.detail,
        )
        for row in rows
    ]
