"""Request and response models for the API boundary (LLD 9).

This is the one place camelCase exists. CLAUDE.md: conversion happens *only*
here, via Pydantic field aliases, so nothing inside the backend ever sees a
camelCase key and nothing in the frontend ever sees a snake_case one.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from analyzer.core.enums import CaptureSource, FindingCategory, RunStage, RunStatus, Severity


class ApiModel(BaseModel):
    """Serialises as camelCase, accepts either spelling on the way in."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class CaptureSummary(ApiModel):
    id: UUID
    filename: str
    sha256: str
    size_bytes: int
    source: CaptureSource
    packet_count: int | None = None
    duration_s: float | None = None
    has_ike: bool | None = None
    truncated: bool | None = None
    created_at: datetime


class CapturePage(ApiModel):
    items: list[CaptureSummary]
    total: int
    limit: int
    offset: int


class RunSummary(ApiModel):
    id: UUID
    capture_id: UUID
    status: RunStatus
    stage: RunStage | None = None
    progress: float
    engine_version: str
    policy_version: str
    error: dict[str, object] | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    assessment_id: UUID | None = None


class FindingSummary(ApiModel):
    """One row of ``GET /assessments/{id}/findings``.

    Served from the ``findings`` table rather than from the document's JSON,
    so severity filtering and penalty ordering are real SQL (LLD section 4.1
    forbids filtering on a JSON column).
    """

    finding_key: str
    severity: Severity
    category: FindingCategory
    penalty: int
    sa_spi: str | None = None
    title: str
    detail: dict[str, object]


class AssessmentSummary(ApiModel):
    id: UUID
    capture_id: UUID
    run_id: UUID
    score_total: int
    rating: str
    exposure_score: int
    created_at: datetime


class AttributeDiff(ApiModel):
    """One parameter, side by side. Backs the step 7.12 comparison view."""

    field: str
    a_value: object | None = None
    a_provenance: str | None = None
    b_value: object | None = None
    b_provenance: str | None = None
    changed: bool


class ComparisonResponse(ApiModel):
    a: AssessmentSummary
    b: AssessmentSummary
    score_delta: int
    findings_only_in_a: list[str]
    findings_only_in_b: list[str]
    findings_in_both: list[str]
    attribute_diffs: list[AttributeDiff]


class HealthResponse(ApiModel):
    status: Literal["ok", "degraded"]
    database: Literal["up", "down"]
    version: str


class AnalyzeAccepted(ApiModel):
    run_id: UUID = Field(description="Poll GET /runs/{id} or stream /runs/{id}/events")
    capture_id: UUID
    status: RunStatus
