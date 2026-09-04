"""SQLAlchemy models. LLD section 4.3.

One model set serves PostgreSQL (Neon, default) and SQLite (offline, air-gapped,
CI). The portability rules from LLD section 4.1 are load-bearing rather than
stylistic, and each is applied here:

- ``sa.JSON``, never ``JSONB``. Postgres gets ``JSONB`` from a dialect-guarded
  Alembic step (step 1.6); the models stay backend-neutral so SQLite never meets
  a type it cannot create.
- ``sa.Uuid`` for keys -- native ``uuid`` on Postgres, ``CHAR(32)`` on SQLite.
- ``UtcDateTime`` for timestamps, so both backends return aware UTC values.
- No array columns, no ``ILIKE``, no JSON path filtering, no window functions in
  the hot path. Application queries live elsewhere, but the schema is what makes
  those rules keepable.

The duplication between ``assessments.document`` and the ``findings`` /
``security_associations`` tables is deliberate (LLD section 4.3). The JSON
document is the immutable artefact that reports and exports are rendered from;
the relational rows exist so the dashboard can filter, sort and aggregate
without a single JSON path query. The write path populates both in one
transaction.

PCAP bytes never enter the database. ``captures.storage_path`` points at the
filesystem.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from analyzer.core.enums import (
    CaptureSource,
    FindingCategory,
    RunStage,
    RunStatus,
    Severity,
)
from analyzer.core.ids import new_id
from analyzer.db.types import UtcDateTime

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
"""Deterministic names for every constraint and index.

Without this, SQLAlchemy leaves constraints unnamed and the two backends invent
different names. Alembic then cannot write a downgrade that drops them, because
there is nothing stable to name -- which is how a project ends up with
migrations that only run forwards. All snake_case, per CLAUDE.md.
"""


def _enum(enum_cls: type, /, *, length: int = 32) -> sa.Enum:
    """A portable enum column.

    ``native_enum=False`` keeps this a ``VARCHAR`` on both backends rather than a
    Postgres ``ENUM`` type, which SQLite has no equivalent for and which needs a
    migration to extend.

    ``values_callable`` is not optional. Without it SQLAlchemy stores the Python
    member *names* -- ``TRIPLE_DES_CBC`` -- rather than the wire values that
    ``core/enums.py`` defines and the API serialises. Every consumer would then
    see a different spelling from the database.

    No CHECK constraint: ``core/schema.py`` is the validation boundary, and a
    cross-dialect CHECK adds migration churn (SQLite needs a table rebuild to
    alter one) for a rule that is already enforced before the write.
    """
    return sa.Enum(
        enum_cls,
        native_enum=False,
        create_constraint=False,
        length=length,
        values_callable=lambda e: [member.value for member in e],
    )


class Base(DeclarativeBase):
    """Declarative base carrying the shared metadata and naming convention."""

    metadata = sa.MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map = {  # noqa: RUF012 -- SQLAlchemy reads this as a plain dict
        uuid.UUID: sa.Uuid(),
        dict[str, Any]: sa.JSON(),
    }


class Capture(Base):
    """An uploaded, live-captured or testbed-generated PCAP. LLD section 4.3."""

    __tablename__ = "captures"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    filename: Mapped[str] = mapped_column(sa.Text, nullable=False)

    sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    """Content hash, and the deduplication key for uploads (LLD section 9).

    ``String(64)`` rather than the LLD's ``CHAR(64)``: on Postgres ``CHAR``
    blank-pads to width and compares padded, which would make an otherwise
    identical hash miss the unique index depending on how it was written.
    """

    size_bytes: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    source: Mapped[CaptureSource] = mapped_column(_enum(CaptureSource), nullable=False)

    storage_path: Mapped[str] = mapped_column(sa.Text, nullable=False)
    """Filesystem location. PCAPs never enter the database -- a 2 GB upload cap
    (LLD section 9) makes that obvious, but it also keeps the database small
    enough to branch cheaply on Neon."""

    packet_count: Mapped[int | None] = mapped_column(sa.Integer)
    duration_s: Mapped[float | None] = mapped_column(sa.Float)
    has_ike: Mapped[bool | None] = mapped_column(sa.Boolean)
    truncated: Mapped[bool | None] = mapped_column(sa.Boolean)

    ground_truth: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON)
    """Testbed labels (FR-1.11). NULL for analyst uploads, which is the
    distinction between a training row and a real one."""

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)

    runs: Mapped[list[AnalysisRun]] = relationship(
        back_populates="capture",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (sa.Index("ix_captures_sha256", "sha256", unique=True),)


class AnalysisRun(Base):
    """One execution of the pipeline over one capture. LLD section 4.3."""

    __tablename__ = "analysis_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    capture_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("captures.id", ondelete="CASCADE"),
        nullable=False,
    )

    status: Mapped[RunStatus] = mapped_column(_enum(RunStatus), nullable=False)
    stage: Mapped[RunStage | None] = mapped_column(_enum(RunStage))

    progress: Mapped[float] = mapped_column(
        sa.Float, nullable=False, default=0.0, server_default="0"
    )
    """0.0 to 1.0, streamed to the dashboard over SSE (LLD section 9)."""

    engine_version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    policy_version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    model_versions: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False, default=dict)

    error: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON)
    """RFC 9457 Problem Details for a failed run, stored as written so the API
    can serve it back verbatim rather than re-deriving it."""

    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)

    capture: Mapped[Capture] = relationship(back_populates="runs")
    assessment: Mapped[Assessment | None] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )


class Assessment(Base):
    """The stored assessment document plus the columns the dashboard sorts on.

    ``document`` holds the full ``core.schema.Assessment`` model. The scalar
    columns beside it are promoted copies of fields that need to be filtered or
    ordered -- LLD section 4.1 forbids filtering on a JSON column, so anything a
    query touches becomes a real column.
    """

    __tablename__ = "assessments"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    run_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    capture_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("captures.id", ondelete="CASCADE"),
        nullable=False,
    )

    schema_version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    score_total: Mapped[int] = mapped_column(sa.SmallInteger, nullable=False)
    rating: Mapped[str] = mapped_column(sa.Text, nullable=False)
    exposure_score: Mapped[int] = mapped_column(sa.SmallInteger, nullable=False)

    document: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False)
    """The immutable artefact. Reports, the JSON export (FR-6.9) and the
    frontend's cached fetch all read this and nothing else."""

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)

    run: Mapped[AnalysisRun] = relationship(back_populates="assessment")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    security_associations: Mapped[list[SecurityAssociationRow]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Finding(Base):
    """A finding, denormalised out of ``assessments.document`` for querying.

    Exists so ``GET /assessments/{id}/findings`` can filter by severity and sort
    by penalty without a JSON path expression (LLD section 4.1, step 6.7).
    """

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
    )

    finding_key: Mapped[str] = mapped_column(sa.Text, nullable=False)
    """The stable rule key -- ``CRYPTO-3DES``. Named ``finding_key`` rather than
    ``id`` because ``id`` is this row's own UUIDv7; the Pydantic ``Finding.id``
    maps here."""

    severity: Mapped[Severity] = mapped_column(_enum(Severity), nullable=False)
    category: Mapped[FindingCategory] = mapped_column(_enum(FindingCategory), nullable=False)
    penalty: Mapped[int] = mapped_column(sa.SmallInteger, nullable=False)
    sa_spi: Mapped[str | None] = mapped_column(sa.Text)
    detail: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False)

    assessment: Mapped[Assessment] = relationship(back_populates="findings")

    __table_args__ = (sa.Index("ix_findings_assessment", "assessment_id", "severity"),)


class SecurityAssociationRow(Base):
    """An SA, denormalised out of ``assessments.document`` for querying.

    Named with a ``Row`` suffix so it is never confused with
    ``core.schema.SecurityAssociation``, which is the contract type. The table
    keeps the LLD's ``security_associations`` name.
    """

    __tablename__ = "security_associations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
    )

    spi_initiator: Mapped[str] = mapped_column(sa.Text, nullable=False)
    src_addr: Mapped[str] = mapped_column(sa.Text, nullable=False)
    dst_addr: Mapped[str] = mapped_column(sa.Text, nullable=False)
    packet_count: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    byte_count: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False)

    assessment: Mapped[Assessment] = relationship(back_populates="security_associations")

    __table_args__ = (sa.Index("ix_security_associations_assessment", "assessment_id"),)


# Declared after the class so the index can reference mapped columns directly and
# express the DESC ordering the LLD specifies. Both backends support DESC in an
# index; the dashboard lists runs and assessments newest-first, and without the
# ordering baked in the planner sorts every page.
sa.Index("ix_runs_capture", AnalysisRun.capture_id, AnalysisRun.started_at.desc())
sa.Index("ix_assessments_capture", Assessment.capture_id, Assessment.created_at.desc())

__all__ = [
    "AnalysisRun",
    "Assessment",
    "Base",
    "Capture",
    "Finding",
    "SecurityAssociationRow",
]
