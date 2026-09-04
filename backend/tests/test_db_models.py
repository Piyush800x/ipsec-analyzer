"""Step 1.5 -- the model set creates and behaves identically on both backends.

Done-when: ``Base.metadata.create_all()`` runs against SQLite and PostgreSQL.
That is necessary but weak on its own, so the portability rules from LLD section
4.1 are checked as properties of the metadata, and a full write/read cycle is
exercised on both backends to catch the places where "it created the table" and
"it round-trips the data" diverge -- UUIDs, JSON, and timezone-aware timestamps
being the three that reliably do.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from analyzer.core.enums import CaptureSource, FindingCategory, RunStage, RunStatus, Severity
from analyzer.core.ids import new_id
from analyzer.core.schema import Assessment as AssessmentDoc
from analyzer.db.models import (
    AnalysisRun,
    Assessment,
    Base,
    Capture,
    Finding,
    SecurityAssociationRow,
)

FIXTURE = Path(__file__).parent / "fixtures" / "assessment_weak.json"

EXPECTED_TABLES = {
    "captures",
    "analysis_runs",
    "assessments",
    "findings",
    "security_associations",
}


# --------------------------------------------------------------------------
# Portability rules, checked against the metadata itself
# --------------------------------------------------------------------------


def test_every_lld_table_is_present() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_no_jsonb_anywhere_in_the_models() -> None:
    """LLD section 4.1. JSONB is a Postgres type SQLite cannot create; the
    upgrade happens in a dialect-guarded Alembic step, not here."""
    for table in Base.metadata.tables.values():
        for column in table.columns:
            assert type(column.type).__name__ != "JSONB", f"{table.name}.{column.name}"


def test_no_postgres_only_column_types() -> None:
    """No arrays, no HSTORE, no native enums, no Postgres-specific anything.

    A model that only compiles on one backend defeats the offline compose file,
    the CI matrix, and the demo posture in LLD section 13 all at once.
    """
    banned = {"ARRAY", "HSTORE", "INET", "CIDR", "MACADDR", "TSVECTOR", "JSONPATH"}
    for table in Base.metadata.tables.values():
        for column in table.columns:
            assert type(column.type).__name__ not in banned, f"{table.name}.{column.name}"
            if isinstance(column.type, sa.Enum):
                assert column.type.native_enum is False, (
                    f"{table.name}.{column.name} would create a Postgres ENUM type"
                )


def test_enum_columns_store_wire_values_not_member_names() -> None:
    """Without ``values_callable`` SQLAlchemy stores ``TRIPLE_DES_CBC`` where the
    rest of the system expects ``3des-cbc``."""
    severity = Base.metadata.tables["findings"].columns["severity"]
    assert isinstance(severity.type, sa.Enum)
    assert set(severity.type.enums) == {s.value for s in Severity}


def test_primary_keys_are_uuid_columns() -> None:
    for table in Base.metadata.tables.values():
        (pk,) = list(table.primary_key.columns)
        assert pk.name == "id"
        assert isinstance(pk.type, sa.Uuid), table.name


def test_all_identifiers_are_snake_case() -> None:
    """CLAUDE.md: snake_case in Python and in the database, no exceptions."""
    for table in Base.metadata.tables.values():
        assert table.name.islower(), table.name
        assert " " not in table.name, table.name
        for column in table.columns:
            assert column.name == column.name.lower(), f"{table.name}.{column.name}"
            assert "-" not in column.name

    for table in Base.metadata.tables.values():
        for index in table.indexes:
            assert index.name is not None
            assert index.name.startswith("ix_"), index.name
            assert index.name == index.name.lower()


def test_foreign_keys_cascade_on_delete() -> None:
    """Deleting a capture must not strand its runs, assessments and findings."""
    for table in Base.metadata.tables.values():
        for fk in table.foreign_keys:
            assert fk.ondelete == "CASCADE", f"{table.name}.{fk.parent.name}"


def test_lld_indexes_exist_with_their_specified_names() -> None:
    names = {index.name for table in Base.metadata.tables.values() for index in table.indexes}
    assert {
        "ix_captures_sha256",
        "ix_runs_capture",
        "ix_assessments_capture",
        "ix_findings_assessment",
    } <= names


def test_sha256_is_unique() -> None:
    """Upload dedupe (LLD section 9) depends on this being enforced by the
    database, not by a read-then-write race in the request handler."""
    (index,) = [
        i for i in Base.metadata.tables["captures"].indexes if i.name == "ix_captures_sha256"
    ]
    assert index.unique is True


# --------------------------------------------------------------------------
# The Done-when, on both backends
# --------------------------------------------------------------------------


async def test_create_all_and_drop_all(engine: AsyncEngine, backend: str) -> None:
    """Step 1.5's Done-when. The ``engine`` fixture has already run create_all;
    this asserts the tables really landed and that drop_all is clean too."""
    async with engine.connect() as conn:
        found = await conn.run_sync(lambda c: set(sa.inspect(c).get_table_names()))
    assert found >= EXPECTED_TABLES, f"{backend}: missing {EXPECTED_TABLES - found}"

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        remaining = await conn.run_sync(lambda c: set(sa.inspect(c).get_table_names()))
    assert not (EXPECTED_TABLES & remaining), f"{backend}: drop_all left tables behind"

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# --------------------------------------------------------------------------
# A full write/read cycle, identical on both backends
# --------------------------------------------------------------------------


def _rows() -> tuple[Capture, AnalysisRun, Assessment, Finding, SecurityAssociationRow]:
    doc = AssessmentDoc.model_validate_json(FIXTURE.read_text(encoding="utf-8"))
    document: dict[str, Any] = json.loads(doc.model_dump_json())

    created = datetime(2026, 9, 3, 9, 20, 11, 903000, tzinfo=UTC)
    capture = Capture(
        id=new_id(),
        filename="tunnel_a_weak.pcap",
        sha256="9f2c" + "0" * 60,
        size_bytes=4_212_880,
        source=CaptureSource.TESTBED,
        storage_path="/data/captures/9f2c.pcap",
        packet_count=doc.capture_quality.packet_count,
        duration_s=doc.capture_quality.duration_s,
        has_ike=doc.capture_quality.has_ike,
        truncated=doc.capture_quality.truncated,
        ground_truth={"mode": "transport", "esp": "3des-sha1", "dh": 2, "pfs": False},
        created_at=created,
    )
    run = AnalysisRun(
        id=new_id(),
        capture_id=capture.id,
        status=RunStatus.SUCCEEDED,
        stage=RunStage.REPORT,
        progress=1.0,
        engine_version=doc.engine_version,
        policy_version=doc.policy_version,
        model_versions=dict(doc.model_versions),
        started_at=created,
        finished_at=created + timedelta(seconds=41),
    )
    assessment = Assessment(
        id=doc.assessment_id,
        run_id=run.id,
        capture_id=capture.id,
        schema_version=doc.schema_version,
        score_total=doc.score.total,
        rating=doc.score.rating,
        exposure_score=doc.metadata_exposure.score,
        document=document,
        created_at=doc.generated_at,
    )
    first = doc.findings[0]
    finding = Finding(
        id=new_id(),
        assessment_id=assessment.id,
        finding_key=first.id,
        severity=first.severity,
        category=first.category,
        penalty=first.penalty,
        sa_spi=first.sa_spi,
        detail=json.loads(first.model_dump_json()),
    )
    sa_doc = doc.security_associations[0]
    sa_row = SecurityAssociationRow(
        id=new_id(),
        assessment_id=assessment.id,
        spi_initiator=sa_doc.spi_initiator,
        src_addr=str(sa_doc.src),
        dst_addr=str(sa_doc.dst),
        packet_count=sa_doc.packet_count,
        byte_count=sa_doc.byte_count,
        detail=json.loads(sa_doc.model_dump_json()),
    )
    return capture, run, assessment, finding, sa_row


async def test_write_and_read_back_the_weak_fixture(engine: AsyncEngine, backend: str) -> None:
    """The write path of step 6.5, in miniature, on both backends."""
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    capture, run, assessment, finding, sa_row = _rows()

    async with session_factory() as session, session.begin():
        session.add_all([capture, run, assessment, finding, sa_row])

    async with session_factory() as session:
        stored = await session.get(Assessment, assessment.id)
        assert stored is not None, backend

        # JSON survives intact, including nested provenance.
        assert stored.document["score"]["total"] == 15
        sa_json = stored.document["security_associations"][0]
        assert sa_json["encryption_alg"]["provenance"] == "observed"
        assert sa_json["negotiated_lifetime_s"]["provenance"] == "observed"
        assert sa_json["observed_rekey_s"]["provenance"] == "unavailable"
        assert sa_json["observed_rekey_s"]["note"]

        # UUIDv7 keys survive, and stay v7.
        assert stored.id == assessment.id
        assert stored.id.version == 7

        # Timestamps come back aware and in UTC on both backends.
        assert stored.created_at.tzinfo is not None
        assert stored.created_at.utcoffset() == timedelta(0)
        assert stored.created_at == assessment.created_at

        stored_finding = await session.get(Finding, finding.id)
        assert stored_finding is not None
        assert stored_finding.severity is Severity.CRITICAL
        assert stored_finding.category is FindingCategory.CRYPTOGRAPHIC_STRENGTH

        stored_capture = await session.get(Capture, capture.id)
        assert stored_capture is not None
        assert stored_capture.source is CaptureSource.TESTBED
        assert stored_capture.ground_truth == capture.ground_truth


async def test_enum_columns_persist_as_lowercase_wire_values(engine: AsyncEngine) -> None:
    """Read the raw column, not the ORM's coerced value.

    If this stored ``CRITICAL`` instead of ``critical``, the ORM would still hand
    back the right enum and every Python-level assertion would pass, while the
    dashboard's severity filter -- which queries the column directly -- silently
    matched nothing.
    """
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    capture, run, assessment, finding, sa_row = _rows()
    async with session_factory() as session, session.begin():
        session.add_all([capture, run, assessment, finding, sa_row])

    async with engine.connect() as conn:
        raw = await conn.execute(sa.text("SELECT severity, category FROM findings"))
        rows = raw.all()
    assert rows == [("critical", "cryptographic_strength")]


async def test_severity_filter_needs_no_json_path_query(engine: AsyncEngine) -> None:
    """LLD section 4.1 forbids JSON path filtering, which is why ``findings``
    duplicates content already inside ``assessments.document``. Step 6.7's
    endpoint is this query."""
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    capture, run, assessment, finding, sa_row = _rows()
    async with session_factory() as session, session.begin():
        session.add_all([capture, run, assessment, finding, sa_row])

    async with session_factory() as session:
        stmt = (
            sa.select(Finding)
            .where(Finding.assessment_id == assessment.id)
            .where(Finding.severity == Severity.CRITICAL)
            .order_by(Finding.penalty.desc())
        )
        result = list((await session.scalars(stmt)).all())
    assert [f.finding_key for f in result] == ["CRYPTO-3DES"]


async def test_naive_datetime_is_refused_at_the_database_boundary(engine: AsyncEngine) -> None:
    """CLAUDE.md: a naive datetime crossing a module boundary is a bug. It is
    refused loudly rather than stored as an ambiguous local time."""
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    capture, *_ = _rows()
    capture.created_at = datetime(2026, 9, 3, 9, 20, 11)  # noqa: DTZ001 -- the point of the test

    with pytest.raises(Exception, match="naive datetime"):
        async with session_factory() as session, session.begin():
            session.add(capture)


async def test_offset_timestamps_normalise_to_utc(engine: AsyncEngine) -> None:
    """Two runs that record the same instant in different offsets must be equal
    on read-back, or NFR-4's byte-identical comparison fails on a clock."""
    from datetime import timezone

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    capture, *_ = _rows()
    ist = timezone(timedelta(hours=5, minutes=30))
    capture.created_at = datetime(2026, 9, 3, 14, 50, 11, 903000, tzinfo=ist)

    async with session_factory() as session, session.begin():
        session.add(capture)

    async with session_factory() as session:
        stored = await session.get(Capture, capture.id)
        assert stored is not None
        assert stored.created_at == datetime(2026, 9, 3, 9, 20, 11, 903000, tzinfo=UTC)
        assert stored.created_at.utcoffset() == timedelta(0)
