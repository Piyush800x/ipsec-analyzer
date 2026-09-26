"""Capture upload and CRUD (LLD 9). Steps 6.3, 6.4, and the analyze trigger.

The upload path never holds a capture in memory: it streams to a temporary
file in 8 MB chunks, hashing as it goes, and only then decides whether to keep
it. That ordering is what makes the 2 GB cap (LLD section 9) and the
magic-byte check enforceable without a 2 GB allocation, and it is why a
rejected file never reaches its final path at all.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Final
from uuid import UUID

import sqlalchemy as sa
from fastapi import APIRouter, Body, File, Query, Request, UploadFile, status

from analyzer.api.deps import SessionDep, SettingsDep, StorageDep
from analyzer.api.errors import (
    DependencyUnavailableError,
    NotFoundError,
    PayloadTooLargeError,
    ValidationError,
)
from analyzer.api.jobs import JobRunner
from analyzer.api.schemas import AnalyzeAccepted, AnalyzeRequest, CapturePage, CaptureSummary
from analyzer.core.enums import CaptureSource, RunStatus
from analyzer.core.ids import new_id
from analyzer.db import models
from analyzer.report.render import PDF_BACKEND_HINT, pdf_backend_available

router = APIRouter(prefix="/captures", tags=["captures"])

CHUNK_BYTES: Final = 8 * 1024 * 1024
"""LLD section 9. Large enough that a 2 GB upload is a few hundred reads,
small enough that concurrent uploads do not add up to anything alarming."""

PCAP_MAGIC: Final[tuple[bytes, ...]] = (
    b"\xd4\xc3\xb2\xa1",  # classic pcap, little-endian
    b"\xa1\xb2\xc3\xd4",  # classic pcap, big-endian
    b"\x4d\x3c\xb2\xa1",  # nanosecond, little-endian
    b"\xa1\xb2\x3c\x4d",  # nanosecond, big-endian
    b"\x0a\x0d\x0d\x0a",  # pcapng section header block
)
"""LLD section 9's list. Checked against the first four bytes actually written
to disk, not against the filename -- a ``.txt`` renamed to ``.pcap`` is the
exact case step 6.3 requires be rejected before persistence."""


def _summary(row: models.Capture) -> CaptureSummary:
    return CaptureSummary.model_validate(row)


@router.post("", status_code=status.HTTP_201_CREATED, response_model=CaptureSummary)
async def upload_capture(
    session: SessionDep,
    settings: SettingsDep,
    storage: StorageDep,
    file: Annotated[UploadFile, File(description="A pcap or pcapng capture")],
) -> CaptureSummary:
    """Stream a capture to disk, dedupe on SHA-256, and record it."""
    filename = Path(file.filename or "capture.pcap").name
    limit = settings.max_upload_bytes

    digest = hashlib.sha256()
    size = 0
    first_chunk = b""

    with tempfile.NamedTemporaryFile(dir=storage, delete=False, suffix=".part") as staged:
        staged_path = Path(staged.name)
        try:
            while chunk := await file.read(CHUNK_BYTES):
                if not first_chunk:
                    first_chunk = chunk[:4]
                size += len(chunk)
                if size > limit:
                    raise PayloadTooLargeError(limit)
                digest.update(chunk)
                staged.write(chunk)
        except PayloadTooLargeError:
            staged.close()
            staged_path.unlink(missing_ok=True)
            raise

    if not first_chunk.startswith(PCAP_MAGIC):
        staged_path.unlink(missing_ok=True)
        raise ValidationError(
            "The uploaded file is not a pcap or pcapng capture: its first four "
            "bytes match no known capture-file magic number.",
            extra={"filename": filename},
        )

    sha256 = digest.hexdigest()
    existing = await session.scalar(
        sa.select(models.Capture).where(models.Capture.sha256 == sha256)
    )
    if existing is not None:
        # Dedupe rather than conflict: re-uploading a capture an analyst
        # already has is a normal thing to do, and the useful answer is the
        # row they already own.
        staged_path.unlink(missing_ok=True)
        return _summary(existing)

    capture_id = new_id()
    final_path = storage / f"{capture_id}.pcap"
    shutil.move(str(staged_path), final_path)

    row = models.Capture(
        id=capture_id,
        filename=filename,
        sha256=sha256,
        size_bytes=size,
        source=CaptureSource.UPLOAD,
        storage_path=str(final_path),
        created_at=datetime.now(tz=UTC),
    )
    session.add(row)
    await session.flush()
    return _summary(row)


@router.get("", response_model=CapturePage)
async def list_captures(
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CapturePage:
    total = await session.scalar(sa.select(sa.func.count()).select_from(models.Capture)) or 0
    rows = (
        await session.scalars(
            sa.select(models.Capture)
            .order_by(models.Capture.id.desc())  # UUIDv7: id order is chronological
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return CapturePage(
        items=[_summary(row) for row in rows], total=total, limit=limit, offset=offset
    )


async def _get_capture(session: SessionDep, capture_id: UUID) -> models.Capture:
    row = await session.get(models.Capture, capture_id)
    if row is None:
        raise NotFoundError("capture", capture_id)
    return row


@router.get("/{capture_id}", response_model=CaptureSummary)
async def get_capture(session: SessionDep, capture_id: UUID) -> CaptureSummary:
    return _summary(await _get_capture(session, capture_id))


@router.delete("/{capture_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_capture(session: SessionDep, capture_id: UUID) -> None:
    """Remove the row and the stored PCAP. Step 6.4: no orphaned file."""
    row = await _get_capture(session, capture_id)
    stored = Path(row.storage_path)
    await session.delete(row)
    await session.flush()
    stored.unlink(missing_ok=True)


def _check_can_email(runner: JobRunner) -> None:
    """Refuse an address this deployment cannot deliver to, before the run.

    Checked up front rather than discovered when the run finishes: an analyst
    who asked for the reports by email and got a silent nothing a minute later
    has been told something false. Both refusals are 503s because the request
    is fine and an operator's install is what is missing.
    """
    if not runner.can_email:
        raise DependencyUnavailableError(
            "Emailing reports is not configured on this server. An operator enables it "
            "by setting SMTP_HOST and SMTP_FROM (see .env.example). The analysis does "
            "not need it: start it again without an email address.",
            capability="email",
        )
    if not pdf_backend_available():
        raise DependencyUnavailableError(PDF_BACKEND_HINT, capability="pdf")


@router.post(
    "/{capture_id}/analyze",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AnalyzeAccepted,
)
async def start_analysis(
    request: Request,
    session: SessionDep,
    capture_id: UUID,
    body: Annotated[AnalyzeRequest | None, Body()] = None,
) -> AnalyzeAccepted:
    capture = await _get_capture(session, capture_id)
    if not Path(capture.storage_path).exists():
        raise NotFoundError("stored capture file for capture", capture_id)

    runner: JobRunner = request.app.state.job_runner
    notify_email = body.notify_email if body is not None else None
    if notify_email is not None:
        _check_can_email(runner)
    engine = request.app.state.assessment_engine
    run = models.AnalysisRun(
        id=new_id(),
        capture_id=capture.id,
        status=RunStatus.QUEUED,
        progress=0.0,
        engine_version=request.app.state.engine_version,
        policy_version=engine.policy.version,
        model_versions={},
    )
    session.add(run)
    await session.flush()
    run_id = run.id
    capture_uuid = capture.id
    storage_path = Path(capture.storage_path)

    # Commit before handing the run to the background task. The job's first
    # write is `_mark_running`, and SQLite holds a write lock for the whole of
    # an open transaction -- so leaving this one open until the dependency
    # tears it down would stall the job for the length of the request.
    await session.commit()

    runner.submit(run_id, capture_uuid, storage_path, notify_email=notify_email)
    return AnalyzeAccepted(run_id=run_id, capture_id=capture_uuid, status=RunStatus.QUEUED)
