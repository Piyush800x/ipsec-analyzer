"""Run status and the SSE progress stream (LLD 9). Step 6.6."""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import UUID

import sqlalchemy as sa
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from analyzer.api.deps import SessionDep
from analyzer.api.errors import NotFoundError
from analyzer.api.schemas import RunSummary
from analyzer.db import models

router = APIRouter(prefix="/runs", tags=["runs"])


@router.get("/{run_id}", response_model=RunSummary)
async def get_run(session: SessionDep, run_id: UUID) -> RunSummary:
    run = await session.get(models.AnalysisRun, run_id)
    if run is None:
        raise NotFoundError("run", run_id)
    assessment_id = await session.scalar(
        sa.select(models.Assessment.id).where(models.Assessment.run_id == run_id)
    )
    return RunSummary(
        id=run.id,
        capture_id=run.capture_id,
        status=run.status,
        stage=run.stage,
        progress=run.progress,
        engine_version=run.engine_version,
        policy_version=run.policy_version,
        error=run.error,
        started_at=run.started_at,
        finished_at=run.finished_at,
        assessment_id=assessment_id,
    )


@router.get("/{run_id}/events")
async def stream_run_events(request: Request, run_id: UUID) -> StreamingResponse:
    """Server-sent events for one run, in LLD section 9's wire format.

    ``X-Accel-Buffering: no`` and ``Cache-Control: no-cache`` are both load
    bearing: without them a proxy in front of this endpoint will buffer the
    stream and the dashboard's progress bar jumps from 0 to 100 at the end,
    which looks exactly like a hung analysis.
    """
    runner = request.app.state.job_runner

    async def generate() -> AsyncIterator[str]:
        async for event in runner.bus.subscribe(run_id):
            if await request.is_disconnected():
                return
            yield event.encode()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
