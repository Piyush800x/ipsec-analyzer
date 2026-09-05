"""Background analysis jobs and SSE progress (LLD 9). Step 6.6.

``asyncio.Semaphore(MAX_CONCURRENT_ANALYSES)`` bounds concurrent analyses; the
CPU-bound stages run in a ``ProcessPoolExecutor`` so the event loop stays free
to serve the SSE streams watching them. No Celery, no Redis -- LLD section 9 is
explicit that a 60-second job budget does not justify that infrastructure.

The event bus is in-process and deliberately so. It is the same decision as the
job runner: one API process owns its runs, and a second process would need a
broker to see them. If this ever runs multiplied behind a load balancer, the
bus is the piece that has to change, and it is isolated here for that reason.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from analyzer.api.pipeline import (
    STAGE_PROGRESS,
    analyse_capture,
    analyse_capture_json,
    persist_assessment,
)
from analyzer.assess.engine import AssessmentEngine
from analyzer.core.enums import RunStage, RunStatus
from analyzer.core.schema import Assessment as AssessmentDocument
from analyzer.db import models

log = logging.getLogger(__name__)

QUEUE_MAXSIZE = 64
"""Bounded so a client that opens an SSE stream and stops reading cannot grow
a queue without limit. Progress events are advisory -- dropping one on a full
queue is better than holding the run's memory hostage to a stalled reader."""


@dataclass(slots=True)
class RunEvent:
    event: str
    data: dict[str, Any]

    def encode(self) -> str:
        """SSE wire format, exactly as LLD section 9 specifies it."""
        return f"event: {self.event}\ndata: {json.dumps(self.data, separators=(',', ':'))}\n\n"


@dataclass(slots=True)
class _RunChannel:
    subscribers: list[asyncio.Queue[RunEvent | None]] = field(default_factory=list)
    history: list[RunEvent] = field(default_factory=list)
    finished: bool = False


class EventBus:
    """Fan-out of run progress to any number of SSE subscribers."""

    def __init__(self) -> None:
        self._channels: dict[UUID, _RunChannel] = {}

    def publish(self, run_id: UUID, event: RunEvent) -> None:
        channel = self._channels.setdefault(run_id, _RunChannel())
        channel.history.append(event)
        if event.event in ("complete", "error"):
            channel.finished = True
        for queue in list(channel.subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:  # pragma: no cover - only under a stalled reader
                log.warning("dropping progress event for run %s: subscriber queue full", run_id)
        if channel.finished:
            for queue in list(channel.subscribers):
                queue.put_nowait(None)

    async def subscribe(self, run_id: UUID) -> AsyncIterator[RunEvent]:
        """Replay what this run has already emitted, then stream the rest.

        Replaying matters: a dashboard that opens the stream a moment after
        POSTing the analysis would otherwise miss the first stage, and a run
        that finished before anyone subscribed would stream nothing at all.
        """
        channel = self._channels.setdefault(run_id, _RunChannel())
        for event in list(channel.history):
            yield event
        if channel.finished:
            return

        queue: asyncio.Queue[RunEvent | None] = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
        channel.subscribers.append(queue)
        try:
            while True:
                pending = await queue.get()
                if pending is None:
                    return
                yield pending
        finally:
            if queue in channel.subscribers:
                channel.subscribers.remove(queue)

    def forget(self, run_id: UUID) -> None:
        self._channels.pop(run_id, None)


class JobRunner:
    """Owns the concurrency bound, the process pool, and the event bus."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        engine: AssessmentEngine,
        *,
        max_concurrent: int,
        engine_version: str,
        use_process_pool: bool = True,
    ) -> None:
        self._session_factory = session_factory
        self._engine = engine
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._engine_version = engine_version
        self._pool: ProcessPoolExecutor | None = ProcessPoolExecutor() if use_process_pool else None
        self.bus = EventBus()
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def queued_or_running(self) -> int:
        return len([task for task in self._tasks if not task.done()])

    def submit(self, run_id: UUID, capture_id: UUID, pcap_path: Path) -> None:
        task = asyncio.create_task(self._run(run_id, capture_id, pcap_path))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def wait_for(self, run_id: UUID, timeout: float = 30.0) -> None:
        """Test and shutdown helper: block until this run stops emitting."""
        async with asyncio.timeout(timeout):
            async for _ in self.bus.subscribe(run_id):
                pass

    async def aclose(self) -> None:
        """Cancel in-flight runs and *wait* for them to unwind.

        Awaiting matters: a cancelled run still runs its exception path, which
        touches the database to mark the run failed. Returning before that
        finished would let the caller dispose the engine underneath it, and the
        symptom is a "Connection closed" traceback from a task nobody is
        waiting on.
        """
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)

    async def _run(self, run_id: UUID, capture_id: UUID, pcap_path: Path) -> None:
        self.bus.publish(
            run_id,
            RunEvent(
                "progress",
                {
                    "runId": str(run_id),
                    "stage": "queued",
                    "progress": 0.0,
                    "message": "waiting for a slot",
                },
            ),
        )
        async with self._semaphore:
            await self._mark_running(run_id)
            try:
                document = await self._analyse(run_id, capture_id, pcap_path)
            except Exception as exc:
                log.exception("analysis run %s failed", run_id)
                await self._mark_failed(run_id, exc)
                self.bus.publish(
                    run_id,
                    RunEvent("error", {"runId": str(run_id), "detail": str(exc)}),
                )
                return

            assessment_id = await self._persist(run_id, document)
            self.bus.publish(
                run_id,
                RunEvent("complete", {"runId": str(run_id), "assessmentId": str(assessment_id)}),
            )

    async def _analyse(self, run_id: UUID, capture_id: UUID, pcap_path: Path) -> Any:
        loop = asyncio.get_running_loop()

        def emit(stage: RunStage, progress: float, message: str) -> None:
            # Called from the worker thread/process only when running inline;
            # the pool path publishes stage events around the call instead.
            self.bus.publish(
                run_id,
                RunEvent(
                    "progress",
                    {
                        "runId": str(run_id),
                        "stage": stage.value,
                        "progress": progress,
                        "message": message,
                    },
                ),
            )

        if self._pool is None:
            return await loop.run_in_executor(
                None,
                lambda: analyse_capture(
                    pcap_path,
                    self._engine,
                    capture_id=capture_id,
                    engine_version=self._engine_version,
                    on_progress=emit,
                ),
            )

        # A ProcessPoolExecutor cannot call back into this process, so stage
        # events are emitted here around the call rather than from inside it.
        emit(RunStage.INGEST, STAGE_PROGRESS[RunStage.INGEST] / 2, "reading the capture")
        payload = await loop.run_in_executor(
            self._pool,
            partial(
                analyse_capture_json,
                pcap_path,
                self._engine,
                capture_id=capture_id,
                engine_version=self._engine_version,
            ),
        )
        document = AssessmentDocument.model_validate_json(payload)
        for stage in (RunStage.INGEST, RunStage.TRACK_A, RunStage.TRACK_B, RunStage.ASSESS):
            emit(stage, STAGE_PROGRESS[stage], f"{stage.value} complete")
        return document

    async def _mark_running(self, run_id: UUID) -> None:
        async with self._session_factory() as session:
            run = await session.get(models.AnalysisRun, run_id)
            if run is not None:
                run.status = RunStatus.RUNNING
                run.stage = RunStage.INGEST
                run.started_at = datetime.now(tz=UTC)
                await session.commit()

    async def _mark_failed(self, run_id: UUID, exc: Exception) -> None:
        async with self._session_factory() as session:
            run = await session.get(models.AnalysisRun, run_id)
            if run is not None:
                run.status = RunStatus.FAILED
                run.finished_at = datetime.now(tz=UTC)
                run.error = {
                    "type": "https://ipsec-analyzer.invalid/problems/analysis-failed",
                    "title": "Analysis failed",
                    "status": 500,
                    "detail": str(exc),
                }
                await session.commit()

    async def _persist(self, run_id: UUID, document: Any) -> UUID:
        async with self._session_factory() as session:
            row = await persist_assessment(session, document, run_id=run_id)
            run = await session.get(models.AnalysisRun, run_id)
            if run is not None:
                run.status = RunStatus.SUCCEEDED
                run.stage = RunStage.ASSESS
                run.progress = 1.0
                run.finished_at = datetime.now(tz=UTC)
            await session.commit()
            assessment_id: UUID = row.id
            return assessment_id
