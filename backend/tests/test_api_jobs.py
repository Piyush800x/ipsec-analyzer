"""Step 6.6: the concurrency bound, the event bus, and the process pool.

Separated from ``test_api.py`` because the ``ProcessPoolExecutor`` path forks
interpreters and is the slowest thing in the suite -- it is worth paying for
once, on one test, rather than on every request-level test.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from uuid import UUID

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import analyzer.api.jobs as jobs_module
from analyzer.api.jobs import EventBus, RunEvent
from analyzer.api.main import API_PREFIX, create_app
from analyzer.core.config import Settings
from analyzer.core.ids import new_id
from analyzer.db.models import Base
from analyzer.db.session import create_db_engine
from tests._pcap import DLT_EN10MB, esp_payload, eth_frame, ipv4_packet, udp_packet, write_pcap

BASELINE = Path(__file__).resolve().parents[1] / "src/analyzer/assess/policies/baseline.yaml"
MODELS_DIR = Path(__file__).resolve().parents[1] / "models"


def _capture_bytes(tmp_path: Path, spi: int) -> bytes:
    path = tmp_path / f"cap{spi}.pcap"
    write_pcap(
        path,
        DLT_EN10MB,
        [
            eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp_packet(500, 500, b"x" * 28))),
            eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(spi, 1))),
            eth_frame(ipv4_packet("10.0.0.2", "10.0.0.1", 50, esp_payload(spi + 1, 1))),
            eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(spi, 2))),
        ],
    )
    return path.read_bytes()


# --- the event bus, without any HTTP ---------------------------------------


async def test_event_bus_replays_history_to_a_late_subscriber() -> None:
    """A dashboard that subscribes a moment after POSTing must not miss the
    first stage, and a run that finished first must still stream something."""
    bus = EventBus()
    run_id = new_id()
    bus.publish(run_id, RunEvent("progress", {"stage": "ingest"}))
    bus.publish(run_id, RunEvent("complete", {"assessmentId": "x"}))

    seen = [event.event async for event in bus.subscribe(run_id)]

    assert seen == ["progress", "complete"]


async def test_event_bus_streams_to_a_live_subscriber() -> None:
    bus = EventBus()
    run_id = new_id()
    received: list[str] = []

    async def consume() -> None:
        async for event in bus.subscribe(run_id):
            received.append(event.event)

    task = asyncio.create_task(consume())
    await asyncio.sleep(0)
    bus.publish(run_id, RunEvent("progress", {"stage": "track_a"}))
    bus.publish(run_id, RunEvent("complete", {}))
    async with asyncio.timeout(5):
        await task

    assert received == ["progress", "complete"]


def test_event_encodes_in_the_sse_wire_format() -> None:
    encoded = RunEvent("progress", {"runId": "abc", "progress": 0.5}).encode()
    assert encoded.startswith("event: progress\ndata: {")
    assert encoded.endswith("\n\n")


# --- the runner, over a real app -------------------------------------------


@pytest_asyncio.fixture
async def pooled_client(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        storage_path=tmp_path / "captures",
        policy_path=BASELINE,
        model_dir=tmp_path / "models",
        max_upload_bytes=64 * 1024 * 1024,
        max_concurrent_analyses=2,
    )
    engine = create_db_engine(settings.database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    app = create_app(settings=settings, db_engine=engine, use_process_pool=True)
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http,
        app.router.lifespan_context(app),
    ):
        http.app = app  # type: ignore[attr-defined]
        yield http
    await engine.dispose()


@pytest.mark.slow
async def test_analysis_runs_in_a_process_pool(pooled_client: AsyncClient, tmp_path: Path) -> None:
    """The CPU stages really do execute in a separate process (LLD section 9)."""
    upload = await pooled_client.post(
        f"{API_PREFIX}/captures",
        files={"file": ("cap.pcap", _capture_bytes(tmp_path, 1), "application/octet-stream")},
    )
    started = await pooled_client.post(f"{API_PREFIX}/captures/{upload.json()['id']}/analyze")
    run_id = UUID(started.json()["runId"])
    await pooled_client.app.state.job_runner.wait_for(run_id, timeout=120)  # type: ignore[attr-defined]

    run = await pooled_client.get(f"{API_PREFIX}/runs/{run_id}")
    assert run.json()["status"] == "succeeded", run.json()


async def test_semaphore_bounds_concurrent_analyses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Step 6.6 Done-when: two analyses run concurrently and a third queues.

    The bound is asserted by watching how many analyses are inside the
    pipeline at once, with the pipeline itself replaced by something slow
    enough to overlap. Timing the real pipeline would prove the same thing
    only by luck: these captures analyse in milliseconds.
    """
    in_flight = 0
    peak = 0
    released = asyncio.Event()

    real = jobs_module.analyse_capture

    def slow_analyse(*args: object, **kwargs: object) -> object:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        try:
            # Busy-wait on the event from the worker thread: this stands in for
            # the CPU-bound stages holding a semaphore slot.
            while not released.is_set():
                time.sleep(0.01)
            return real(*args, **kwargs)  # type: ignore[arg-type]
        finally:
            in_flight -= 1

    monkeypatch.setattr(jobs_module, "analyse_capture", slow_analyse)

    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        storage_path=tmp_path / "captures",
        policy_path=BASELINE,
        model_dir=tmp_path / "models",
        max_upload_bytes=64 * 1024 * 1024,
        max_concurrent_analyses=2,
    )
    engine = create_db_engine(settings.database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    app = create_app(settings=settings, db_engine=engine, use_process_pool=False)
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http,
        app.router.lifespan_context(app),
    ):
        run_ids = []
        for index in range(3):
            upload = await http.post(
                f"{API_PREFIX}/captures",
                files={
                    "file": (
                        f"cap{index}.pcap",
                        _capture_bytes(tmp_path, 10 * (index + 1)),
                        "application/octet-stream",
                    )
                },
            )
            started = await http.post(f"{API_PREFIX}/captures/{upload.json()['id']}/analyze")
            run_ids.append(UUID(started.json()["runId"]))

        # Let the two that got a slot reach the pipeline, then confirm the
        # third is still waiting on the semaphore rather than running.
        async with asyncio.timeout(10):
            while in_flight < 2:
                await asyncio.sleep(0.01)
        await asyncio.sleep(0.1)
        assert in_flight == 2, "a third analysis started despite the semaphore"

        released.set()
        for run_id in run_ids:
            await runner_wait(app, run_id)

        assert peak == 2
        for run_id in run_ids:
            run = await http.get(f"{API_PREFIX}/runs/{run_id}")
            assert run.json()["status"] == "succeeded", run.json()
    await engine.dispose()


async def runner_wait(app: object, run_id: UUID) -> None:
    await app.state.job_runner.wait_for(run_id, timeout=60)  # type: ignore[attr-defined]


# --- the models actually reaching the analysis ------------------------------


async def test_the_configured_model_dir_reaches_the_pipeline(tmp_path: Path) -> None:
    """`MODEL_DIR` must arrive at `analyse_capture`, and nothing else can tell.

    This guards a defect that shipped and was invisible for the whole of Phase
    9. ``Settings.model_dir`` existed, ``docker-compose.offline.yml`` set it,
    the image carried the artefacts -- and ``JobRunner`` never passed it on, so
    the pipeline defaulted it to ``None``.

    ``None`` does not raise. ``InferenceService`` is deliberately built to
    degrade: no model directory means every model-backed attribute comes back
    UNAVAILABLE *with a reason*, and the run succeeds. So the symptom was a
    complete, internally consistent, entirely plausible assessment reporting
    "no trained model is available for this deployment" on a deployment that
    had them on disk -- and the note, being the honest one for a model-free
    build, read as correct.

    Asserted at the pipeline boundary rather than through a real model: the
    question is whether the path is *connected*, and a test that needed trained
    artefacts would be skipped exactly where those artefacts are missing.
    """
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'jobs.db'}",
        storage_path=tmp_path / "captures",
        policy_path=BASELINE,
        model_dir=tmp_path / "some-models",
        max_upload_bytes=1024 * 1024,
        max_concurrent_analyses=1,
    )
    app = create_app(settings=settings, use_process_pool=False)

    async with app.router.lifespan_context(app):
        runner = app.state.job_runner
        assert runner._model_dir == settings.model_dir, (
            "JobRunner did not receive Settings.model_dir, so every analysis "
            "will run model-free and say so as though that were the truth"
        )


async def test_an_assessment_records_the_models_that_produced_it(tmp_path: Path) -> None:
    """`model_versions` must describe what ran, because empty is a *claim*.

    The contract (``core/schema.py``) says an empty ``model_versions`` means no
    inference ran, and the technical report acts on that: it prints "Models:
    none loaded" and renders a section explaining that the model-backed fields
    were unavailable. So a pipeline that simply forgets to pass the versions
    does not produce a document with a field missing -- it produces one that
    states, in print, that no model ran.

    That shipped, and the contradiction was only visible by reading a report
    from a deployment that had models: the same document reported VoIP at
    confidence 1.0 and "none loaded".

    Both directions are asserted here, because it is the *threading* that broke
    and a one-sided test would pass against a pipeline that hardcoded `{}`.
    """
    from analyzer.api.pipeline import analyse_capture
    from analyzer.assess.engine import AssessmentEngine
    from analyzer.assess.policy import load_policy

    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(_capture_bytes(tmp_path, 7))
    engine = AssessmentEngine(load_policy(BASELINE))

    document = analyse_capture(
        pcap,
        engine,
        capture_id=new_id(),
        engine_version="test",
        model_dir=tmp_path / "no-models-here",
    )

    assert document.model_versions == {}, (
        "a build with no models must report none, so that an empty value keeps "
        "meaning what the contract says it means"
    )

    if not (MODELS_DIR / "traffic_lightgbm.txt").is_file():
        pytest.skip("no trained artefacts committed, so there is nothing to hash")

    loaded = analyse_capture(
        pcap,
        engine,
        capture_id=new_id(),
        engine_version="test",
        model_dir=MODELS_DIR,
    )
    assert loaded.model_versions, (
        "models were on disk and loadable, and the assessment still claims none "
        "ran -- which the technical report prints as 'Models: none loaded'"
    )
