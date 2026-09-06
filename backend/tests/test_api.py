"""Phase 6: the API, the job runner and the pipeline, end to end.

Every test drives a real FastAPI app over ASGI against a throwaway SQLite
file, with the job runner running inline rather than in a process pool -- the
pool is exercised separately in ``test_api_jobs.py`` where its cost is paid
once.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.pool import NullPool

from analyzer.api.errors import PROBLEM_CONTENT_TYPE
from analyzer.api.main import API_PREFIX, create_app
from analyzer.core.config import Settings
from analyzer.db.models import Base
from analyzer.db.session import create_db_engine
from tests._pcap import DLT_EN10MB, esp_payload, eth_frame, ipv4_packet, udp_packet, write_pcap
from tests.conftest import postgres_url

BASELINE = Path(__file__).resolve().parents[1] / "src/analyzer/assess/policies/baseline.yaml"


def _database_url(backend: str, tmp_path: Path) -> str:
    if backend == "sqlite":
        return f"sqlite+aiosqlite:///{tmp_path / 'api.db'}"
    return postgres_url() or ""


def _pcap_bytes(tmp_path: Path, name: str = "cap.pcap", *, spi: int = 1) -> bytes:
    """A minimal but *pairable* capture: IKE first, then both ESP directions
    interleaved.

    The interleaving is deliberate. ``write_pcap`` stamps one whole second per
    frame, and step 3.5 pairs two directional flows only when their time ranges
    actually intersect -- two single-packet flows a second apart do not, and
    would arrive as two unpaired SAs rather than one pair.

    ``spi`` varies the bytes so two uploads in one test are not deduped into
    one capture by their SHA-256.
    """
    path = tmp_path / name
    frames = [
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp_packet(500, 500, b"x" * 28))),
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(spi, 1))),
        eth_frame(ipv4_packet("10.0.0.2", "10.0.0.1", 50, esp_payload(spi + 1, 1))),
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(spi, 2))),
        eth_frame(ipv4_packet("10.0.0.2", "10.0.0.1", 50, esp_payload(spi + 1, 2))),
    ]
    write_pcap(path, DLT_EN10MB, frames)
    return path.read_bytes()


@pytest_asyncio.fixture
async def client(backend: str, tmp_path: Path) -> AsyncIterator[AsyncClient]:
    """The API, over ASGI, against whichever backend `backend` selected.

    Step 11.2: the full API suite runs on SQLite *and* PostgreSQL. The
    dual-backend requirement (LLD section 4.1) is about the whole stack, not
    just the model layer -- an endpoint that works on SQLite and not on
    Postgres is exactly the failure that survives a model-only test.
    """
    settings = Settings(
        database_url=_database_url(backend, tmp_path),
        storage_path=tmp_path / "captures",
        policy_path=BASELINE,
        model_dir=tmp_path / "models",
        max_upload_bytes=64 * 1024 * 1024,
        max_concurrent_analyses=2,
    )
    engine = create_db_engine(settings.database_url, poolclass=NullPool)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)

    app = create_app(settings=settings, db_engine=engine, use_process_pool=False)
    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://test") as http,
        app.router.lifespan_context(app),
    ):
        http.app = app  # type: ignore[attr-defined] # tests reach app.state for the runner
        yield http
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
    await engine.dispose()


async def _upload(
    client: AsyncClient, tmp_path: Path, name: str = "cap.pcap", *, spi: int = 1
) -> dict:
    response = await client.post(
        f"{API_PREFIX}/captures",
        files={
            "file": (name, _pcap_bytes(tmp_path, name, spi=spi), "application/vnd.tcpdump.pcap")
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


# --- step 6.1: health -------------------------------------------------------


async def test_health_reports_ok_against_sqlite(client: AsyncClient) -> None:
    response = await client.get(f"{API_PREFIX}/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "up"


# --- step 6.2: RFC 9457 problem details -------------------------------------


async def test_unknown_route_is_problem_json(client: AsyncClient) -> None:
    """Step 6.2 Done-when: a 404 is application/problem+json with the four
    required members."""
    response = await client.get(f"{API_PREFIX}/captures/00000000-0000-7000-8000-000000000000")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)
    body = response.json()
    assert set(body) >= {"type", "title", "status", "detail"}
    assert body["status"] == 404


async def test_invalid_uuid_is_problem_json(client: AsyncClient) -> None:
    response = await client.get(f"{API_PREFIX}/captures/not-a-uuid")
    assert response.status_code == 422
    assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)
    assert response.json()["title"] == "Request validation failed"


# --- step 6.3: upload -------------------------------------------------------


async def test_upload_returns_201_and_dedupes_on_sha256(
    client: AsyncClient, tmp_path: Path
) -> None:
    first = await _upload(client, tmp_path)
    second = await _upload(client, tmp_path)
    assert first["id"] == second["id"], "the same bytes must not create a second capture"
    assert first["sha256"] == second["sha256"]


async def test_upload_rejects_a_txt_renamed_to_pcap(client: AsyncClient) -> None:
    """Step 6.3 Done-when: magic-byte validation before persistence."""
    response = await client.post(
        f"{API_PREFIX}/captures",
        files={
            "file": ("evil.pcap", b"this is plainly not a capture file", "application/octet-stream")
        },
    )
    assert response.status_code == 422
    assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)
    listed = await client.get(f"{API_PREFIX}/captures")
    assert listed.json()["total"] == 0, "a rejected upload must not be persisted"


async def test_upload_over_the_cap_is_rejected(client: AsyncClient, tmp_path: Path) -> None:
    client.app.state.settings.max_upload_bytes = 16  # type: ignore[attr-defined]
    response = await client.post(
        f"{API_PREFIX}/captures",
        files={"file": ("big.pcap", _pcap_bytes(tmp_path), "application/octet-stream")},
    )
    assert response.status_code == 413
    assert response.json()["limitBytes"] == 16


async def test_rejected_upload_leaves_no_file_behind(client: AsyncClient, tmp_path: Path) -> None:
    await client.post(
        f"{API_PREFIX}/captures",
        files={"file": ("evil.pcap", b"nope", "application/octet-stream")},
    )
    storage = tmp_path / "captures"
    assert list(storage.glob("*")) == []


# --- step 6.4: capture CRUD -------------------------------------------------


async def test_list_captures_paginates(client: AsyncClient, tmp_path: Path) -> None:
    for index in range(3):
        await _upload(client, tmp_path, f"cap{index}.pcap", spi=10 * (index + 1))
    response = await client.get(f"{API_PREFIX}/captures", params={"limit": 2, "offset": 0})
    body = response.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2
    assert body["limit"] == 2


async def test_get_capture_detail(client: AsyncClient, tmp_path: Path) -> None:
    capture = await _upload(client, tmp_path)
    response = await client.get(f"{API_PREFIX}/captures/{capture['id']}")
    assert response.status_code == 200
    assert response.json()["filename"] == "cap.pcap"


async def test_delete_removes_row_and_file(client: AsyncClient, tmp_path: Path) -> None:
    """Step 6.4 Done-when: delete leaves no orphaned file on disk."""
    capture = await _upload(client, tmp_path)
    stored = list((tmp_path / "captures").glob("*.pcap"))
    assert len(stored) == 1

    response = await client.delete(f"{API_PREFIX}/captures/{capture['id']}")
    assert response.status_code == 204
    assert list((tmp_path / "captures").glob("*.pcap")) == []
    assert (await client.get(f"{API_PREFIX}/captures/{capture['id']}")).status_code == 404


async def test_delete_unknown_capture_is_404(client: AsyncClient) -> None:
    response = await client.delete(f"{API_PREFIX}/captures/00000000-0000-7000-8000-000000000000")
    assert response.status_code == 404


# --- steps 6.5, 6.6: the pipeline and background runs -----------------------


async def _analyse(client: AsyncClient, tmp_path: Path) -> dict:
    capture = await _upload(client, tmp_path)
    started = await client.post(f"{API_PREFIX}/captures/{capture['id']}/analyze")
    assert started.status_code == 202, started.text
    run_id = started.json()["runId"]
    await client.app.state.job_runner.wait_for(  # type: ignore[attr-defined]
        __import__("uuid").UUID(run_id)
    )
    run = await client.get(f"{API_PREFIX}/runs/{run_id}")
    return run.json()


async def test_analysis_run_writes_an_assessment(client: AsyncClient, tmp_path: Path) -> None:
    """Step 6.5 Done-when: an Assessment row plus its findings and SA rows."""
    run = await _analyse(client, tmp_path)
    assert run["status"] == "succeeded", run
    assert run["assessmentId"] is not None

    document = await client.get(f"{API_PREFIX}/assessments/{run['assessmentId']}")
    assert document.status_code == 200
    body = document.json()
    assert body["schema_version"] == "1.0"
    assert len(body["security_associations"]) == 1


async def test_run_status_is_pollable(client: AsyncClient, tmp_path: Path) -> None:
    run = await _analyse(client, tmp_path)
    assert run["progress"] == 1.0
    assert run["finishedAt"] is not None
    assert run["error"] is None


async def test_sse_stream_carries_progress_and_completion(
    client: AsyncClient, tmp_path: Path
) -> None:
    """Step 6.6 Done-when: the events endpoint streams progress live."""
    capture = await _upload(client, tmp_path)
    started = await client.post(f"{API_PREFIX}/captures/{capture['id']}/analyze")
    run_id = started.json()["runId"]

    events: list[str] = []
    async with client.stream("GET", f"{API_PREFIX}/runs/{run_id}/events") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        async with asyncio.timeout(30):
            async for line in response.aiter_lines():
                events.append(line)
                if line.startswith("event: complete"):
                    break

    assert any(line.startswith("event: progress") for line in events)
    assert any(line.startswith("event: complete") for line in events)


async def test_analysis_of_a_missing_file_fails_the_run_not_the_api(
    client: AsyncClient, tmp_path: Path
) -> None:
    capture = await _upload(client, tmp_path)
    for stored in (tmp_path / "captures").glob("*.pcap"):
        stored.unlink()
    response = await client.post(f"{API_PREFIX}/captures/{capture['id']}/analyze")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)


# --- step 6.7: assessment endpoints ----------------------------------------


async def test_findings_filter_by_severity_and_sort_by_penalty(
    client: AsyncClient, tmp_path: Path
) -> None:
    """Step 6.7 Done-when: served from the relational table, no JSON columns."""
    run = await _analyse(client, tmp_path)
    assessment_id = run["assessmentId"]

    everything = await client.get(f"{API_PREFIX}/assessments/{assessment_id}/findings")
    assert everything.status_code == 200
    penalties = [item["penalty"] for item in everything.json()]
    assert penalties == sorted(penalties, reverse=True)

    filtered = await client.get(
        f"{API_PREFIX}/assessments/{assessment_id}/findings",
        params={"severity": ["critical"]},
    )
    assert all(item["severity"] == "critical" for item in filtered.json())


async def test_findings_ascending_order(client: AsyncClient, tmp_path: Path) -> None:
    run = await _analyse(client, tmp_path)
    response = await client.get(
        f"{API_PREFIX}/assessments/{run['assessmentId']}/findings",
        params={"order": "asc"},
    )
    penalties = [item["penalty"] for item in response.json()]
    assert penalties == sorted(penalties)


async def test_findings_for_unknown_assessment_is_404(client: AsyncClient) -> None:
    response = await client.get(
        f"{API_PREFIX}/assessments/00000000-0000-7000-8000-000000000000/findings"
    )
    assert response.status_code == 404


async def test_compare_two_assessments(client: AsyncClient, tmp_path: Path) -> None:
    first = await _analyse(client, tmp_path)
    # A second capture with different bytes, so it is not deduped away.
    path = tmp_path / "other.pcap"
    write_pcap(
        path,
        DLT_EN10MB,
        [
            eth_frame(ipv4_packet("10.1.0.1", "10.1.0.2", 17, udp_packet(500, 500, b"y" * 28))),
            eth_frame(ipv4_packet("10.1.0.1", "10.1.0.2", 50, esp_payload(9, 1))),
        ],
    )
    upload = await client.post(
        f"{API_PREFIX}/captures",
        files={"file": ("other.pcap", path.read_bytes(), "application/octet-stream")},
    )
    started = await client.post(f"{API_PREFIX}/captures/{upload.json()['id']}/analyze")
    await client.app.state.job_runner.wait_for(  # type: ignore[attr-defined]
        __import__("uuid").UUID(started.json()["runId"])
    )
    second_run = (await client.get(f"{API_PREFIX}/runs/{started.json()['runId']}")).json()

    response = await client.get(
        f"{API_PREFIX}/assessments/compare",
        params={"a": first["assessmentId"], "b": second_run["assessmentId"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["a"]["id"] == first["assessmentId"]
    assert isinstance(body["scoreDelta"], int)
    assert any(diff["field"] == "encryption_alg" for diff in body["attributeDiffs"])


async def test_compare_rejects_an_assessment_with_itself(
    client: AsyncClient, tmp_path: Path
) -> None:
    run = await _analyse(client, tmp_path)
    response = await client.get(
        f"{API_PREFIX}/assessments/compare",
        params={"a": run["assessmentId"], "b": run["assessmentId"]},
    )
    assert response.status_code == 422


@pytest.mark.parametrize("path", ["/captures", "/health"])
async def test_endpoints_are_versioned(client: AsyncClient, path: str) -> None:
    assert (await client.get(f"{API_PREFIX}{path}")).status_code == 200
    assert (await client.get(path)).status_code == 404


# --- step 10.4: report endpoints -------------------------------------------


@pytest.mark.parametrize("report_format", ["executive", "technical"])
async def test_report_downloads_as_pdf(
    client: AsyncClient, tmp_path: Path, report_format: str
) -> None:
    """Step 10.4 Done-when: both formats download."""
    run = await _analyse(client, tmp_path)
    response = await client.get(
        f"{API_PREFIX}/assessments/{run['assessmentId']}/report",
        params={"format": report_format},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "attachment" in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF-")


async def test_report_for_unknown_assessment_is_problem_json(client: AsyncClient) -> None:
    response = await client.get(
        f"{API_PREFIX}/assessments/00000000-0000-7000-8000-000000000000/report"
    )
    assert response.status_code == 404
    assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)


async def test_report_rejects_an_unknown_format(client: AsyncClient, tmp_path: Path) -> None:
    run = await _analyse(client, tmp_path)
    response = await client.get(
        f"{API_PREFIX}/assessments/{run['assessmentId']}/report",
        params={"format": "marketing"},
    )
    assert response.status_code == 422
