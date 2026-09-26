"""Phase 6: the API, the job runner and the pipeline, end to end.

Every test drives a real FastAPI app over ASGI against a throwaway SQLite
file, with the job runner running inline rather than in a process pool -- the
pool is exercised separately in ``test_api_jobs.py`` where its cost is paid
once.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.pool import NullPool

from analyzer.api.errors import PROBLEM_CONTENT_TYPE
from analyzer.api.jobs import RunEvent
from analyzer.api.main import API_PREFIX, create_app
from analyzer.core.config import Settings
from analyzer.core.enums import SmtpSecurity
from analyzer.db.models import Base
from analyzer.db.session import create_db_engine
from tests._pcap import DLT_EN10MB, esp_payload, eth_frame, ipv4_packet, udp_packet, write_pcap
from tests._smtp import SmtpSink
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


def _settings(backend: str, tmp_path: Path, **overrides: object) -> Settings:
    fields: dict[str, object] = {
        "database_url": _database_url(backend, tmp_path),
        "storage_path": tmp_path / "captures",
        "policy_path": BASELINE,
        "model_dir": tmp_path / "models",
        "max_upload_bytes": 64 * 1024 * 1024,
        "max_concurrent_analyses": 2,
        # Explicit, and no .env read at all: a developer's real SMTP settings
        # must never reach a test. They did once -- the email tests sent a
        # real Gmail username and App Password to the loopback test sink,
        # which then failed for a reason that had nothing to do with the code.
        "_env_file": None,
        "smtp_host": None,
        "smtp_username": None,
        "smtp_password": None,
        "dashboard_url": None,
        **overrides,
    }
    return Settings(**fields)  # type: ignore[arg-type] # keys are Settings fields


@asynccontextmanager
async def _serve(settings: Settings) -> AsyncIterator[AsyncClient]:
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


@pytest_asyncio.fixture
async def client(backend: str, tmp_path: Path) -> AsyncIterator[AsyncClient]:
    """The API, over ASGI, against whichever backend `backend` selected.

    Step 11.2: the full API suite runs on SQLite *and* PostgreSQL. The
    dual-backend requirement (LLD section 4.1) is about the whole stack, not
    just the model layer -- an endpoint that works on SQLite and not on
    Postgres is exactly the failure that survives a model-only test.
    """
    async with _serve(_settings(backend, tmp_path)) as http:
        yield http


MAIL_RECIPIENT = "analyst@example.com"


@pytest_asyncio.fixture
async def mailing_client(
    backend: str, tmp_path: Path, smtp_sink: SmtpSink
) -> AsyncIterator[AsyncClient]:
    """The same API with emailed reports switched on, delivering to `smtp_sink`."""
    settings = _settings(
        backend,
        tmp_path,
        smtp_host="127.0.0.1",
        smtp_port=smtp_sink.port,
        smtp_security=SmtpSecurity.NONE,
        smtp_from="IPsec Analyzer <reports@analyzer.test>",
        smtp_timeout_s=5.0,
        dashboard_url="http://dashboard.test",
    )
    async with _serve(settings) as http:
        yield http


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


# --- cross-platform: PDFs render with or without WeasyPrint -----------------


def _without_weasyprint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make this machine look like stock Windows: no GTK, so no WeasyPrint.
    On a machine that really has no GTK this changes nothing, which is fine;
    on Linux CI it is what makes the fallback path run at all."""
    monkeypatch.setattr("analyzer.report.render._weasyprint", lambda: None)


async def test_report_renders_html(client: AsyncClient, tmp_path: Path) -> None:
    """``?inline=1`` is pure Jinja2, the fastest way to look at a template."""
    run = await _analyse(client, tmp_path)
    response = await client.get(
        f"{API_PREFIX}/assessments/{run['assessmentId']}/report",
        params={"format": "technical", "inline": 1},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<html" in response.text.lower()


@pytest.mark.parametrize("report_format", ["executive", "technical"])
async def test_report_downloads_as_pdf_without_weasyprint(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, report_format: str
) -> None:
    """This was a 503 naming the GTK3 runtime. A download button that works
    only after an operator installs a desktop toolkit does not work."""
    _without_weasyprint(monkeypatch)
    run = await _analyse(client, tmp_path)
    response = await client.get(
        f"{API_PREFIX}/assessments/{run['assessmentId']}/report",
        params={"format": report_format},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")


# --- emailed reports ---------------------------------------------------------


async def _start(client: AsyncClient, tmp_path: Path, **request: object) -> str:
    capture = await _upload(client, tmp_path)
    started = await client.post(f"{API_PREFIX}/captures/{capture['id']}/analyze", **request)
    assert started.status_code == 202, started.text
    return str(started.json()["runId"])


async def _events(client: AsyncClient, run_id: str) -> list[RunEvent]:
    """Everything the run emitted, via the bus's replay of a finished run."""
    runner = client.app.state.job_runner  # type: ignore[attr-defined]
    await runner.wait_for(UUID(run_id))
    return [event async for event in runner.bus.subscribe(UUID(run_id))]


async def test_an_address_is_refused_when_this_server_cannot_email(
    client: AsyncClient, tmp_path: Path
) -> None:
    """Refused before the run, not discovered after it: an analyst told "we
    will email it" and then sent nothing has been told something false."""
    capture = await _upload(client, tmp_path)
    response = await client.post(
        f"{API_PREFIX}/captures/{capture['id']}/analyze", json={"notifyEmail": MAIL_RECIPIENT}
    )

    assert response.status_code == 503
    assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)
    body = response.json()
    assert body["capability"] == "email"
    assert "SMTP_HOST" in body["detail"]
    assert client.app.state.job_runner.queued_or_running == 0  # type: ignore[attr-defined]


async def test_a_malformed_address_is_a_422(mailing_client: AsyncClient, tmp_path: Path) -> None:
    capture = await _upload(mailing_client, tmp_path)
    response = await mailing_client.post(
        f"{API_PREFIX}/captures/{capture['id']}/analyze", json={"notifyEmail": "not-an-address"}
    )

    assert response.status_code == 422
    assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)
    assert any("notifyEmail" in error["loc"] for error in response.json()["errors"])


async def test_an_empty_json_body_starts_an_ordinary_run(
    client: AsyncClient, tmp_path: Path
) -> None:
    """The dashboard now always sends a JSON body, and `{}` when no address
    was given. That must behave exactly like the bodiless POST it replaced."""
    events = await _events(client, await _start(client, tmp_path, json={}))

    assert events[-1].event == "complete"
    assert "email" not in events[-1].data


async def test_a_completed_run_emails_both_reports(
    mailing_client: AsyncClient, smtp_sink: SmtpSink, tmp_path: Path
) -> None:
    run_id = await _start(mailing_client, tmp_path, json={"notifyEmail": MAIL_RECIPIENT})
    events = await _events(mailing_client, run_id)

    stages = [event.data["stage"] for event in events if event.event == "progress"]
    assert stages[-1] == "report"
    complete = events[-1]
    assert complete.event == "complete"
    assert complete.data["email"] == {"status": "sent"}

    assessment_id = complete.data["assessmentId"]
    [received] = smtp_sink.received
    assert received.rcpt_tos == [MAIL_RECIPIENT]
    attachments = list(received.message.iter_attachments())
    assert [a.get_filename() for a in attachments] == [
        f"ipsec-executive-{assessment_id}.pdf",
        f"ipsec-technical-{assessment_id}.pdf",
    ]
    assert all(a.get_content().startswith(b"%PDF-") for a in attachments)
    body = received.message.get_body(preferencelist=("plain",))
    assert body is not None
    assert f"http://dashboard.test/assessments/{assessment_id}" in body.get_content()


async def test_an_address_is_accepted_and_emailed_without_weasyprint(
    mailing_client: AsyncClient,
    smtp_sink: SmtpSink,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reported bug. On Windows without GTK, giving an address on the
    capture page was refused with a 503 about the GTK3 runtime, before the run
    even started. The portable engine renders the attachments instead."""
    _without_weasyprint(monkeypatch)
    run_id = await _start(mailing_client, tmp_path, json={"notifyEmail": MAIL_RECIPIENT})
    events = await _events(mailing_client, run_id)

    assert events[-1].event == "complete"
    assert events[-1].data["email"] == {"status": "sent"}
    [received] = smtp_sink.received
    attachments = [a.get_content() for a in received.message.iter_attachments()]
    assert len(attachments) == 2
    assert all(pdf.startswith(b"%PDF-") for pdf in attachments)


async def test_a_failed_email_does_not_fail_the_run(
    mailing_client: AsyncClient, smtp_sink: SmtpSink, tmp_path: Path
) -> None:
    """The assessment is persisted before sending starts, so the analyst still
    gets it -- and the run still *completes*, which is the part that matters:
    no `complete` event would leave the dashboard waiting forever."""
    smtp_sink.refuse[MAIL_RECIPIENT] = "550 5.1.1 No such user"
    run_id = await _start(mailing_client, tmp_path, json={"notifyEmail": MAIL_RECIPIENT})
    events = await _events(mailing_client, run_id)

    complete = events[-1]
    assert complete.event == "complete"
    assert complete.data["email"]["status"] == "failed"
    assert "recipient" in complete.data["email"]["detail"]
    assert smtp_sink.received == []

    run = await mailing_client.get(f"{API_PREFIX}/runs/{run_id}")
    assert run.json()["status"] == "succeeded"
    document = await mailing_client.get(f"{API_PREFIX}/assessments/{complete.data['assessmentId']}")
    assert document.status_code == 200


async def test_a_run_without_an_address_sends_nothing(
    mailing_client: AsyncClient, smtp_sink: SmtpSink, tmp_path: Path
) -> None:
    """Configuring SMTP makes emailing *possible*; only the analyst's own
    request makes it happen."""
    events = await _events(mailing_client, await _start(mailing_client, tmp_path))

    assert "email" not in events[-1].data
    assert all(event.data.get("stage") != "report" for event in events)
    assert smtp_sink.received == []
