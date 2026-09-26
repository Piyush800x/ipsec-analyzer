"""Emailed reports: the message, the SMTP conversation, and how it fails.

Every send goes to a real SMTP server on a loopback socket (tests/_smtp.py),
so these prove the attachments survive the wire rather than that ``smtplib``
was called. What is *not* exercised here is TLS: STARTTLS and implicit TLS
need a certificate a loopback sink does not have, and are covered by MT-29
against a real provider instead.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from analyzer.core.config import Settings
from analyzer.core.enums import SmtpSecurity
from analyzer.core.schema import Assessment
from analyzer.report.mail import (
    DEFAULT_PORTS,
    ReportEmailError,
    ReportMailer,
    SmtpConfig,
    build_message,
    send_message,
)
from analyzer.report.render import (
    PDF_BACKEND_HINT,
    PdfBackendUnavailableError,
    pdf_backend_available,
    report_filename,
    top_risks,
)
from tests._smtp import SmtpSink, free_port, throwaway_credential

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ASSESSMENT_ID = UUID("01920000-0000-7000-8000-00000000abcd")
SENDER = "IPsec Analyzer <reports@analyzer.test>"
RECIPIENT = "analyst@example.com"
FAKE_PDFS = {"executive": b"%PDF-1.7 executive body", "technical": b"%PDF-1.7 technical body"}

needs_pdf_backend = pytest.mark.skipif(
    not pdf_backend_available(),
    reason="WeasyPrint's native libraries are not installed; see render.PDF_BACKEND_HINT",
)


def _weak() -> Assessment:
    return Assessment.model_validate_json((FIXTURES / "assessment_weak.json").read_text())


def _config(port: int, **overrides: object) -> SmtpConfig:
    fields: dict[str, object] = {
        "host": "127.0.0.1",
        "port": port,
        "sender": SENDER,
        "security": SmtpSecurity.NONE,
        "timeout_s": 5.0,
        **overrides,
    }
    return SmtpConfig(**fields)  # type: ignore[arg-type] # the dict is built to match


# --- the message -------------------------------------------------------------


def test_both_reports_are_attached_under_their_download_names() -> None:
    """The emailed file must be the file the dashboard's download button gives."""
    message = build_message(_weak(), ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT)
    attachments = list(message.iter_attachments())

    assert [a.get_filename() for a in attachments] == [
        report_filename("executive", ASSESSMENT_ID),
        report_filename("technical", ASSESSMENT_ID),
    ]
    assert {a.get_content_type() for a in attachments} == {"application/pdf"}
    assert [a.get_content() for a in attachments] == list(FAKE_PDFS.values())


def test_subject_and_body_lead_with_the_score() -> None:
    weak = _weak()
    message = build_message(weak, ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT)
    body = message.get_body(preferencelist=("plain",))
    assert body is not None
    text = body.get_content()

    assert message["Subject"] == (f"IPsec assessment: {weak.score.rating} ({weak.score.total}/100)")
    assert f"{weak.score.total}/100 ({weak.score.rating})" in text
    assert f"Metadata exposure: {weak.metadata_exposure.score}/100" in text


def test_body_names_the_same_top_risks_as_the_executive_report() -> None:
    weak = _weak()
    message = build_message(weak, ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT)
    body = message.get_body(preferencelist=("plain",))
    assert body is not None
    text = body.get_content()

    risks = top_risks(weak)
    assert risks, "the weak fixture exists to have findings"
    for finding in risks:
        assert finding.title in text


def test_dashboard_link_appears_only_when_a_dashboard_is_configured() -> None:
    def text(url: str | None) -> str:
        message = build_message(
            _weak(), ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT, dashboard_url=url
        )
        body = message.get_body(preferencelist=("plain",))
        assert body is not None
        return str(body.get_content())

    assert "dashboard" not in text(None)
    assert f"https://vpn-audit.example/assessments/{ASSESSMENT_ID}" in text(
        "https://vpn-audit.example/"
    )


def test_headers_a_receiving_server_expects_are_present() -> None:
    message = build_message(_weak(), ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT)

    assert message["From"] == SENDER
    assert message["To"] == RECIPIENT
    assert message["Date"]
    assert message["Message-ID"].endswith("@analyzer.test>")


# --- the SMTP conversation -----------------------------------------------------


def test_the_message_survives_a_real_smtp_conversation(smtp_sink: SmtpSink) -> None:
    message = build_message(_weak(), ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT)
    send_message(_config(smtp_sink.port), message)

    [received] = smtp_sink.received
    assert received.mail_from == "reports@analyzer.test"
    assert received.rcpt_tos == [RECIPIENT]
    assert [a.get_content() for a in received.message.iter_attachments()] == list(
        FAKE_PDFS.values()
    )


@pytest.mark.filterwarnings("ignore:Requiring AUTH while not requiring TLS")
def test_credentials_are_used_when_configured() -> None:
    message = build_message(_weak(), ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT)
    login, secret = throwaway_credential(), throwaway_credential()
    with SmtpSink(credentials=(login, secret)) as sink:
        send_message(_config(sink.port, username=login, password=secret), message)
        assert len(sink.received) == 1


@pytest.mark.filterwarnings("ignore:Requiring AUTH while not requiring TLS")
def test_wrong_credentials_are_reported_as_such() -> None:
    message = build_message(_weak(), ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT)
    login, secret = throwaway_credential(), throwaway_credential()
    with SmtpSink(credentials=(login, secret)) as sink:
        with pytest.raises(ReportEmailError, match="credentials"):
            send_message(
                _config(sink.port, username=login, password=throwaway_credential()), message
            )
        assert sink.received == []


def test_a_server_without_login_is_not_blamed_on_starttls(smtp_sink: SmtpSink) -> None:
    """``starttls()`` and ``login()`` raise the same exception when the server
    lacks the feature. Reporting both as a STARTTLS problem sent an operator
    to check the wrong setting; this is the case that did it."""
    message = build_message(_weak(), ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT)
    config = _config(
        smtp_sink.port, username=throwaway_credential(), password=throwaway_credential()
    )

    with pytest.raises(ReportEmailError, match="does not accept logins") as exc_info:
        send_message(config, message)

    assert "STARTTLS" not in str(exc_info.value)
    assert smtp_sink.received == []


def test_a_refused_recipient_is_reported_without_echoing_the_server(
    smtp_sink: SmtpSink,
) -> None:
    """The message reaches the analyst verbatim, so it must not carry the
    server's reply, which is free text the server's operator controls."""
    smtp_sink.refuse[RECIPIENT] = "550 5.1.1 mailbox-internal-7731 does not exist"
    message = build_message(_weak(), ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT)

    with pytest.raises(ReportEmailError, match="recipient") as exc_info:
        send_message(_config(smtp_sink.port), message)

    assert "mailbox-internal-7731" not in str(exc_info.value)
    assert smtp_sink.received == []


def test_an_unreachable_server_is_a_report_email_error() -> None:
    message = build_message(_weak(), ASSESSMENT_ID, FAKE_PDFS, sender=SENDER, recipient=RECIPIENT)
    with pytest.raises(ReportEmailError, match="connect"):
        send_message(_config(free_port()), message)


# --- the mailer: render, then send ---------------------------------------------


@needs_pdf_backend
def test_the_mailer_sends_both_rendered_pdfs(smtp_sink: SmtpSink) -> None:
    ReportMailer(_config(smtp_sink.port), rule_count=14).deliver(_weak(), ASSESSMENT_ID, RECIPIENT)

    [received] = smtp_sink.received
    pdfs = [a.get_content() for a in received.message.iter_attachments()]
    assert len(pdfs) == 2
    for pdf in pdfs:
        assert pdf.startswith(b"%PDF-")
        assert pdf.rstrip().endswith(b"%%EOF")


def test_without_a_pdf_backend_nothing_is_sent(
    smtp_sink: SmtpSink, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An email promising two reports and carrying none is worse than no email."""

    def _no_backend(*args: object, **kwargs: object) -> bytes:
        raise PdfBackendUnavailableError(PDF_BACKEND_HINT)

    monkeypatch.setattr("analyzer.report.mail.render_pdf", _no_backend)
    mailer = ReportMailer(_config(smtp_sink.port), rule_count=14)

    with pytest.raises(ReportEmailError, match="PDF rendering"):
        mailer.deliver(_weak(), ASSESSMENT_ID, RECIPIENT)
    assert smtp_sink.received == []


# --- configuration -----------------------------------------------------------


def _settings(**overrides: object) -> Settings:
    # No .env, and SMTP off unless the test says otherwise: a developer's own
    # SMTP settings must not decide what these assertions see.
    fields: dict[str, object] = {"smtp_host": None, **overrides}
    return Settings(
        _env_file=None,
        database_url="sqlite+aiosqlite:///:memory:",
        **fields,  # type: ignore[arg-type] # keys are Settings fields
    )


def test_emailing_is_off_unless_an_operator_turns_it_on() -> None:
    assert SmtpConfig.from_settings(_settings()) is None


@pytest.mark.parametrize("security", list(SmtpSecurity))
def test_the_port_defaults_to_the_one_the_security_mode_uses(security: SmtpSecurity) -> None:
    config = SmtpConfig.from_settings(
        _settings(smtp_host="mail.example", smtp_from=SENDER, smtp_security=security)
    )
    assert config is not None
    assert config.port == DEFAULT_PORTS[security]


def test_an_explicit_port_wins() -> None:
    config = SmtpConfig.from_settings(
        _settings(smtp_host="mail.example", smtp_from=SENDER, smtp_port=2525)
    )
    assert config is not None
    assert config.port == 2525


def test_the_password_is_unwrapped_only_at_the_last_moment() -> None:
    secret = throwaway_credential()
    settings = _settings(
        smtp_host="mail.example",
        smtp_from=SENDER,
        smtp_username=throwaway_credential(),
        smtp_password=secret,
    )
    assert secret not in repr(settings)
    config = SmtpConfig.from_settings(settings)
    assert config is not None
    assert secret not in repr(config)
    assert config.password == secret
