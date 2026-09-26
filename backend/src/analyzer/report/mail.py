"""Emailing the finished reports. A user request, outside the implementation plan.

When an analyst gives an address as they start an analysis, the job runner
calls ``ReportMailer.deliver`` once the assessment is persisted. It renders
both PDFs with the same ``render_pdf`` the download endpoint uses, so the
attachment is the exact file the dashboard would hand back, then sends them
over SMTP.

Why SMTP from here, rather than EmailJS in the browser or Nodemailer in the
Next.js server: the run completes in this process and the PDF is rendered in
this process. A browser-side sender only fires while the tab stays open, caps
attachment size, and routes report content through a third party. A Node-side
sender would need the frontend server to learn about run completion, which it
never sees. ``smtplib`` is the standard library, so this adds no dependency.

Everything here is blocking by design, and the runner calls it through
``asyncio.to_thread``. Rendering is CPU-bound native code and ``smtplib`` is
synchronous; making one of them async would not make the whole thing so.
"""

from __future__ import annotations

import smtplib
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from typing import Final
from uuid import UUID

from analyzer.core.config import Settings
from analyzer.core.enums import Severity, SmtpSecurity
from analyzer.core.schema import Assessment
from analyzer.report.render import (
    PdfRenderError,
    ReportFormat,
    render_pdf,
    report_filename,
    top_risks,
)

REPORT_FORMATS: Final[tuple[ReportFormat, ...]] = ("executive", "technical")
"""Both reports go out. They are written for different readers (steps 10.2 and
10.3), and the analyst who asked is often forwarding one of them to the
other reader."""

DEFAULT_PORTS: Final[dict[SmtpSecurity, int]] = {
    SmtpSecurity.STARTTLS: 587,
    SmtpSecurity.SSL: 465,
    SmtpSecurity.NONE: 25,
}

_FORMAT_BLURBS: Final[dict[ReportFormat, str]] = {
    "executive": "Executive summary: the risks and what to do about them, for a non-technical "
    "reader.",
    "technical": "Technical report: every finding with its evidence, and the method's limits.",
}


class ReportEmailError(RuntimeError):
    """The reports could not be emailed.

    The message goes straight to the analyst over SSE, so it says *what*
    failed in terms they can act on or pass to an operator. It never includes
    the server's reply verbatim, which can echo addresses and configuration.
    The original exception is chained for the server log.
    """


@dataclass(frozen=True, slots=True)
class SmtpConfig:
    host: str
    port: int
    sender: str
    security: SmtpSecurity = SmtpSecurity.STARTTLS
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    """Kept out of ``repr`` so a config logged while debugging a failed send
    does not log the credential with it."""
    timeout_s: float = 30.0

    @classmethod
    def from_settings(cls, settings: Settings) -> SmtpConfig | None:
        """``None`` when emailing is not configured, which is the default."""
        if settings.smtp_host is None or settings.smtp_from is None:
            return None
        return cls(
            host=settings.smtp_host,
            port=settings.smtp_port or DEFAULT_PORTS[settings.smtp_security],
            sender=settings.smtp_from,
            security=settings.smtp_security,
            username=settings.smtp_username,
            password=(
                settings.smtp_password.get_secret_value()
                if settings.smtp_password is not None
                else None
            ),
            timeout_s=settings.smtp_timeout_s,
        )


def _body(assessment: Assessment, assessment_id: UUID, dashboard_url: str | None) -> str:
    score = assessment.score
    counts = [
        f"{count} {severity.value}"
        for severity in Severity
        if (count := sum(1 for f in assessment.findings if f.severity is severity))
    ]
    top = top_risks(assessment)

    lines = [
        "The IPsec assessment you asked for is complete.",
        "",
        f"Security score:    {score.total}/100 ({score.rating})",
        f"Metadata exposure: {assessment.metadata_exposure.score}/100 (higher means more leakage)",
        f"Findings:          {', '.join(counts) if counts else 'none'}",
    ]
    if top:
        lines += ["", "Top risks:"]
        lines += [f"  - {finding.title} ({finding.severity.value})" for finding in top]

    lines += ["", "Two reports are attached:"]
    lines += [
        f"  - {report_filename(fmt, assessment_id)}\n    {_FORMAT_BLURBS[fmt]}"
        for fmt in REPORT_FORMATS
    ]
    if dashboard_url:
        lines += [
            "",
            f"View it in the dashboard: {dashboard_url.rstrip('/')}/assessments/{assessment_id}",
        ]
    lines += [
        "",
        f"Assessment {assessment_id}, generated "
        f"{assessment.generated_at.strftime('%Y-%m-%d %H:%M UTC')} "
        f"by engine {assessment.engine_version}.",
    ]
    return "\n".join(lines) + "\n"


def build_message(
    assessment: Assessment,
    assessment_id: UUID,
    attachments: Mapping[ReportFormat, bytes],
    *,
    sender: str,
    recipient: str,
    dashboard_url: str | None = None,
) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = (
        f"IPsec assessment: {assessment.score.rating} ({assessment.score.total}/100)"
    )
    message["From"] = sender
    message["To"] = recipient
    message["Date"] = formatdate(usegmt=True)
    # smtplib adds neither header, and a missing Message-ID counts against a
    # message in most receiving servers' spam scoring.
    message["Message-ID"] = make_msgid(domain=parseaddr(sender)[1].partition("@")[2] or None)
    message.set_content(_body(assessment, assessment_id, dashboard_url))
    for report_format, pdf in attachments.items():
        message.add_attachment(
            pdf,
            maintype="application",
            subtype="pdf",
            filename=report_filename(report_format, assessment_id),
        )
    return message


def send_message(config: SmtpConfig, message: EmailMessage) -> None:
    """Hand ``message`` to the SMTP server, or raise ``ReportEmailError``.

    The ``except`` order matters: every ``smtplib`` exception subclasses
    ``OSError``, so the catch-all for connection failures has to come last.
    ``SMTPNotSupportedError`` is caught at each call instead, because
    ``starttls()`` and ``login()`` both raise it and only the call site says
    which of the two the server lacks.
    """
    context = ssl.create_default_context()
    try:
        client = (
            smtplib.SMTP_SSL(config.host, config.port, timeout=config.timeout_s, context=context)
            if config.security is SmtpSecurity.SSL
            else smtplib.SMTP(config.host, config.port, timeout=config.timeout_s)
        )
        with client:
            if config.security is SmtpSecurity.STARTTLS:
                try:
                    client.starttls(context=context)
                except smtplib.SMTPNotSupportedError as exc:
                    msg = "The mail server does not support STARTTLS; check SMTP_SECURITY."
                    raise ReportEmailError(msg) from exc
            if config.username is not None and config.password is not None:
                try:
                    client.login(config.username, config.password)
                except smtplib.SMTPNotSupportedError as exc:
                    msg = (
                        "The mail server does not accept logins on this connection; check "
                        "SMTP_SECURITY, or unset SMTP_USERNAME and SMTP_PASSWORD."
                    )
                    raise ReportEmailError(msg) from exc
            client.send_message(message)
    except smtplib.SMTPAuthenticationError as exc:
        msg = "The mail server rejected this server's SMTP credentials."
        raise ReportEmailError(msg) from exc
    except smtplib.SMTPRecipientsRefused as exc:
        msg = "The mail server refused the recipient address."
        raise ReportEmailError(msg) from exc
    except smtplib.SMTPSenderRefused as exc:
        msg = "The mail server refused this server's sender address."
        raise ReportEmailError(msg) from exc
    except smtplib.SMTPException as exc:
        msg = "The mail server did not accept the message."
        raise ReportEmailError(msg) from exc
    except OSError as exc:
        # Refused, unresolvable, timed out, or a TLS handshake failure.
        msg = "Could not connect to the mail server."
        raise ReportEmailError(msg) from exc


class ReportMailer:
    """Renders both reports for an assessment and emails them."""

    def __init__(
        self, config: SmtpConfig, *, rule_count: int, dashboard_url: str | None = None
    ) -> None:
        self._config = config
        self._rule_count = rule_count
        self._dashboard_url = dashboard_url

    def deliver(self, assessment: Assessment, assessment_id: UUID, recipient: str) -> None:
        """Blocking. Call through ``asyncio.to_thread``."""
        try:
            attachments = {
                fmt: render_pdf(assessment, fmt, rule_count=self._rule_count)
                for fmt in REPORT_FORMATS
            }
        except PdfRenderError as exc:
            msg = "The reports could not be rendered as PDFs, so there was nothing to attach."
            raise ReportEmailError(msg) from exc

        message = build_message(
            assessment,
            assessment_id,
            attachments,
            sender=self._config.sender,
            recipient=recipient,
            dashboard_url=self._dashboard_url,
        )
        send_message(self._config, message)
