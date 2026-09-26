"""A real SMTP server on a loopback socket, for the emailed-report tests.

aiosmtpd rather than a mock of ``smtplib``. A mock proves the code calls the
methods it was written to call. A server proves the message survives an actual
SMTP conversation (EHLO, AUTH, the envelope, DATA's dot-stuffing and the
base64 round trip of two PDF attachments), which is where a mailer actually
breaks.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from email import message_from_bytes, policy
from email.message import EmailMessage
from types import TracebackType
from typing import Any, cast

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, AuthResult, Envelope, LoginPassword, Session


def free_port() -> int:
    """A loopback port nothing is listening on, as of this call."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@dataclass(frozen=True, slots=True)
class Received:
    mail_from: str
    rcpt_tos: list[str]
    message: EmailMessage


class SmtpSink:
    """Accepts mail and keeps it. ``refuse`` makes RCPT TO fail per address."""

    def __init__(self, *, credentials: tuple[str, str] | None = None) -> None:
        self.received: list[Received] = []
        self.refuse: dict[str, str] = {}
        """Address -> the SMTP reply that refuses it."""
        self.port = free_port()
        self._credentials = credentials
        auth: dict[str, Any] = (
            {
                "authenticator": self._authenticate,
                "auth_required": True,
                # smtplib only sends AUTH over TLS if the server demands TLS
                # first; a loopback test has no certificate to offer.
                "auth_require_tls": False,
            }
            if credentials is not None
            else {}
        )
        self._controller = Controller(self, hostname="127.0.0.1", port=self.port, **auth)

    def __enter__(self) -> SmtpSink:
        self._controller.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._controller.stop()

    def _authenticate(
        self, server: SMTP, session: Session, envelope: Envelope, mechanism: str, auth_data: object
    ) -> AuthResult:
        if not isinstance(auth_data, LoginPassword) or self._credentials is None:
            return AuthResult(success=False, handled=False)
        login, password = self._credentials
        ok = auth_data.login.decode() == login and auth_data.password.decode() == password
        return AuthResult(success=ok, handled=False)

    async def handle_RCPT(  # noqa: N802 - aiosmtpd dispatches on this exact name
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        if address in self.refuse:
            return self.refuse[address]
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(  # noqa: N802 - aiosmtpd dispatches on this exact name
        self, server: SMTP, session: Session, envelope: Envelope
    ) -> str:
        content = envelope.original_content or b""
        self.received.append(
            Received(
                mail_from=str(envelope.mail_from),
                rcpt_tos=list(envelope.rcpt_tos),
                message=cast(EmailMessage, message_from_bytes(content, policy=policy.default)),
            )
        )
        return "250 Message accepted for delivery"
