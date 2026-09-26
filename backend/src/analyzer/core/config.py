"""Application settings. Step 1.8.

Everything the process needs to know that is not code. Read once at startup from
the environment and a ``.env`` file, validated eagerly, and then immutable.

The design principle is that a misconfiguration fails at startup with a message
that says what to do, rather than at the first request with a stack trace from
somewhere inside a driver. Three failures are common enough to deserve their own
message:

- ``DATABASE_URL`` unset. Pydantic's own "Field required" is technically correct
  and tells nobody where to look.
- A synchronous driver URL. ``postgresql://`` instead of ``postgresql+asyncpg://``
  is copied straight from a Neon console or a psql command line, and the failure
  surfaces much later as an ``InvalidRequestError`` about a sync engine.
- ``?sslmode=require``. That is libpq's spelling; asyncpg raises
  ``connect() got an unexpected keyword argument 'sslmode'`` and the fix is one
  word away, but only if you already know it.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Self

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from analyzer.core.enums import SmtpSecurity

_CORE_DIR = Path(__file__).resolve().parent
_BACKEND_DIR = _CORE_DIR.parents[2]
_REPO_ROOT = _BACKEND_DIR.parent

ASYNC_DRIVERS = ("postgresql+asyncpg://", "sqlite+aiosqlite://")
"""The only two URL schemes this application can drive.

Everything below the API is async, so a synchronous driver does not degrade
gracefully -- it fails at the first query with an error that does not mention
the URL at all.
"""


class ConfigurationError(RuntimeError):
    """The process cannot start with the configuration it was given.

    Deliberately not an HTTP error: nothing is serving yet when this is raised,
    so there is nobody to hand an RFC 9457 document to.
    """


class Settings(BaseSettings):
    """Runtime configuration, loaded from the environment and ``.env``.

    Field names are lowercase; pydantic-settings matches them case-insensitively
    against ``DATABASE_URL``, ``STORAGE_PATH`` and so on. ``.env`` is read from
    the repository root and then from ``backend/``, so a single file at the top
    of the tree serves both the API and anything run from ``backend/``.
    """

    model_config = SettingsConfigDict(
        env_file=(_REPO_ROOT / ".env", _BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    database_url: str = Field(
        ...,
        description="Async SQLAlchemy URL. Neon's POOLED endpoint in normal operation.",
    )
    """Required, and deliberately without a default.

    A default would mean the application quietly comes up against the wrong
    database -- usually a local SQLite file that looks empty rather than broken.
    """

    database_url_direct: str | None = Field(
        default=None,
        description="Neon's DIRECT endpoint. Alembic only; the API never uses it.",
    )
    """Migrations take session-level locks that PgBouncer's transaction mode
    cannot hold, so DDL goes to the direct endpoint (docs/database-setup.md)."""

    storage_path: Path = Field(
        default=Path("./data/captures"),
        description="Where PCAP files live. They never enter the database.",
    )

    policy_path: Path = Field(
        default=Path("./src/analyzer/assess/policies/baseline.yaml"),
        description="Assessment policy file (LLD 8.1). Editable without code changes.",
    )

    model_dir: Path = Field(
        default=Path("./models"),
        description="Trained Track B artefacts, DVC-tracked.",
    )

    max_upload_bytes: int = Field(
        default=2 * 1024**3,
        gt=0,
        description="Upload cap. 2 GB per LLD section 9.",
    )

    max_concurrent_analyses: int = Field(
        default=2,
        ge=1,
        description="Bounds concurrent pipeline runs (LLD section 9).",
    )

    smtp_host: str | None = Field(
        default=None,
        description="SMTP server for emailed reports. Unset disables emailing entirely.",
    )
    """Off by default, and the offline stack leaves it off. Emailing a report
    sends assessment content off this machine, which NFR-6 otherwise rules out,
    so it takes an operator setting this *and* an analyst asking per run."""

    smtp_port: int | None = Field(
        default=None,
        gt=0,
        le=65535,
        description="Defaults to 587 for starttls, 465 for ssl, 25 for none.",
    )

    smtp_security: SmtpSecurity = Field(default=SmtpSecurity.STARTTLS)

    smtp_username: str | None = Field(default=None)

    smtp_password: SecretStr | None = Field(default=None)

    smtp_from: str | None = Field(
        default=None,
        description="From: header, e.g. 'IPsec Analyzer <reports@example.com>'.",
    )
    """Required whenever ``smtp_host`` is set, rather than falling back to the
    username: SendGrid's username is the literal ``apikey`` and a From: header
    of ``apikey`` is rejected by every receiving server worth sending to."""

    smtp_timeout_s: float = Field(default=30.0, gt=0)

    dashboard_url: str | None = Field(
        default=None,
        description="Public URL of the dashboard, linked from emailed reports.",
    )

    @field_validator("database_url", "database_url_direct")
    @classmethod
    def _check_driver(cls, value: str | None) -> str | None:
        """Reject a URL this application cannot actually drive."""
        if value is None:
            return None

        if not value.startswith(ASYNC_DRIVERS):
            msg = (
                f"{value.split('://')[0]}:// is not an async driver. Use "
                "postgresql+asyncpg:// or sqlite+aiosqlite://. A URL copied from "
                "the Neon console or a psql command line needs '+asyncpg' adding."
            )
            raise ValueError(msg)

        if "asyncpg" in value and "sslmode=" in value:
            msg = (
                "asyncpg does not understand 'sslmode', which is libpq's spelling. "
                "Use '?ssl=require' instead. Neon's console gives you the libpq form."
            )
            raise ValueError(msg)

        return value

    @model_validator(mode="after")
    def _check_smtp(self) -> Self:
        """A half-configured mailer fails here, not at the end of someone's run."""
        if self.smtp_host is None:
            return self
        if not self.smtp_from:
            msg = "SMTP_HOST is set but SMTP_FROM is not. Set the address reports are sent from."
            raise ValueError(msg)
        if (self.smtp_username is None) != (self.smtp_password is None):
            msg = "SMTP_USERNAME and SMTP_PASSWORD must be set together, or both left unset."
            raise ValueError(msg)
        return self

    @property
    def migration_url(self) -> str:
        """The URL Alembic runs against: direct endpoint, falling back to the
        only one configured."""
        return self.database_url_direct or self.database_url

    @property
    def is_offline(self) -> bool:
        """Whether this process is running fully local, on SQLite.

        NFR-6 says captures are processed locally with no external service call.
        Neon is a hosted database, so while PCAP bytes never leave the machine,
        assessment metadata would. This is the flag that tells the truth about
        which posture is in effect (LLD section 13).
        """
        return self.database_url.startswith("sqlite")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load and validate settings once.

    Re-raises validation failures as ``ConfigurationError`` with a message aimed
    at whoever has to fix it. Cached, so import order does not change how many
    times the environment is read; call ``get_settings.cache_clear()`` in tests.
    """
    try:
        return Settings()
    except ValidationError as exc:
        raise ConfigurationError(_explain(exc)) from exc


def _explain(exc: ValidationError) -> str:
    """Turn a pydantic report into instructions."""
    lines = ["Configuration error. The application cannot start.", ""]
    for error in exc.errors():
        field = ".".join(str(part) for part in error["loc"])
        env_name = field.upper()
        if not field:
            # A model validator spanning several variables; its message names them.
            lines.append(f"  {str(error['msg']).removeprefix('Value error, ')}")
        elif error["type"] == "missing":
            lines.append(f"  {env_name} is not set.")
        else:
            lines.append(f"  {env_name}: {error['msg']}")
    lines += [
        "",
        "Copy .env.example to .env at the repository root and fill it in.",
        "For offline or CI use, DATABASE_URL=sqlite+aiosqlite:///./data/analyzer.db",
        "is enough. See docs/database-setup.md for the Neon pooled/direct split.",
    ]
    return "\n".join(lines)
