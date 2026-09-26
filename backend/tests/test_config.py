"""Step 1.8 -- settings load, and a misconfiguration fails at startup.

Done-when: the app refuses to start with a clear error when ``DATABASE_URL`` is
unset. "Clear" is treated as a testable property here -- the message must name
the variable, point at ``.env.example``, and offer the offline fallback -- because
an error that only says "Field required" satisfies the letter of the requirement
and helps nobody.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from analyzer.core.config import ConfigurationError, Settings, get_settings

ENV_VARS = (
    "DATABASE_URL",
    "DATABASE_URL_DIRECT",
    "STORAGE_PATH",
    "POLICY_PATH",
    "MODEL_DIR",
    "MAX_UPLOAD_BYTES",
    "MAX_CONCURRENT_ANALYSES",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_SECURITY",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_FROM",
    "DASHBOARD_URL",
)

SQLITE_URL = "sqlite+aiosqlite:///./data/analyzer.db"


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """A clean environment with no ``.env`` in reach.

    Settings read the repository's own ``.env`` when one exists, which would make
    these tests pass or fail depending on whose machine they run on.
    """
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setitem(Settings.model_config, "env_file", (tmp_path / "absent.env",))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# --------------------------------------------------------------------------
# The Done-when
# --------------------------------------------------------------------------


def test_missing_database_url_refuses_to_start() -> None:
    with pytest.raises(ConfigurationError) as exc_info:
        get_settings()

    message = str(exc_info.value)
    assert "DATABASE_URL is not set" in message
    assert "cannot start" in message


def test_the_error_says_how_to_fix_it() -> None:
    """A clear error names the file to copy and gives a working fallback."""
    with pytest.raises(ConfigurationError) as exc_info:
        get_settings()

    message = str(exc_info.value)
    assert ".env.example" in message
    assert "sqlite+aiosqlite" in message
    assert "docs/database-setup.md" in message


def test_settings_load_when_database_url_is_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    settings = get_settings()
    assert settings.database_url == SQLITE_URL


# --------------------------------------------------------------------------
# Defaults, from LLD section 9
# --------------------------------------------------------------------------


def test_defaults_match_the_lld(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    settings = get_settings()
    assert settings.max_upload_bytes == 2 * 1024**3
    assert settings.max_concurrent_analyses == 2
    assert settings.storage_path == Path("./data/captures")
    assert settings.model_dir == Path("./models")


def test_every_setting_is_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    monkeypatch.setenv("STORAGE_PATH", "/srv/captures")
    monkeypatch.setenv("POLICY_PATH", "/etc/analyzer/high-assurance.yaml")
    monkeypatch.setenv("MODEL_DIR", "/srv/models")
    monkeypatch.setenv("MAX_UPLOAD_BYTES", "1048576")
    monkeypatch.setenv("MAX_CONCURRENT_ANALYSES", "8")

    settings = get_settings()
    assert settings.storage_path == Path("/srv/captures")
    assert settings.policy_path == Path("/etc/analyzer/high-assurance.yaml")
    assert settings.model_dir == Path("/srv/models")
    assert settings.max_upload_bytes == 1_048_576
    assert settings.max_concurrent_analyses == 8


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MAX_UPLOAD_BYTES", "0"),
        ("MAX_UPLOAD_BYTES", "-1"),
        ("MAX_CONCURRENT_ANALYSES", "0"),
    ],
)
def test_nonsensical_limits_are_rejected(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigurationError, match=name):
        get_settings()


# --------------------------------------------------------------------------
# The three URL mistakes worth their own message
# --------------------------------------------------------------------------


def test_synchronous_driver_url_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Copied from the Neon console or a psql line, and the real failure would
    otherwise surface much later as a sync-engine error."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@ep-x-pooler.neon.tech/db")
    with pytest.raises(ConfigurationError, match="not an async driver"):
        get_settings()


def test_libpq_sslmode_spelling_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """asyncpg raises 'unexpected keyword argument sslmode'; this says which
    word to change."""
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+asyncpg://u:p@ep-x-pooler.neon.tech/db?sslmode=require",
    )
    with pytest.raises(ConfigurationError, match=re.escape("ssl=require")):
        get_settings()


def test_the_asyncpg_ssl_spelling_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "postgresql+asyncpg://u:p@ep-x-pooler.neon.tech/db?ssl=require"
    monkeypatch.setenv("DATABASE_URL", url)
    assert get_settings().database_url == url


def test_direct_url_is_validated_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """Alembic uses this one, and a broken migration URL is discovered at the
    worst possible moment."""
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    monkeypatch.setenv("DATABASE_URL_DIRECT", "postgresql://u:p@ep-x.neon.tech/db")
    with pytest.raises(ConfigurationError, match="not an async driver"):
        get_settings()


# --------------------------------------------------------------------------
# Derived properties
# --------------------------------------------------------------------------


def test_migration_url_prefers_the_direct_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    pooled = "postgresql+asyncpg://u:p@ep-x-pooler.neon.tech/db?ssl=require"
    direct = "postgresql+asyncpg://u:p@ep-x.neon.tech/db?ssl=require"
    monkeypatch.setenv("DATABASE_URL", pooled)
    monkeypatch.setenv("DATABASE_URL_DIRECT", direct)

    settings = get_settings()
    assert settings.migration_url == direct
    assert settings.database_url == pooled


def test_migration_url_falls_back_when_there_is_no_direct_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Correct for SQLite, which has no pooled/direct distinction."""
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    assert get_settings().migration_url == SQLITE_URL


def test_offline_posture_is_reported_honestly(monkeypatch: pytest.MonkeyPatch) -> None:
    """LLD section 13: on Neon, assessment metadata leaves the machine even
    though PCAP bytes do not. Which posture is in effect should not be a guess."""
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    assert get_settings().is_offline is True

    get_settings.cache_clear()
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@ep-x-pooler.neon.tech/db")
    assert get_settings().is_offline is False


def test_settings_are_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    assert get_settings() is get_settings()


# --------------------------------------------------------------------------
# Emailed reports: a half-configured mailer fails at startup, not mid-run
# --------------------------------------------------------------------------


def test_smtp_host_without_a_sender_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Otherwise the first analyst to ask for an email finds out, a minute into
    their run, that it was never going to be sent."""
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")

    with pytest.raises(ConfigurationError) as exc_info:
        get_settings()

    message = str(exc_info.value)
    assert "SMTP_FROM is not" in message
    assert "Value error" not in message  # pydantic's prefix, stripped for the reader


def test_smtp_username_without_a_password_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "reports@example.com")
    monkeypatch.setenv("SMTP_USERNAME", "reports@example.com")

    with pytest.raises(ConfigurationError, match="SMTP_USERNAME and SMTP_PASSWORD"):
        get_settings()


def test_smtp_settings_load_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_SECURITY", "ssl")
    monkeypatch.setenv("SMTP_FROM", "IPsec Analyzer <reports@example.com>")
    monkeypatch.setenv("SMTP_USERNAME", "reports@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")

    settings = get_settings()
    assert settings.smtp_security == "ssl"
    assert settings.smtp_password is not None
    assert settings.smtp_password.get_secret_value() == "app-password"
