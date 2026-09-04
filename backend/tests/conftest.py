"""Shared test fixtures, including the dual-backend database harness.

LLD section 4.1 and section 12: the database layer must behave identically on
PostgreSQL and SQLite, and every test that touches the database runs against
both. That is enforced here rather than left to each test to remember.

SQLite always runs. PostgreSQL runs when ``TEST_POSTGRES_URL`` is set and
reachable, and is skipped with an explicit reason otherwise -- a skipped
Postgres test is visible in the output, whereas a Postgres backend that was
never exercised is not.

To run both locally::

    docker run -d --name ipsec-analyzer-pg \\
      -e POSTGRES_USER=analyzer -e POSTGRES_PASSWORD=analyzer \\
      -e POSTGRES_DB=analyzer_test -p 55432:5432 postgres:16-alpine

    TEST_POSTGRES_URL=postgresql+asyncpg://analyzer:analyzer@localhost:55432/analyzer_test \\
      uv run pytest
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from analyzer.db.session import create_db_engine

if TYPE_CHECKING:
    from _pytest.fixtures import SubRequest

POSTGRES_URL_ENV = "TEST_POSTGRES_URL"
REQUIRE_POSTGRES_ENV = "REQUIRE_POSTGRES"
SKIP_REASON = (
    f"{POSTGRES_URL_ENV} is not set. The dual-backend requirement (LLD 4.1) is "
    "only half-verified without it -- see tests/conftest.py for the one-liner."
)


def postgres_url() -> str | None:
    return os.environ.get(POSTGRES_URL_ENV) or None


@pytest.fixture(params=["sqlite", "postgres"])
def backend(request: SubRequest) -> str:
    """Parametrises a test over both supported backends.

    Skipping the PostgreSQL half is right on a laptop with no server running and
    wrong in CI, where a silently skipped backend leaves a green run that proves
    half of what it claims. ``REQUIRE_POSTGRES=1`` turns the skip into a failure;
    the CI workflow sets it.
    """
    if request.param == "postgres" and postgres_url() is None:
        if os.environ.get(REQUIRE_POSTGRES_ENV):
            pytest.fail(
                f"{REQUIRE_POSTGRES_ENV} is set but {POSTGRES_URL_ENV} is not. "
                "The PostgreSQL backend would have been skipped."
            )
        pytest.skip(SKIP_REASON)
    return str(request.param)


@pytest_asyncio.fixture
async def engine(backend: str, tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """A disposable engine for ``backend``, with a clean schema.

    Postgres reuses one database, so the schema is dropped before and after each
    test rather than relying on a fresh container. SQLite gets a fresh file per
    test from ``tmp_path``.
    """
    # Built through create_db_engine, not create_async_engine, so tests exercise
    # the production engine construction -- including the SQLite foreign-key
    # pragma, without which every ON DELETE CASCADE in the schema is inert and
    # the two backends silently diverge.
    if backend == "sqlite":
        engine = create_db_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    else:
        engine = create_db_engine(postgres_url() or "", poolclass=sa.pool.NullPool)

    from analyzer.db.models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield engine
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()
