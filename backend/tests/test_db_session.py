"""Step 1.7 -- the session factory, including the Neon handling from LLD 4.2.

The Done-when is a smoke test against Neon's pooled endpoint that executes a
query without a prepared-statement error. That needs a live Neon URL, so it runs
when ``NEON_POOLED_URL`` is set and is skipped, loudly, when it is not.

Everything that can be checked without Neon is checked without Neon: that the
pooled-endpoint settings are actually applied, that the same query works
repeatedly on a real Postgres connection (the pattern that fails under
PgBouncer if the caches are left on), and that SQLite enforces the foreign keys
the schema depends on.
"""

from __future__ import annotations

import os

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from analyzer.core.enums import RunStatus
from analyzer.core.ids import new_id
from analyzer.db.models import AnalysisRun, Capture
from analyzer.db.session import (
    POOL_RECYCLE_SECONDS,
    check_connection,
    create_db_engine,
    create_session_factory,
    engine_options,
    is_pooled_postgres,
    session_scope,
)
from tests.conftest import postgres_url
from tests.test_db_models import _rows

NEON_URL_ENV = "NEON_POOLED_URL"
NEON_SKIP = (
    f"{NEON_URL_ENV} is not set. Step 1.7's Done-when -- a session against the "
    "Neon POOLED endpoint executing a query with no prepared-statement error -- "
    "cannot be demonstrated without a live Neon URL."
)


# --------------------------------------------------------------------------
# Neon detection and the settings it turns on
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://u:p@ep-cool-hat-12345-pooler.eu-central-1.aws.neon.tech/db",
        "postgresql+asyncpg://u:p@ep-cool-hat-12345.eu-central-1.aws.neon.tech/db",
        "postgresql+asyncpg://u:p@pgbouncer-pooler.internal:6432/db",
    ],
)
def test_pooled_postgres_is_detected(url: str) -> None:
    assert is_pooled_postgres(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://u:p@localhost:5432/db",
        "sqlite+aiosqlite:///./data/analyzer.db",
        "postgresql+psycopg://u:p@ep-x-pooler.neon.tech/db",
    ],
)
def test_ordinary_urls_are_not_treated_as_pooled(url: str) -> None:
    assert is_pooled_postgres(url) is False


def test_pooled_engine_disables_both_statement_caches() -> None:
    """LLD section 4.2. Disabling one cache and not the other is the usual
    half-fix, and it fails only under concurrency."""
    url = "postgresql+asyncpg://u:p@ep-x-pooler.eu-central-1.aws.neon.tech/db"
    connect_args = engine_options(url)["connect_args"]

    assert connect_args["statement_cache_size"] == 0
    assert connect_args["prepared_statement_cache_size"] == 0

    # Names must be unique across connections that share a pooled backend.
    name_func = connect_args["prepared_statement_name_func"]
    assert name_func() != name_func()


def test_pooled_engine_sets_pre_ping_and_recycle() -> None:
    """Neon scales to zero; a pooled connection that was fine a minute ago is
    dead, and the query after an idle period fails without these."""
    options = engine_options("postgresql+asyncpg://u:p@ep-x-pooler.neon.tech/db")
    assert options["pool_pre_ping"] is True
    assert options["pool_recycle"] == POOL_RECYCLE_SECONDS


def test_sqlite_engine_does_not_get_asyncpg_arguments() -> None:
    """Handing asyncpg kwargs to aiosqlite is an immediate TypeError, which is
    how a shared code path between the two backends usually announces itself."""
    options = engine_options("sqlite+aiosqlite:///./data/x.db")
    assert "connect_args" not in options
    assert "pool_pre_ping" not in options
    assert "pool_recycle" not in options


# --------------------------------------------------------------------------
# The Done-when: a live session against the Neon POOLED endpoint
# --------------------------------------------------------------------------


@pytest.mark.neon
@pytest.mark.skipif(not os.environ.get(NEON_URL_ENV), reason=NEON_SKIP)
async def test_neon_pooled_session_executes_without_prepared_statement_error() -> None:
    """Step 1.7's Done-when.

    Repeats the same parameterised statement across several connections. That is
    the shape that trips PgBouncer's transaction pooling: the first execution
    prepares a statement, and a later one lands on a backend that has never seen
    the name.
    """
    url = os.environ[NEON_URL_ENV]
    assert is_pooled_postgres(url), f"{NEON_URL_ENV} should be the POOLED endpoint"

    engine = create_db_engine(url)
    try:
        assert await check_connection(engine) is True

        factory = create_session_factory(engine)
        for i in range(10):
            async with factory() as session:
                value = await session.scalar(sa.text("SELECT :n * 2"), {"n": i})
                assert value == i * 2
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------
# Everything the Done-when implies, on the backends available locally
# --------------------------------------------------------------------------


async def test_check_connection_reports_reachability(engine: AsyncEngine) -> None:
    assert await check_connection(engine) is True


async def test_repeated_parameterised_statements_succeed(engine: AsyncEngine) -> None:
    """The same pattern as the Neon test, run on whichever backends are here.

    On plain Postgres this always passes; it is the regression guard for anyone
    who later "simplifies" the connect arguments away.
    """
    factory = create_session_factory(engine)
    for i in range(10):
        async with factory() as session:
            assert await session.scalar(sa.text("SELECT :n * 2"), {"n": i}) == i * 2


@pytest.mark.skipif(postgres_url() is None, reason="TEST_POSTGRES_URL is not set")
async def test_pooled_settings_do_not_break_a_real_postgres() -> None:
    """The pooled connect arguments are applied to a real server, not just
    inspected. A setting asyncpg rejects would fail at connect time."""
    from analyzer.db.session import _asyncpg_connect_args

    url = postgres_url() or ""
    engine = create_db_engine(url, connect_args=_asyncpg_connect_args())
    try:
        factory = create_session_factory(engine)
        for i in range(10):
            async with factory() as session:
                assert await session.scalar(sa.text("SELECT :n + 1"), {"n": i}) == i + 1
    finally:
        await engine.dispose()


async def test_session_scope_commits_on_success(engine: AsyncEngine) -> None:
    factory = create_session_factory(engine)
    capture, *_ = _rows()

    async with session_scope(factory) as session:
        session.add(capture)

    async with factory() as session:
        assert await session.get(Capture, capture.id) is not None


async def test_session_scope_rolls_back_on_failure(engine: AsyncEngine) -> None:
    """A half-written assessment is worse than none (LLD section 4.3)."""
    factory = create_session_factory(engine)
    capture, *_ = _rows()

    async def add_then_fail() -> None:
        async with session_scope(factory) as session:
            session.add(capture)
            await session.flush()
            msg = "pipeline failed"
            raise RuntimeError(msg)

    with pytest.raises(RuntimeError, match="pipeline failed"):
        await add_then_fail()

    async with factory() as session:
        assert await session.get(Capture, capture.id) is None


# --------------------------------------------------------------------------
# SQLite foreign keys -- off by default, and every CASCADE depends on them
# --------------------------------------------------------------------------


async def test_orphan_insert_is_rejected_on_both_backends(engine: AsyncEngine) -> None:
    """A run pointing at a capture that does not exist must be refused.

    SQLite ships with foreign keys disabled per connection, so without the
    ``PRAGMA foreign_keys=ON`` that ``create_db_engine`` installs, this insert
    succeeds on SQLite and fails on Postgres -- precisely the divergence LLD
    section 4.1 forbids, and the same pragma is what makes every ON DELETE
    CASCADE in the schema real.
    """
    factory = create_session_factory(engine)
    orphan = AnalysisRun(
        id=new_id(),
        capture_id=new_id(),  # no such capture
        status=RunStatus.QUEUED,
        engine_version="0.1.0",
        policy_version="1.0",
        model_versions={},
    )

    async def insert_orphan() -> None:
        async with factory() as session, session.begin():
            session.add(orphan)

    with pytest.raises(IntegrityError, match=r"(?i)foreign key"):
        await insert_orphan()


async def test_cascade_delete_works_on_both_backends(engine: AsyncEngine) -> None:
    """Deleting a capture must take its runs, assessment, findings and SAs with
    it -- identically on both backends."""
    factory = create_session_factory(engine)
    capture, run, assessment, finding, sa_row = _rows()

    async with session_scope(factory) as session:
        session.add_all([capture, run, assessment, finding, sa_row])

    async with session_scope(factory) as session:
        stored = await session.get(Capture, capture.id)
        assert stored is not None
        await session.delete(stored)

    async with factory() as session:
        for table in ("analysis_runs", "assessments", "findings", "security_associations"):
            remaining = await session.scalar(sa.text(f"SELECT count(*) FROM {table}"))
            assert remaining == 0, table
