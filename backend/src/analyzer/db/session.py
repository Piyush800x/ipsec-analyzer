"""Engine and session construction. LLD section 4.2.

Most of this file is one function, and almost all of that function is defending
against two Neon behaviours that each cost a day to diagnose from the symptom.

**PgBouncer breaks asyncpg's prepared statements.** Neon's pooled endpoint runs
PgBouncer in transaction mode, which hands a different backend connection to the
client between statements. asyncpg prepares statements and caches them by name;
the next statement lands on a connection that has never seen that name, and the
result is an intermittent ``InvalidSQLStatementNameError`` or
``DuplicatePreparedStatementError`` that only shows up under concurrency and
looks like a network fault. Three settings are needed together, and disabling
one cache while leaving the other is the usual half-fix.

**Neon scales to zero.** After a few minutes idle the compute suspends. Pooled
connections that were fine a moment ago are dead, and the next query fails
before the cold start even begins. ``pool_pre_ping`` validates a connection
before handing it out; ``pool_recycle`` retires them before the idle timeout can.

SQLite gets its own defence: foreign keys are off by default, so every
``ON DELETE CASCADE`` in the schema is silently inert until the pragma is set.
That is exactly the kind of divergence LLD section 4.1 forbids -- deleting a
capture would cascade on Postgres and orphan rows on SQLite.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from analyzer.core.ids import new_id

POOL_RECYCLE_SECONDS = 280
"""Retire connections before Neon's idle timeout can kill them underneath us."""


def is_pooled_postgres(url: str) -> bool:
    """Whether this URL points at a transaction-mode connection pooler.

    Neon spells it with ``-pooler`` in the hostname. Any Neon host is treated as
    pooled as well: the cost of disabling a statement cache that did not need
    disabling is a little repeated parse work, and the cost of the reverse is an
    API that fails under load in a way nobody reproduces locally.
    """
    if "+asyncpg" not in url:
        return False
    return "-pooler" in url or "neon.tech" in url


def _asyncpg_connect_args() -> dict[str, Any]:
    """The three settings that make asyncpg survive PgBouncer.

    ``statement_cache_size=0`` disables asyncpg's own cache.
    ``prepared_statement_cache_size=0`` disables the second cache SQLAlchemy's
    asyncpg dialect keeps on top of it -- disabling only one leaves the other
    holding stale names.
    ``prepared_statement_name_func`` stops even a single-use prepared statement
    from colliding: asyncpg names them ``__asyncpg_stmt_1__`` and counts from
    zero per connection, so two clients sharing a pooled backend generate the
    same name.
    """
    return {
        "statement_cache_size": 0,
        "prepared_statement_cache_size": 0,
        "prepared_statement_name_func": lambda: f"__asyncpg_{new_id()}__",
    }


def engine_options(url: str, **overrides: Any) -> dict[str, Any]:
    """The keyword arguments ``create_async_engine`` should get for ``url``.

    Split out from ``create_db_engine`` so it can be asserted on directly.
    SQLAlchemy bakes engine-level ``connect_args`` into a closure with no public
    accessor, so a test that builds an engine cannot check what it was given --
    and "the Neon settings are applied" is exactly the thing that must not
    regress silently.
    """
    options: dict[str, Any] = dict(overrides)

    if url.startswith("sqlite"):
        # aiosqlite takes none of the pooling or asyncpg arguments below, and
        # handing it one is an immediate TypeError.
        return options

    if is_pooled_postgres(url):
        caller_args: dict[str, Any] = options.get("connect_args", {})
        options["connect_args"] = {**_asyncpg_connect_args(), **caller_args}

    options.setdefault("pool_pre_ping", True)
    options.setdefault("pool_recycle", POOL_RECYCLE_SECONDS)
    return options


def create_db_engine(url: str, *, echo: bool = False, **kwargs: Any) -> AsyncEngine:
    """Build an engine appropriate to whichever backend ``url`` names.

    Takes the URL explicitly rather than reaching for settings, so tests and the
    Alembic environment can point it wherever they need without an environment
    variable in the way.
    """
    engine = create_async_engine(url, echo=echo, **engine_options(url, **kwargs))
    if engine.dialect.name == "sqlite":
        _enable_sqlite_foreign_keys(engine)
    return engine


def _enable_sqlite_foreign_keys(engine: AsyncEngine) -> None:
    """Turn on foreign key enforcement for every SQLite connection.

    SQLite ships with foreign keys disabled for backwards compatibility, per
    connection and not per database. Without this, every ``ON DELETE CASCADE``
    in ``db/models.py`` is decorative on the offline backend: deleting a capture
    leaves its runs, assessments and findings behind, and nothing complains.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _set_pragma(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def engine_from_settings(**kwargs: Any) -> AsyncEngine:
    """The application's engine, built from ``core.config``.

    Uses ``database_url`` -- the POOLED endpoint. Alembic reaches for
    ``migration_url`` instead, which is the direct one; getting those two
    backwards is the failure mode ``docs/database-setup.md`` opens with.
    """
    # Imported inside the function so that importing db.session does not pull
    # in settings, and so tests can build engines against arbitrary URLs
    # without DATABASE_URL being set at all.
    from analyzer.core.config import get_settings

    return create_db_engine(get_settings().database_url, **kwargs)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Session factory for the API and the pipeline.

    ``expire_on_commit=False`` because the request handler reads attributes off
    an object after the transaction closes; the default would issue a refresh
    against a connection that has already gone back to the pool.
    """
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


@asynccontextmanager
async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """A session wrapped in one transaction, committed on success.

    The write path in step 6.5 populates ``assessments``, ``findings`` and
    ``security_associations`` together; LLD section 4.3 requires that to be one
    transaction, because a half-written assessment is worse than none.
    """
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def check_connection(engine: AsyncEngine) -> bool:
    """Whether the database answers. Backs ``/api/v1/health`` (step 6.1).

    On Neon this doubles as the cold-start trigger, so a health check after an
    idle period may take noticeably longer than one against a warm compute.
    """
    async with engine.connect() as conn:
        result = await conn.scalar(sa.text("SELECT 1"))
    return bool(result == 1)
