"""Alembic environment. Steps 1.6 and 1.7.

Two things here are not boilerplate and matter a great deal.

**Migrations run against the DIRECT connection string, never the pooled one.**
Neon's pooled endpoint runs PgBouncer in transaction mode, which cannot hold the
session-level locks DDL takes. Migrations through the pooler do not fail
cleanly; they fail intermittently and look like network flakiness, which is a
day lost before anyone suspects the endpoint. So this file reads
``DATABASE_URL_DIRECT`` and only falls back to ``DATABASE_URL`` when it is
unset -- which is the correct behaviour for SQLite, where there is no such
distinction.

**``render_as_batch`` is on for SQLite.** SQLite cannot ``ALTER COLUMN`` or drop
a constraint; Alembic's batch mode rewrites the table instead. Without it, the
first migration that alters anything runs on Postgres and fails on SQLite, and
the offline compose file (LLD section 13) stops working.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from analyzer.db.models import Base
from analyzer.db.types import UtcDateTime

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def database_url() -> str:
    """The URL migrations run against.

    Direct endpoint first. Raising rather than defaulting is deliberate: a
    default would silently migrate the wrong database, and "which database did
    that DDL land on" is not a question anyone wants to answer after the fact.
    """
    url = os.environ.get("DATABASE_URL_DIRECT") or os.environ.get("DATABASE_URL")
    if not url:
        msg = (
            "Neither DATABASE_URL_DIRECT nor DATABASE_URL is set. Alembic needs "
            "the DIRECT Neon endpoint (the host without '-pooler'), or a SQLite "
            "URL for offline work. See .env.example and docs/database-setup.md."
        )
        raise RuntimeError(msg)
    return url


def render_item(
    type_: str,
    obj: object,
    autogen_context: object,  # noqa: ARG001 -- required by Alembic's hook signature
) -> str | bool:
    """Render custom column types as their plain SQLAlchemy equivalent.

    A migration is a historical record that has to keep running long after the
    code it was generated from has moved. Emitting
    ``analyzer.db.types.UtcDateTime()`` into a version file couples every past
    migration to a module that is free to be renamed, and the import error
    surfaces as a broken ``downgrade base`` at the worst possible moment.

    ``UtcDateTime``'s ``impl`` is ``DateTime(timezone=True)``, so the DDL is
    identical either way -- the Python-side conversion the decorator adds is a
    runtime concern that migrations do not need.
    """
    if type_ == "type" and isinstance(obj, UtcDateTime):
        return "sa.DateTime(timezone=True)"
    return False


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        render_item=render_item,
        # SQLite cannot ALTER COLUMN or drop a constraint in place.
        render_as_batch=connection.dialect.name == "sqlite",
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting. ``alembic upgrade head --sql``."""
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = database_url()

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
