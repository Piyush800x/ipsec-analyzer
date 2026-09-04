"""Column types that behave identically on PostgreSQL and SQLite.

LLD section 4.1 requires one model set to serve both backends. Most of that is
achieved by avoiding Postgres-only constructs, but timestamps need active help:
Postgres has a real ``TIMESTAMPTZ`` and SQLite has no time zone concept at all.
Left alone, the same row round-trips as an aware datetime on one backend and a
naive one on the other, and the naive value then compares wrong against an aware
one without raising anything a test would notice.

``UtcDateTime`` closes that gap at the type layer, so nothing above the database
has to know which backend it is talking to.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


class UtcDateTime(TypeDecorator[datetime]):
    """A timezone-aware UTC timestamp on every backend.

    On the way in: naive datetimes are rejected outright rather than assumed to
    be UTC, because that assumption is wrong roughly half the time and silently.
    Aware values are converted to UTC.

    On the way out: SQLite returns naive values because it has nowhere to put an
    offset, so UTC is reattached. Postgres already returns aware values in UTC
    and passes through unchanged.
    """

    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(
        self,
        value: datetime | None,
        dialect: Dialect,  # noqa: ARG002 -- required by the TypeDecorator interface
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            msg = (
                "naive datetime reached the database layer. Timestamps are UTC and "
                "timezone-aware everywhere (CLAUDE.md); use datetime.now(tz=UTC)"
            )
            raise ValueError(msg)
        return value.astimezone(UTC)

    def process_result_value(
        self,
        value: datetime | None,
        dialect: Dialect,  # noqa: ARG002 -- required by the TypeDecorator interface
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            # SQLite. The stored value is UTC by construction of the bind side.
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def load_dialect_impl(self, dialect: Dialect) -> Any:
        return dialect.type_descriptor(sa.DateTime(timezone=True))
