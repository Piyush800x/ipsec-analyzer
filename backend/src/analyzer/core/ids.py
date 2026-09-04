"""UUIDv7 identifier generation.

LLD section 1: every entity primary key is a UUIDv7. Version 7 embeds a
millisecond Unix timestamp in its high bits, so identifiers sort chronologically
as byte strings. That gives ``ORDER BY id`` a meaningful order, keeps B-tree
inserts append-only instead of scattering them the way UUIDv4 does, and removes
the need for a separate sequence column purely to establish "which came first".

The stdlib gained ``uuid.uuid7()`` only in Python 3.14; on 3.11 we take it from
the ``uuid6`` package. It returns a plain ``uuid.UUID``, so SQLAlchemy's
``sa.Uuid`` and Pydantic's ``UUID`` both accept it with no adapter.
"""

from __future__ import annotations

from uuid import UUID

from uuid6 import uuid7


def new_id() -> UUID:
    """Return a fresh UUIDv7.

    The single entry point for identifier creation. Never call ``uuid.uuid4()``
    directly -- a v4 key in a v7 column destroys the time ordering that the rest
    of the system assumes, and does so invisibly.
    """
    return uuid7()


def timestamp_ms(value: UUID) -> int:
    """Extract the embedded Unix timestamp, in milliseconds, from a UUIDv7.

    Useful for debugging and for asserting ordering in tests. Raises for any
    other UUID version, because the high bits mean something different there and
    reading them as a time would produce a plausible, wrong answer.
    """
    if value.version != 7:
        msg = f"expected a UUIDv7, got version {value.version}"
        raise ValueError(msg)
    return value.int >> 80
