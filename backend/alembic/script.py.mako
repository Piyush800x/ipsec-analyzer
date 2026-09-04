"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

A migration is a historical record. It must keep running years from now, so it
depends only on Alembic and SQLAlchemy -- never on ``analyzer.*``, which is free
to be renamed or deleted. ``alembic/env.py`` renders our custom column types as
their SQLAlchemy equivalents to keep that true.

Both directions must succeed on PostgreSQL *and* SQLite. Downgrades are not
optional (CLAUDE.md), and CI runs ``upgrade head`` then ``downgrade base`` on
both backends.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision: str = ${repr(up_revision)}
down_revision: str | Sequence[str] | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    """Upgrade schema."""
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    """Downgrade schema."""
    ${downgrades if downgrades else "pass"}
