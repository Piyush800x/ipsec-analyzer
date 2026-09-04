# Backend

Python 3.11+, managed with [uv](https://docs.astral.sh/uv/). Layout follows
[LLD §2](../docs/LLD.md). Modules carrying only a docstring are skeletons for a
later phase — see [docs/implementation-plan.md](../docs/implementation-plan.md).

## Setup

```bash
uv sync                       # create .venv and install locked dependencies
cp ../.env.example ../.env    # then fill it in
```

The only required setting is `DATABASE_URL`. For offline work:

```
DATABASE_URL=sqlite+aiosqlite:///./data/analyzer.db
```

## Checks

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

`../scripts/ci-local.sh` runs exactly what CI runs, backend and frontend.

## Testing against both backends

The database layer must behave identically on PostgreSQL and SQLite
([LLD §4.1](../docs/LLD.md)). `tests/conftest.py` parametrises every database
test over both, and **skips the PostgreSQL half unless `TEST_POSTGRES_URL` is
set** — so a green run on a laptop with no server proves only half of what it
looks like it proves.

```bash
../scripts/pg-dev.sh up
export TEST_POSTGRES_URL="$(../scripts/pg-dev.sh url)"
uv run pytest
../scripts/pg-dev.sh down
```

CI sets `REQUIRE_POSTGRES=1` alongside the URL, which turns a skipped PostgreSQL
backend into a failure rather than a silent gap.

## Migrations

Alembic reads `DATABASE_URL_DIRECT` and falls back to `DATABASE_URL`. On Neon
that distinction matters: DDL takes session-level locks PgBouncer's transaction
mode cannot hold, so migrations go to the **direct** endpoint while the API uses
the **pooled** one. See [docs/database-setup.md](../docs/database-setup.md).

```bash
uv run alembic upgrade head
uv run alembic downgrade base     # must also succeed, on both backends
uv run alembic revision --autogenerate -m "what changed"
uv run alembic check              # fails if the models have drifted from head
```

## Docker image

Carries the pinned `tshark` that Track A shells out to. The version is recorded
in three places — the `Dockerfile`, `pyproject.toml` under
`[tool.ipsec-analyzer.external-tools]`, and asserted by
`tests/test_tshark_version.py` — because Wireshark's JSON field names change
across releases and a drift breaks the parser silently rather than loudly.

```bash
docker build -t ipsec-analyzer-backend:0.1.0 .
docker run --rm ipsec-analyzer-backend:0.1.0 tshark --version
```

The build fails with an unmet-dependency error when Debian rotates the pinned
package out of the archive. That failure is the point: bump the pin
deliberately and re-run the Track A tests, rather than relaxing it.
