# Database setup

Companion to [LLD.md](LLD.md) §4. Covers implementation-plan steps 0.5, 1.6 and 1.7.

The database layer must behave **identically** on PostgreSQL and SQLite. Postgres
(Neon) is the default; SQLite is the offline, air-gapped, demo-laptop and CI backend.
Anything that works on only one of them is a bug, not a trade-off.

---

## 1. Neon project (step 0.5)

One Neon project for the team, one **database branch per developer** so nobody is
fighting over a shared schema while Alembic revisions are still churning.

1. Create the project at <https://console.neon.tech>. Region: whichever is nearest
   the team. Postgres 16.
2. Name the default branch `main`. Nothing should ever be migrated against it by
   hand — it is what CI and the demo point at.
3. For each developer, create a branch off `main` named `dev/<name>`. Neon branches
   are copy-on-write, so this is instant and costs nothing.
4. From that branch's **Connection Details** panel, copy **both** connection
   strings — the pooled one and the direct one. They differ by `-pooler` in the
   hostname.
5. `cp .env.example .env` and fill in `DATABASE_URL` (pooled),
   `DATABASE_URL_DIRECT` (direct) and `NEON_BRANCH`.

### Verifying your branch

```bash
psql "postgresql://<user>:<password>@ep-<id>.<region>.aws.neon.tech/<db>?sslmode=require" -c 'SELECT 1'
```

Note `postgresql://` and `sslmode=require` for `psql` — that is libpq's spelling.
The application uses `postgresql+asyncpg://` and `ssl=require`, which is not the
same thing. See §3.

---

## 2. Pooled vs direct — which goes where

| Consumer | Endpoint | Why |
|---|---|---|
| API / application | **pooled** (`-pooler`) | Neon scales to zero and connections are expensive; PgBouncer amortises them |
| Alembic migrations | **direct** | DDL takes session-level locks that PgBouncer's transaction mode cannot hold |
| `psql` for a quick look | either | direct is simpler |

Getting this backwards does not fail loudly. Migrations through the pooler fail
intermittently and look like network flakiness. `alembic/env.py` therefore reads
`DATABASE_URL_DIRECT` and falls back to `DATABASE_URL` only when it is unset.

---

## 3. Three Neon gotchas

**PgBouncer breaks asyncpg's prepared-statement cache.** In transaction mode a
connection is handed to a different client between statements, so a statement
prepared on one is not there on the next. asyncpg caches prepared statements by
default and raises `InvalidSQLStatementNameError` or
`DuplicatePreparedStatementError` under load. `db/session.py` passes
`statement_cache_size=0` for pooled endpoints. This is not a performance
optimisation to revisit later — without it, the API breaks under concurrency.

**Neon scales to zero.** After ~5 minutes idle the compute suspends. The next
query pays a cold start of a few hundred milliseconds, and a connection that was
sitting in the pool is dead. `pool_pre_ping=True` makes SQLAlchemy validate a
connection before handing it out; `pool_recycle=280` retires connections before
the idle timeout can kill them.

**`sslmode` is libpq, not asyncpg.** Neon's console gives you
`?sslmode=require`. Handing that to `postgresql+asyncpg://` raises
`connect() got an unexpected keyword argument 'sslmode'`. Use `?ssl=require`.

---

## 4. Offline / SQLite

```bash
DATABASE_URL=sqlite+aiosqlite:///./data/analyzer.db
DATABASE_URL_DIRECT=sqlite+aiosqlite:///./data/analyzer.db
```

This is the mode to demo on (LLD §13): no cold start, no network, and it is the
honest answer to NFR-6 when a security audience asks whether assessment metadata
leaves the machine.

---

## 5. Migrations (step 1.6)

```bash
cd backend
uv run alembic upgrade head      # uses DATABASE_URL_DIRECT
uv run alembic downgrade base    # must also succeed -- downgrades are not optional
```

Both directions must run cleanly on **both** backends. CI enforces it.

The models use `sa.JSON`, never `JSONB`. Postgres gets `JSONB` from a
dialect-guarded step inside the migration, so SQLite never sees a type it cannot
create and the model definitions stay backend-neutral.

---

## 6. Local PostgreSQL for testing

You do not need Neon to satisfy the dual-backend rule locally. A throwaway
container is enough, and `scripts/pg-dev.sh` manages it:

```bash
./scripts/pg-dev.sh up
export TEST_POSTGRES_URL="$(./scripts/pg-dev.sh url)"
cd backend && uv run pytest        # now runs every DB test twice
./scripts/pg-dev.sh down
```

It listens on **55432**, not 5432, so it cannot collide with a PostgreSQL you
actually depend on.

Without `TEST_POSTGRES_URL` the PostgreSQL half of every database test is
skipped, and the run is green having verified half of what it claims. CI sets
`REQUIRE_POSTGRES=1` so that a skip becomes a failure there.

To exercise the migration round trip against it:

```bash
export DATABASE_URL_DIRECT="$(./scripts/pg-dev.sh url)"
cd backend
uv run alembic upgrade head
uv run alembic downgrade base
```

The `JSON` to `JSONB` promotion is visible on PostgreSQL only:

```sql
SELECT table_name, column_name, data_type
FROM information_schema.columns
WHERE table_schema = 'public' AND data_type IN ('json', 'jsonb');
```

All six JSON columns should read `jsonb` after `upgrade head`. On SQLite the
same columns read `JSON`, which is the whole point of keeping `sa.JSON` in the
models and doing the promotion in a dialect-guarded migration step.
