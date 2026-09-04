# Getting set up

From a fresh machine to a passing test suite. Should take about fifteen minutes,
most of it downloads.

If something goes wrong, jump to [§8 Troubleshooting](#8-troubleshooting) — every
entry there is a failure someone has actually hit, not a hypothetical.

---

## 1. Prerequisites

| Tool | Version | Needed for | Install |
|---|---|---|---|
| **git** | any recent | everything | <https://git-scm.com/downloads> |
| **uv** | 0.5+ | the backend | <https://docs.astral.sh/uv/getting-started/installation/> |
| **Node.js** | 22 LTS or newer | the frontend | <https://nodejs.org/> |
| **Docker Desktop** | any recent | container image, local PostgreSQL | <https://www.docker.com/products/docker-desktop/> |

You do **not** need Python installed. `uv` reads `backend/.python-version` and
fetches Python 3.11 itself.

You do **not** need PostgreSQL installed. SQLite covers everything except the
dual-backend tests, and `scripts/pg-dev.sh` runs PostgreSQL in a container when
you want it.

Docker is optional for day-to-day work. It is needed only for the backend image
(which carries the pinned `tshark`) and for the local PostgreSQL.

```bash
git --version
uv --version
node --version          # v22 or newer
docker info             # should print server details, not a connection error
```

---

## 2. Clone

```bash
git clone https://github.com/Piyush800x/ipsec-analyzer.git
cd ipsec-analyzer
```

---

## 3. Configure

```bash
cp .env.example .env
```

Now open `.env` and choose one of two paths.

### Offline (recommended to start)

Everything runs locally on SQLite. No account, no network, no cold starts. This
is also the configuration to demo on.

```
DATABASE_URL=sqlite+aiosqlite:///./data/analyzer.db
DATABASE_URL_DIRECT=sqlite+aiosqlite:///./data/analyzer.db
```

Leave the rest of the file at its defaults.

### Neon (the team default)

Two URLs, and **they are not interchangeable**:

```
DATABASE_URL=postgresql+asyncpg://<user>:<pw>@ep-<id>-pooler.<region>.aws.neon.tech/<db>?ssl=require
DATABASE_URL_DIRECT=postgresql+asyncpg://<user>:<pw>@ep-<id>.<region>.aws.neon.tech/<db>?ssl=require
NEON_BRANCH=dev/<your-name>
```

`DATABASE_URL` is the **pooled** endpoint — the hostname *with* `-pooler` — and
the application uses it. `DATABASE_URL_DIRECT` is the **direct** endpoint, and
only Alembic uses it, because DDL takes session-level locks that PgBouncer's
transaction mode cannot hold.

Two things to fix as you paste from the Neon console:

- Change `postgresql://` to `postgresql+asyncpg://`.
- Change `?sslmode=require` to `?ssl=require`. `sslmode` is libpq's spelling and
  asyncpg does not understand it.

Settings validation rejects both mistakes at startup with a message saying which
word to change, so you will not get far with them wrong.

Ask the project lead for a Neon branch of your own — one per developer, so
nobody is fighting over a shared schema while migrations are still churning.
[docs/database-setup.md](docs/database-setup.md) §1 has the full procedure.

---

## 4. Backend

```bash
cd backend
mkdir -p data          # SQLite will not create the directory itself
uv sync
```

`uv sync` builds `.venv/`, fetches Python 3.11 if needed, and installs from
`uv.lock`. Then create the schema:

```bash
uv run alembic upgrade head
```

Expect one line: `Running upgrade  -> 6173d44f0cce, initial schema`.

Check it worked:

```bash
uv run python -c "import analyzer; print(analyzer.__version__)"     # 0.1.0
uv run pytest -q
```

Expect **`206 passed, 15 skipped`**. All fifteen skips are expected here: thirteen
are the PostgreSQL half of the dual-backend database tests, which need a server
you have not started yet (§7 turns those on and the count becomes
`219 passed, 2 skipped`); one needs a live Neon URL; one runs inside the
container image instead.

> **Never `pip install` into this environment.** Add dependencies with
> `uv add <package>` so `pyproject.toml` and `uv.lock` stay authoritative, and
> run everything through `uv run`.

---

## 5. Frontend

```bash
cd ../frontend
npm ci
npm run dev
```

Open <http://localhost:3000>. You will see the stock Next.js page — the
dashboard is Phase 7 and does not exist yet. What this confirms is that the
toolchain works.

```bash
npx tsc --noEmit
npm run lint
npm run build
```

---

## 6. Verify the whole thing

One command runs exactly what CI runs:

```bash
cd ..
./scripts/ci-local.sh
```

Expect `CI-LOCAL: PASSED` with ruff, ruff-format, mypy, pytest, `tsc --noEmit`,
ESLint and `next build` all reporting `PASS`.

Keep this in your muscle memory — it is the difference between "works on my
machine" and "will pass review".

---

## 7. Optional extras

### Local PostgreSQL, for the dual-backend tests

The database layer must behave **identically on PostgreSQL and SQLite**, and
every database test runs against both. But the PostgreSQL half is *skipped* when
`TEST_POSTGRES_URL` is unset, so a green run on a laptop with no server proves
only half of what it appears to.

```bash
./scripts/pg-dev.sh up
export TEST_POSTGRES_URL="$(./scripts/pg-dev.sh url)"

cd backend && uv run pytest -q          # now runs every DB test twice

cd .. && ./scripts/pg-dev.sh down
```

The count moves from `206 passed, 15 skipped` to `219 passed, 2 skipped`. If it
does not move, the URL did not take — see the last entry in §8.

It listens on **55432**, not 5432, so it cannot collide with a PostgreSQL you
actually depend on. CI sets `REQUIRE_POSTGRES=1` alongside the URL, which turns
a skipped backend into a failure.

### The backend container image

Carries the pinned `tshark` that Track A will shell out to.

```bash
cd backend
docker build -t ipsec-analyzer-backend:0.1.0 .
docker run --rm ipsec-analyzer-backend:0.1.0 tshark --version
```

Expect `TShark (Wireshark) 4.4.18.` — matching `pyproject.toml` under
`[tool.ipsec-analyzer.external-tools]`, which `tests/test_tshark_version.py`
asserts. Wireshark's JSON field names change between releases and break the
parser silently rather than loudly, which is why the version is pinned in three
places that must agree.

### Editor

Point your editor at `backend/.venv` as the interpreter. `.editorconfig` handles
indentation and line endings. Ruff is the only formatter — do not also enable
Black or isort, they will fight.

---

## 8. Troubleshooting

### `unable to open database file` (SQLite)

The `data/` directory does not exist. SQLite will not create it.

```bash
cd backend && mkdir -p data
```

### `connect() got an unexpected keyword argument 'sslmode'`

Your URL uses libpq's spelling. Change `?sslmode=require` to `?ssl=require`.

### `postgresql:// is not an async driver`

Change the scheme to `postgresql+asyncpg://`. Everything below the API is async,
and a synchronous driver does not degrade gracefully — it fails at the first
query with an error that does not mention the URL at all.

### `DATABASE_URL is not set`

You have no `.env`, or it is somewhere the backend does not look. It is read
from the repository root and from `backend/`. `cp .env.example .env` at the root.

### `InvalidSQLStatementNameError` / `DuplicatePreparedStatementError`

Neon's pooled endpoint runs PgBouncer in transaction mode, which breaks
asyncpg's prepared-statement cache. `db/session.py` handles this automatically
for any URL containing `-pooler` or `neon.tech`. If you are seeing it, you are
probably connecting through a pooler this detection does not recognise — say so,
and we will widen it.

### Migrations fail intermittently, or look like network errors

You are running Alembic through the **pooled** endpoint. Set
`DATABASE_URL_DIRECT` to the direct one. This failure does not announce itself
clearly, which is why it is worth recognising by shape.

### `docker: failed to connect to the docker API`

Docker Desktop is not running. Start it and wait for the whale icon to settle.

### `Version '...' for 'tshark' was not found` during `docker build`

Debian has rotated the pinned package out of the archive. **This is the pin
working, not a bug.** Bump `TSHARK_DEB_VERSION` and `TSHARK_VERSION` in
`backend/Dockerfile` *and* `pyproject.toml`, then re-run the Track A tests before
merging. Do not relax the pin to make the build pass.

### `pytest` reports far more skips than expected

`TEST_POSTGRES_URL` did not take, so only SQLite ran. See §7. Confirm with
`REQUIRE_POSTGRES=1 uv run pytest`, which fails rather than skips.

### A stray `NUL` directory appears (Windows)

npm occasionally materialises its cache under the reserved name `NUL`. It is
git-ignored. Removing it needs the extended-path prefix, since ordinary tools
cannot open a reserved name:

```powershell
[System.IO.Directory]::Delete('\\?\<full-path>\NUL', $true)
```

### Line endings look wrong in a diff

`.gitattributes` normalises everything to LF. If you cloned before it existed,
`git rm --cached -r . && git reset --hard` will re-normalise your working tree.

---

## 9. Where to go next

Work follows [docs/implementation-plan.md](docs/implementation-plan.md) in
order. Find your workstream, take the next unstarted step, and treat its
**Done when** line as the definition of finished — demonstrated by running it,
not by the code compiling.

| Code | Track | Scope |
|---|---|---|
| **P** | Platform | Core schema, database, API, jobs, deployment, CI |
| **N** | Network | Testbed, ingest, Track A parsing |
| **M** | ML | Features, Track B models, calibration, evaluation |
| **F** | Frontend | Next.js app, dashboard views, reports |

Gate G1 is passed, so all four are unblocked. The frontend and report
workstreams build against `backend/tests/fixtures/assessment_weak.json` and
`assessment_strong.json` until the engine exists —
[their README](backend/tests/fixtures/README.md) explains which properties of
those files are deliberate.

Before your first commit, read [CLAUDE.md](CLAUDE.md). The conventions there —
UUIDv7 keys, UTC-aware timestamps, `snake_case` in the database, `sa.JSON` never
`JSONB` — are load-bearing rather than stylistic, and each has a reason recorded
next to it.

Every completed phase or feature updates [CHANGELOG.md](CHANGELOG.md) and
[manualtesting.md](manualtesting.md) in the same commit as the change.
