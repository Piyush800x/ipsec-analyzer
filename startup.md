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
uv sync --all-groups
```

`uv sync --all-groups` builds `.venv/`, fetches Python 3.11 if needed, and
installs from `uv.lock`.

> **`--all-groups`, not a bare `uv sync`.** The `testbed` group (`docker`,
> `jinja2`, `pyyaml`) is not installed by default, and four test modules import
> it unconditionally — a bare `uv sync` leaves you with collection errors that
> look like a broken checkout and are not.

Then create the schema:

```bash
uv run alembic upgrade head
```

Expect one line: `Running upgrade  -> 6173d44f0cce, initial schema`.

Check it worked:

```bash
uv run python -c "import analyzer; print(analyzer.__version__)"     # 0.1.0
uv run pytest -q
```

Expect **`508 passed, 68 skipped`**. The skips are expected and fall
into four groups:

| Skipped because | Turn them on with |
|---|---|
| The PostgreSQL half of every database *and API* test | §7 — start a local server |
| Docker-backed testbed tests (Phase 2) | a running Docker daemon |
| The slow tests (100 MB performance run, 20-iteration leak check) | `-m slow` |
| The host-`tshark` version check | install tshark, or run it in the image |

A green run on a laptop with no PostgreSQL and no Docker proves rather less
than the count suggests, which is exactly why the skips are visible rather
than silently absent.

> **Never `pip install` into this environment.** Add dependencies with
> `uv add <package>` so `pyproject.toml` and `uv.lock` stay authoritative, and
> run everything through `uv run`.

---

## 5. Frontend

```bash
cd ../frontend
npm ci
USE_FIXTURES=1 npm run dev
```

Open <http://localhost:3000>.

`USE_FIXTURES=1` serves every read from the two demo assessments in
`src/lib/fixtures/`, so **the whole dashboard renders with the backend not
running at all**. That is the fastest way to see what the product claims:
follow either fixture through to its Configuration tab, where every parameter
shows whether it was observed, inferred, or is honestly undeterminable — which
is the entire thesis in one screen.

Drop the flag once the API is up (§6) and the same views read live data.

```bash
npx tsc --noEmit
npm run lint
npm run build
```

> `npx tsc --noEmit` fails on a fresh clone with
> `Cannot find name 'LayoutProps'` until you have run `npm run build` or
> `npm run dev` once. Next.js 16 generates those route-typed helpers into
> `.next/types/`, which is git-ignored. It is not a broken checkout.

---

## 5b. The API

```bash
cd ../backend
uv run uvicorn analyzer.api.main:create_app --factory --port 8000
```

`--factory` because `create_app()` builds the engine, session factory, policy
and job runner itself; there is deliberately no module-level `app` to import,
so tests can stand one up against a throwaway database.

```bash
curl localhost:8000/api/v1/health
curl -F file=@some-capture.pcap localhost:8000/api/v1/captures
curl -X POST localhost:8000/api/v1/captures/<id>/analyze
curl -N localhost:8000/api/v1/runs/<run-id>/events      # live SSE progress
curl -o report.pdf "localhost:8000/api/v1/assessments/<id>/report?format=executive"
```

Interactive docs at <http://localhost:8000/docs>.

**Track A needs `tshark` on PATH.** Without it the analysis still completes —
every IKE-derived field comes back `unavailable` with that as the stated
reason, which is a degraded analysis rather than a failure. Install it
(`sudo apt-get install -y tshark`) to exercise the parser, and see
`manualtesting.md` MT-16 for why that is worth doing before trusting Track A.

---

## 6. Verify the whole thing

One command runs exactly what CI runs:

```bash
cd ..
./scripts/ci-local.sh
```

Expect `CI-LOCAL: PASSED` with ruff, ruff-format, mypy, pytest,
`gen-types --check`, `tsc --noEmit`, ESLint and `next build` all reporting
`PASS`.

`gen-types --check` is the one that surprises people: it regenerates the
frontend's TypeScript types from the backend's OpenAPI schema and fails if the
committed file differs. A Pydantic field changed without regenerating breaks
the build here rather than surfacing as an `undefined` in the browser later.
Fix it with `./scripts/gen-types.sh` and commit the result.

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

39 of the 68 default skips are the PostgreSQL half, and they turn into passes.
If the count does not move, the URL did not take — see the last entry in §8.

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

### `permission denied while trying to connect to the docker API`

Not the same as the daemon being down. The socket is `root:docker` mode `0660`,
so your account has to be in the `docker` group:

```bash
getent group docker          # are you listed?
sudo usermod -aG docker "$USER"
```

**Then start a new login session.** Supplementary groups are fixed when a
process starts, so `usermod` does nothing for any shell, editor, or agent
already running — `getent group docker` will list you while `id -nG` in that
shell still does not, which is the confusing part. Log out and back in, or
`newgrp docker` for a single shell. There is no way to pick the group up from
inside an already-running process.

### `docker: failed to connect to the docker API` (no "permission denied")

The daemon is not running. `sudo systemctl start docker`, or on Docker Desktop
start it and wait for the whale icon to settle.

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

Gate **G3 — End to end** is passed: a capture goes in, and an assessment comes
out through ingest → Track A → Track B → assess → persist, visible in the
dashboard and downloadable as either report.

What is left is what needs a Docker daemon. Phase 8 (the labelled dataset) has
its generator and its verification harness written but has never been run;
Phase 9's learned components (9.5–9.12) wait on that dataset, and
`backend/models/` is honestly empty in the meantime. Phase 11's remaining steps
— the PostgreSQL CI run, the offline-stack rehearsal, the frozen demo captures
— are gated the same way. [CHANGELOG.md](CHANGELOG.md) records per phase what
was demonstrated and what was not.

The frontend and the report templates render against
`backend/tests/fixtures/assessment_weak.json` and `assessment_strong.json` —
[their README](backend/tests/fixtures/README.md) explains which properties of
those files are deliberate, and why `model_versions` names models that do not
exist.

Before your first commit, read [CLAUDE.md](CLAUDE.md). The conventions there —
UUIDv7 keys, UTC-aware timestamps, `snake_case` in the database, `sa.JSON` never
`JSONB` — are load-bearing rather than stylistic, and each has a reason recorded
next to it.

Every completed phase or feature updates [CHANGELOG.md](CHANGELOG.md) and
[manualtesting.md](manualtesting.md) in the same commit as the change.
