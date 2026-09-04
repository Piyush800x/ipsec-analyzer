# Manual testing

Procedures a person runs by hand, for the things an automated suite cannot prove
on its own: that a clean clone works, that the container carries what it claims,
that the migration really round-trips against a real server, and — from Phase 7
onward — that the dashboard shows the right thing to a human looking at it.

**Add a section here whenever a phase completes or a feature lands.** The
automated suite proves the code does what the code says; this file proves the
product does what the plan said. A step whose **Done when** involves a human
looking at something belongs here, always.

Record the result when you run a check. `Last verified` with a date and a
version is the difference between a test plan and a test *record* — and a check
nobody has run since March is a check nobody should trust.

Companion to [CHANGELOG.md](CHANGELOG.md), which records what changed;
this file records what was confirmed to work.

---

## Prerequisites

| Need | For |
|---|---|
| [uv](https://docs.astral.sh/uv/) | everything backend |
| Node 22+ | frontend |
| Docker Desktop **running** | MT-02, MT-05, MT-06, MT-07 |
| A Neon connection string | MT-08 only |

```bash
cd backend && uv sync
cd ../frontend && npm ci
```

Anything that touches the database needs a local PostgreSQL. One command:

```bash
./scripts/pg-dev.sh up
export TEST_POSTGRES_URL="$(./scripts/pg-dev.sh url)"
# ...
./scripts/pg-dev.sh down
```

---

## Status

| ID | Check | Phase | Last verified | Result |
|---|---|---|---|---|
| MT-01 | Clean clone comes up | 0.3 | 2026-09-04 | Pass |
| MT-02 | Backend image carries the pinned tshark | 0.6 | 2026-09-04 | Pass |
| MT-03 | CI blocks a lint error | 0.4 | 2026-09-04 | Pass (locally; see note) |
| MT-04 | Missing config refuses to start | 1.8 | 2026-09-04 | Pass |
| MT-05 | Full suite on both backends | 1.5, 1.7 | 2026-09-04 | Pass |
| MT-06 | Migration round trip on both backends | 1.6 | 2026-09-04 | Pass |
| MT-07 | JSON becomes JSONB on PostgreSQL only | 1.6 | 2026-09-04 | Pass |
| MT-08 | Neon pooled endpoint, no prepared-statement error | 1.7 | — | **Not run** |
| MT-09 | Per-developer Neon branch reachable | 0.5 | — | **Not run** |
| MT-10 | Demo fixtures are honest | 1.4 | 2026-09-04 | Pass |
| MT-11 | `startup.md` works as written | onboarding | 2026-09-04 | Pass |

---

## MT-01 — A clean clone comes up

**Proves** step 0.3. Nothing needed to run this project is untracked, and no
generated file that should have been ignored is required.

```bash
git clone https://github.com/Piyush800x/ipsec-analyzer.git /tmp/mt01
cd /tmp/mt01/backend && uv sync --frozen
uv run python -c "import analyzer; print(analyzer.__version__)"

cd ../frontend && npm ci && npm run dev
```

**Expect** `0.1.0`, then `Ready in Ns` and HTTP 200 at <http://localhost:3000>.

**Watch for** a missing `uv.lock` or `package-lock.json` — `uv sync --frozen`
and `npm ci` both fail loudly rather than resolving fresh, which is the point.

> Last verified 2026-09-04 · `2165a44` · Pass. Real clone of `origin/main`:
> `import analyzer` returned `0.1.0`, `next dev` was ready in 3.9 s and served
> HTTP 200.

---

## MT-02 — The backend image carries the pinned tshark

**Proves** step 0.6. Track A parses Wireshark's JSON output, whose field names
change between releases. A drift does not raise — it produces wrong values.

```bash
cd backend
docker build -t ipsec-analyzer-backend:0.1.0 .
docker run --rm ipsec-analyzer-backend:0.1.0 tshark --version | head -1
grep -A1 'external-tools' pyproject.toml | tail -1
```

**Expect** `TShark (Wireshark) 4.4.18.` and `tshark = "4.4.18"` — the same
number from both.

**If the build fails** with an unmet-dependency error naming a newer version,
Debian has rotated the pinned package out of the archive. That failure is
working as designed. Bump `TSHARK_DEB_VERSION` and `TSHARK_VERSION` in the
`Dockerfile` *and* `pyproject.toml`, then re-run the Track A golden-PCAP tests
before merging. Do not relax the pin to make the build pass.

> Last verified 2026-09-04 · Pass, after bumping 4.4.16 → 4.4.18 when
> trixie-security moved. The pin caught it, which is the whole point.

---

## MT-03 — CI blocks a lint error

**Proves** step 0.4.

```bash
cd backend
printf '\n\nimport os\ndef broken( x ):\n    print("bad", os, undefined_name)\n' \
  >> src/analyzer/core/errors.py
cd .. && ./scripts/ci-local.sh backend; echo "exit=$?"
cd backend && git checkout src/analyzer/core/errors.py
```

**Expect** ruff, ruff-format and mypy each reporting `FAIL`, and
`CI-LOCAL: FAILED` with exit 1.

**Note** `scripts/ci-local.sh` mirrors `.github/workflows/ci.yml` but is not the
same thing. The real condition — a pull request blocked by GitHub Actions — has
not been exercised yet, because no PR has run. Open a throwaway PR with a lint
error once the repository has a `main` branch and branch protection.

> Last verified 2026-09-04 · Pass locally. **The GitHub-side half is still
> outstanding.**

---

## MT-04 — Missing configuration refuses to start

**Proves** step 1.8. A misconfiguration should fail at startup with a message
that says what to do, not at the first request with a driver stack trace.

```bash
cd backend
env -u DATABASE_URL -u DATABASE_URL_DIRECT \
  uv run python -c "from analyzer.db.session import engine_from_settings; engine_from_settings()"
```

**Expect** a `ConfigurationError` naming `DATABASE_URL`, pointing at
`.env.example`, and offering the SQLite fallback verbatim.

Also try each of these, which are the mistakes people actually make:

| `DATABASE_URL` | Expected message |
|---|---|
| `postgresql://u:p@host/db` | `not an async driver` |
| `postgresql+asyncpg://u:p@host/db?sslmode=require` | use `ssl=require` |
| `sqlite+aiosqlite:///./data/analyzer.db` | starts cleanly |

> Last verified 2026-09-04 · Pass.

---

## MT-05 — The full suite on both backends

**Proves** steps 1.5 and 1.7, and LLD §4.1's rule that the database layer
behaves identically on both.

```bash
./scripts/pg-dev.sh up
export TEST_POSTGRES_URL="$(./scripts/pg-dev.sh url)"
cd backend && uv run pytest -q
```

**Expect** `219 passed, 2 skipped`. The two skips are MT-08 (live Neon) and the
host-tshark check, which runs inside the image instead.

**Watch for** a much larger skip count — that means `TEST_POSTGRES_URL` did not
take and only SQLite ran. Confirm with:

```bash
uv run pytest -q -k "postgres" | tail -1     # should show passes, not all skips
REQUIRE_POSTGRES=1 uv run pytest -q          # turns a skipped backend into a failure
```

> Last verified 2026-09-04 · PostgreSQL 16.14 · Pass, 219 passed / 2 skipped.

---

## MT-06 — Migration round trip on both backends

**Proves** step 1.6. Downgrades are not optional — a migration that only runs
forwards is discovered at the worst possible moment.

```bash
cd backend
# SQLite
DATABASE_URL_DIRECT="sqlite+aiosqlite:///./data/mt06.db" uv run alembic upgrade head
DATABASE_URL_DIRECT="sqlite+aiosqlite:///./data/mt06.db" uv run alembic downgrade base

# PostgreSQL
export DATABASE_URL_DIRECT="$(../scripts/pg-dev.sh url)"
uv run alembic upgrade head
uv run alembic downgrade base
```

**Expect** `Running upgrade  -> <rev>` then `Running downgrade <rev> ->` on
each, with no errors, and only `alembic_version` left behind afterwards. Run it
twice on each backend — a downgrade that leaves a stray index passes once and
fails the second time.

Also confirm the migration has not drifted from the models:

```bash
uv run alembic upgrade head && uv run alembic check
```

**Expect** `No new upgrade operations detected.`

> Last verified 2026-09-04 · revision `6173d44f0cce` · Pass on both, twice each.

---

## MT-07 — JSON becomes JSONB on PostgreSQL only

**Proves** the dialect-guarded step in `6173d44f0cce`, and with it the reason
the models say `sa.JSON`: SQLite cannot create `JSONB`, so the promotion happens
in the migration where SQLite never reaches it.

```bash
cd backend
export DATABASE_URL_DIRECT="$(../scripts/pg-dev.sh url)"
uv run alembic upgrade head
docker exec ipsec-analyzer-pg psql -U analyzer -h 127.0.0.1 -d analyzer_test -c \
  "SELECT table_name, column_name, data_type FROM information_schema.columns
   WHERE table_schema='public' AND data_type IN ('json','jsonb') ORDER BY 1,2"
```

**Expect** six rows, every one `jsonb`: `analysis_runs.error`,
`analysis_runs.model_versions`, `assessments.document`, `captures.ground_truth`,
`findings.detail`, `security_associations.detail`.

The same columns on SQLite must read `JSON`:

```bash
DATABASE_URL_DIRECT="sqlite+aiosqlite:///./data/mt07.db" uv run alembic upgrade head
uv run python -c "
import sqlite3
c = sqlite3.connect('data/mt07.db')
print([r[2] for r in c.execute('PRAGMA table_info(captures)') if r[1] == 'ground_truth'])"
```

**Expect** `['JSON']`. A `jsonb` here would mean the dialect guard has broken and
the offline backend is about to fail.

> Last verified 2026-09-04 · Pass. Six `jsonb` on PostgreSQL, `JSON` on SQLite.

---

## MT-08 — Neon pooled endpoint, no prepared-statement error

**Proves** step 1.7's actual Done-when. **Not yet run** — needs a live Neon URL.

Neon's pooled endpoint runs PgBouncer in transaction mode. asyncpg prepares
statements and caches them by name; the next statement lands on a backend that
has never seen that name. The failure is intermittent, appears only under
concurrency, and looks like a network fault.

```bash
cd backend
export NEON_POOLED_URL="postgresql+asyncpg://<user>:<pw>@ep-<id>-pooler.<region>.aws.neon.tech/<db>?ssl=require"
uv run pytest tests/test_db_session.py -k neon -v
```

**Expect** the test to pass rather than skip. Note the URL must be the **pooled**
one — the hostname with `-pooler` — or the test asserts its way out immediately.
Note also `?ssl=require`, not `?sslmode=require`; Neon's console gives you the
libpq spelling and asyncpg does not understand it.

**Watch for** `InvalidSQLStatementNameError` or
`DuplicatePreparedStatementError`. Either means one of the three settings in
`_asyncpg_connect_args()` has been lost.

> Last verified — · **Not run.** `NEON_POOLED_URL` unavailable. The settings it
> depends on are verified against a local PostgreSQL (MT-05), but PgBouncer has
> never actually been in the path.

---

## MT-09 — Per-developer Neon branch is reachable

**Proves** step 0.5. **Not yet run** — needs the Neon account.

Each developer gets a branch off `main` named `dev/<name>`, so nobody is
fighting over one schema while Alembic revisions are still churning. Setup is in
[docs/database-setup.md](docs/database-setup.md) §1.

```bash
psql "postgresql://<user>:<pw>@ep-<id>.<region>.aws.neon.tech/<db>?sslmode=require" -c 'SELECT 1'
```

**Expect** `1`. Note this is the `psql`/libpq spelling — `postgresql://` and
`sslmode`. The application uses `postgresql+asyncpg://` and `ssl`, which is not
the same thing and is the single most common confusion here.

Then, per developer: `cp .env.example .env`, fill in the **pooled** URL as
`DATABASE_URL` and the **direct** one as `DATABASE_URL_DIRECT`, and confirm
`uv run alembic upgrade head` lands on their own branch and nobody else's.

> Last verified — · **Not run.**

---

## MT-10 — The demo fixtures are honest

**Proves** step 1.4. These two files are what the frontend and report
workstreams build against for weeks, and step 5.4 asserts the engine reproduces
the weak one exactly. This is a read-through, not just a validation run.

```bash
cd backend && uv run pytest tests/test_fixtures.py -q
```

Then read the two files and confirm by eye that the honesty properties hold —
the automated tests check them, but these are the ones a reviewer will
challenge, so know why they are the way they are:

- Both captures have `sufficient_for_lattice: false`. A VoIP call produces two
  or three distinct ESP lengths where the cipher-family sieve needs eight
  (LLD §7.2). This failure mode is guaranteed to appear during the live demo.
- The hardened tunnel's `negotiated_lifetime_s` is `unavailable`, citing
  RFC 7296. IKEv2 does not negotiate lifetimes. A number here would be the
  correctness bug the LLD names outright.
- Its `encryption_alg`, `encryption_keylen` and `integrity_alg` are `inferred`,
  not `observed` — the Child SA proposal is inside the encrypted `IKE_AUTH`
  exchange (LLD §6.4).
- Its `pfs_enabled` and `auth_method` are `unavailable`, each with a note that
  explains itself rather than a dash.
- `operating_mode` is `inferred` in **both**, even with a complete IKE capture.
  Tunnel versus transport is not carried in any cleartext field.
- Metadata exposure is 95 against 92. Hardening the cryptography barely moved
  it, which is PRD §4.1's whole argument.

**Expect** 29 passed, and every one of the above to be visibly true in the JSON.

> Last verified 2026-09-04 · Pass. Weak 15/100 `critical`, strong 90/100
> `strong`.

---

## MT-11 — `startup.md` works as written

**Proves** that a new team member can actually get running. Distinct from MT-01,
which proves nothing needed is untracked; this proves the *instructions* are
right. A setup guide nobody re-runs rots quietly, and the person who discovers
it is the one you least want blocked.

Follow [startup.md](startup.md) §2 through §6 **literally**, in a fresh clone, on
a machine where the repo is not already set up. Do not substitute commands you
know work — the point is to catch the step that has silently stopped being true.

```bash
git clone https://github.com/Piyush800x/ipsec-analyzer.git /tmp/mt11
cd /tmp/mt11
cp .env.example .env
# edit .env: DATABASE_URL=sqlite+aiosqlite:///./data/analyzer.db
cd backend && mkdir -p data && uv sync
uv run alembic upgrade head
uv run pytest -q
```

**Expect** `Running upgrade  -> 6173d44f0cce, initial schema`, then
`206 passed, 15 skipped`. Note `.env` is the *only* configuration — if you find
yourself exporting `DATABASE_URL` on the command line to make a step work, the
guide is wrong and needs fixing rather than working around.

**Watch for** counts drifting. Both numbers are quoted in `startup.md` §4 and
§7, and a stale count teaches a newcomer to ignore expected output.

> Last verified 2026-09-04 · Pass — **after fixing a real defect it exposed**.
> `alembic/env.py` read `os.environ` directly and never saw `.env`, so step §4
> failed for anyone following the guide. Every migration run during Phase 1 had
> passed the URL on the command line, which is the one path that always worked.
> This is exactly what MT-11 exists to catch.

---

## Adding a check

Copy this. Keep it short enough that someone will actually run it.

```markdown
## MT-NN — <what a human confirms>

**Proves** step X.Y. <Why an automated test cannot settle this.>

​```bash
<copy-pasteable commands>
​```

**Expect** <the specific observable outcome, not "it works">.

**Watch for** <the plausible-looking wrong result, if there is one>.

> Last verified YYYY-MM-DD · <version or commit> · Pass/Fail · <notes>
```

Then add a row to the Status table, and note the new check in
[CHANGELOG.md](CHANGELOG.md) under the step that introduced it.
