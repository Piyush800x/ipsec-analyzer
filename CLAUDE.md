# CLAUDE.md

Project conventions for the AI-Powered IPsec VPN Protocol Analyzer.

Authoritative specifications live in [docs/](docs/):

- [docs/ipsec-analyzer-prd.md](docs/ipsec-analyzer-prd.md) — requirements (FR-x.y, NFR-x), scoring rubric, demo script
- [docs/LLD.md](docs/LLD.md) — schemas, interfaces, algorithms, contracts
- [docs/implementation-plan.md](docs/implementation-plan.md) — ordered steps, each with a **Done when** condition

When this file and the specs disagree, the specs win — and the disagreement is a bug in this file.

Two living records track what has actually happened, as opposed to what was planned:

- [CHANGELOG.md](CHANGELOG.md) — what landed, per plan step, plus deviations from the
  specs and open spec questions.
- [manualtesting.md](manualtesting.md) — the checks a person runs by hand, with the date
  and result of the last run.

---

## Language and tooling

- **Python 3.11+**, managed with **uv**. Never `pip install` into the environment directly;
  add dependencies with `uv add` so `pyproject.toml` and `uv.lock` stay authoritative.
  Run everything through `uv run` (`uv run pytest`, `uv run alembic ...`).
- **Ruff** is the only formatter and linter. **Line length 100.** `uv run ruff format` and
  `uv run ruff check --fix` before every commit.
- **Full type annotations** on every function, method, and module-level binding.
  `from __future__ import annotations` at the top of every module. mypy runs in strict mode
  and a new `# type: ignore` needs a reason on the same line.
- TypeScript 5.x on the frontend, `tsc --noEmit` clean.

## Naming

- `snake_case` in Python **and in the database** — table names, column names, index names,
  constraint names. No exceptions, including for JSON document keys.
- `camelCase` in TypeScript. Conversion happens **only** at the API boundary, via Pydantic
  field aliases. Nothing inside the backend ever sees a camelCase key.
- Enum *values* are lowercase strings defined once in `core/enums.py` and mirrored to
  TypeScript by codegen. Never re-declare an enum value as a string literal elsewhere.

## Identifiers and time

- **UUIDv7 for every entity primary key.** Time-sortable, so `ORDER BY id` is a usable
  chronological order and we never need a surrogate sequence. Generate with
  `analyzer.core.ids.new_id()`; do not call `uuid.uuid4()` anywhere.
- **All timestamps are UTC and timezone-aware.** `datetime.now(tz=UTC)`, never
  `datetime.utcnow()` (which returns a naive value and will silently compare wrong).
  Serialise as ISO 8601 with an explicit offset. A naive datetime crossing a module
  boundary is a bug.

## The core contract

`core/schema.py` is the single source of truth. Database rows, API responses, report
templates, and frontend types all derive from it. Change it first, then propagate.

`Attribute[T]` carries a mandatory `Provenance`, and the invariant is hard:

- `INFERRED` **must** carry a `confidence`.
- `OBSERVED` **must not** carry a `confidence`.
- `UNAVAILABLE` carries a `note` explaining why, and renders as that explanation — never
  as a blank or a dash.

This is not a convenience check. It is what stops an inference being dressed up as a fact
in a security report, and it is enforced by a model validator with tests proving both
directions fail.

## Database

The database layer **must behave identically on PostgreSQL and SQLite.** Postgres (Neon)
is the default; SQLite is the offline/air-gapped/CI backend. One SQLAlchemy model set
serves both, and every test that touches the DB runs against both.

- Use `sa.JSON`, **never `JSONB`**, in model definitions. The Postgres upgrade to `JSONB`
  happens in a dialect-guarded Alembic step, not in the models.
- **No Postgres-only constructs in application queries**: no array columns, no `ILIKE`
  (use `func.lower(col).like(...)`), no JSON path filtering, no window functions in the
  hot path.
- UUIDs are `sa.Uuid` (native `uuid` on PG, `CHAR(32)` on SQLite).
- Never filter or index on a JSON column. If a query needs a field, promote it to a real
  column — that is why `findings` and `security_associations` duplicate content that is
  already inside `assessments.document`.
- Every migration must survive `alembic upgrade head` followed by `alembic downgrade base`
  on **both** backends. Downgrades are not optional.
- Alembic runs against the **direct** connection string; the API uses the **pooled** one.
- Neon's pooled endpoint runs PgBouncer in transaction mode, which breaks asyncpg's
  prepared-statement cache — pass `statement_cache_size=0`. Neon also scales to zero, so
  `pool_pre_ping=True` is required or the first query after an idle period fails.

## API

- **RFC 9457 Problem Details** for every error response: `application/problem+json` with
  `type`, `title`, `status`, `detail`, and `instance` where meaningful. No bare
  `{"detail": "..."}`, no HTML error pages, no stack traces over the wire.
- Versioned under `/api/v1`.

## Determinism

The assessment engine is a pure function of its inputs: no I/O, no randomness, no
wall-clock reads inside `evaluate()`. Identical input produces byte-identical assessment
JSON (NFR-4). Timestamps and IDs are injected by the caller, not read inside the engine.

## Working practice

- Follow [docs/implementation-plan.md](docs/implementation-plan.md) in order. A step is
  done when its **Done when** line is objectively demonstrated — run it, show the output.
  "It compiles" is not a demonstration.
- Do not build ahead of the plan. Later phases depend on decisions that have not been made.
- Honest gaps beat confident guesses. `UNAVAILABLE` with a reason is a correct answer;
  a plausible-looking fabricated value is a defect.

- **Every completed phase or feature updates both records, in the same commit as the
  change.** [CHANGELOG.md](CHANGELOG.md) gets what the step delivers, anything that could
  not be demonstrated under *Not verified*, and any divergence from the specs under
  *Deviations*. [manualtesting.md](manualtesting.md) gets a new `MT-NN` procedure for
  anything a person must confirm by eye — a rendered view, a container's contents, a
  migration against a real server — and a row in its status table. An entry written later
  is an entry written from memory.
