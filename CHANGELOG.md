# Changelog

What has actually landed, in the order it landed. Structured by the phases and
steps of [docs/implementation-plan.md](docs/implementation-plan.md), because
that is the unit of work this project moves in.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/); the project stays on
`0.x` until the demo build.

**Update this file in the same commit as the change it describes.** An entry
added later is an entry written from memory. Record what a step *delivers*, not
which files moved — and when a step's **Done when** could not be demonstrated,
say so under Not verified rather than leaving it implied.

---

## [Unreleased]

### Added

- `README.md` — what the project is, the two-track thesis, honest current status,
  and where the documentation lives.
- `startup.md` — fresh machine to passing test suite, with the offline and Neon
  paths kept separate and a troubleshooting section of failures people have
  actually hit rather than hypotheticals.
- `manualtesting.md` MT-11, which runs `startup.md` verbatim in a clean clone. A
  setup guide nobody re-runs rots quietly.

### Fixed

- **Alembic could not see `.env`.** `alembic/env.py` read `os.environ` directly,
  so a developer who had configured `.env` exactly as documented still got
  "DATABASE_URL is not set" from `alembic upgrade head`. It now falls back to
  `core.config`, which reads the dotenv file and validates the URL. Explicit
  environment variables still take precedence, so CI and one-off
  `DATABASE_URL_DIRECT=... alembic upgrade head` invocations are unchanged.

  Not caught during Phase 1 because every migration run in that session passed
  the URL on the command line, which is the one path that always worked.

---

## [0.1.0] — 2026-09-04

Gate **G1 — Contract locked**. `core/schema.py` is the single source of truth,
the storage layer runs on both backends, and all four workstreams are unblocked.

Commit `2165a44`. Implementation-plan steps 0.3–0.6 and 1.1–1.8.

### Added — Phase 0, foundations

**0.3 Repository skeleton**
- Tree from [LLD §2](docs/LLD.md): uv-managed Python 3.11 backend under
  `backend/src/analyzer/`, Next.js 16 frontend, `testbed/`, `dataset/`.
- A docstring-only placeholder module for every later phase, so the import graph
  and the plan agree from day one.
- `.gitignore`, `.gitattributes` (LF everywhere, so Windows checkouts do not
  rewrite the tree), `.editorconfig`, MIT `LICENSE`, `CLAUDE.md`.

**0.4 CI pipeline**
- `.github/workflows/ci.yml`: ruff, ruff-format, mypy strict, pytest across both
  database backends, the Alembic upgrade/downgrade round trip on each, plus
  `tsc --noEmit`, ESLint and `next build`.
- `scripts/ci-local.sh` runs the same set locally, so "green here" means "green
  there".
- `REQUIRE_POSTGRES=1` turns a skipped PostgreSQL backend into a CI failure. A
  backend that silently never ran is a green build proving half of what it
  claims.

**0.5 Neon configuration**
- `.env.example` with placeholder pooled and direct connection strings.
- [docs/database-setup.md](docs/database-setup.md): branch-per-developer setup,
  which endpoint each consumer uses, and the three Neon gotchas that each cost a
  day — PgBouncer versus asyncpg's prepared statements, scale-to-zero, and
  `sslmode` being libpq's spelling rather than asyncpg's.
- `scripts/pg-dev.sh` for a throwaway local PostgreSQL on port 55432.

**0.6 tshark version pin**
- `backend/Dockerfile` pinning tshark **4.4.18** (`wireshark-common` pinned
  alongside it, or apt resolves a newer common package and fails the solve).
- The same version recorded in `pyproject.toml` under
  `[tool.ipsec-analyzer.external-tools]` and asserted by
  `tests/test_tshark_version.py`. Wireshark's JSON field names change between
  releases and break the Track A parser silently, so three places must agree and
  the build fails loudly when Debian rotates the package out.

### Added — Phase 1, contract and storage

**1.1 Enums** — `core/enums.py`
- Every enum from [LLD §3](docs/LLD.md), plus `CaptureSource`, `RunStatus` and
  `RunStage` for the storage layer.
- `CATEGORY_CAPS` sits beside `FindingCategory` so a new category cannot be
  added without deciding its cap (PRD §10.1, summing to 100).
- `EncryptionAlg` deliberately carries no AES key length: from ESP alone the
  cipher family is inferable and the key length is not, so folding them together
  would make FR-4.9 unrepresentable.

**1.2 `Evidence` and `Attribute[T]`** — `core/schema.py`
- The provenance invariant, enforced by a model validator: `INFERRED` must carry
  a confidence, `OBSERVED` must not.
- Strengthened beyond LLD §3 so the same dishonesty cannot re-enter by another
  door — `UNAVAILABLE` must explain itself in a note and must hold no value, and
  a null value may not hide behind `OBSERVED` or `INFERRED`.
- `validate_assignment` keeps the invariant true after construction, not only at
  it.
- `Evidence.packet_indices` capped at 20 with `total_matching` alongside
  (LLD §8.4).

**1.3 Full contract** — `core/schema.py`
- `CaptureQuality`, `FeatureAttribution`, `TrafficPrediction`,
  `SecurityAssociation`, `StandardRef`, `Finding`, `ThreatMatrixEntry`,
  `ScoreBreakdown`, `MetadataExposure`, `Assessment`.
- `UtcDatetime` rejects naive datetimes, normalises to UTC, and serialises with
  a trailing `Z` so identical input is byte-identical output (NFR-4).
- `Uuid7`, `HexSpi`, `FindingKey` and `AttackTechniqueId` validate their formats.
- Cross-model validation: no finding may reference an unknown SA, no threat
  matrix entry may cite a finding that is not in the document, a score total must
  equal 100 minus its category penalties, and an informational finding may not
  cost points.
- `core/ids.py` — `new_id()` returning UUIDv7.

**1.4 Fixture assessments** — `backend/tests/fixtures/`
- `assessment_weak.json` and `assessment_strong.json`, the two
  [PRD §16](docs/ipsec-analyzer-prd.md) demo tunnels, written by hand.
- Weak: 15/100 `critical`, 8 findings, ATT&CK T1040/T1110/T1557/T1600.
- Strong: 90/100 `strong`, one surviving finding — `META-HIGH-EXPOSURE`, because
  hardening the cryptography did almost nothing to what the traffic pattern
  reveals. That contrast is PRD §4.1's thesis stated as data.
- Both encode the failure mode guaranteed to appear on stage: a VoIP call
  produces too few distinct ESP lengths for the cipher-family sieve, so
  `sufficient_for_lattice` is false in both.
- `fixtures/README.md` records which properties are deliberate, so nobody
  "fixes" them.

**1.5 SQLAlchemy models** — `db/models.py`, `db/types.py`
- The five tables of LLD §4.3. `sa.JSON` never `JSONB`, `sa.Uuid` keys,
  `ON DELETE CASCADE` throughout, and a metadata naming convention so every
  constraint has a stable name a downgrade can drop.
- Enum columns are portable `VARCHAR` with `values_callable`, so the database
  stores `3des-cbc` rather than `TRIPLE_DES_CBC`.
- `UtcDateTime` column type returns aware UTC values on both backends; SQLite
  otherwise hands back naive datetimes that compare wrong without complaint.

**1.6 Alembic** — `alembic/`
- Initial migration `6173d44f0cce`, with the dialect-guarded `JSON → JSONB`
  promotion for PostgreSQL.
- `env.py` reads `DATABASE_URL_DIRECT` first, because DDL through Neon's pooler
  fails intermittently and looks like network flakiness.
- A `render_item` hook keeps `analyzer.*` out of version files, so a migration
  survives the module it was generated from being renamed.

**1.7 Session factory** — `db/session.py`
- Neon pooled endpoints get `statement_cache_size=0`,
  `prepared_statement_cache_size=0` and a unique statement-name function.
  Disabling one cache and not the other is the usual half-fix, and it fails only
  under concurrency.
- `pool_pre_ping` and `pool_recycle=280` for scale-to-zero.
- `PRAGMA foreign_keys=ON` per SQLite connection, without which every
  `ON DELETE CASCADE` in the schema is decorative on the offline backend.
- `session_scope()` for the single-transaction write path, `check_connection()`
  for the future health endpoint.

**1.8 Settings** — `core/config.py`
- `DATABASE_URL`, `DATABASE_URL_DIRECT`, `STORAGE_PATH`, `POLICY_PATH`,
  `MODEL_DIR`, `MAX_UPLOAD_BYTES`, `MAX_CONCURRENT_ANALYSES`.
- Refuses to start, with instructions, on a missing `DATABASE_URL`, a
  synchronous driver URL, or libpq's `sslmode` spelling.

### Verified

- 219 tests pass across SQLite and PostgreSQL 16; 2 skipped (live Neon, and the
  host-tshark check that runs inside the image).
- `alembic upgrade head` then `downgrade base`, twice, on both backends. All six
  JSON columns read `jsonb` on PostgreSQL and `JSON` on SQLite.
- `docker run ipsec-analyzer-backend:0.1.0 tshark --version` → `4.4.18`.
- Ruff, ruff-format, mypy strict, `tsc --noEmit`, ESLint and `next build` clean.

### Not verified

- **Step 0.5** — no team member has `psql`'d into their own Neon branch. Needs
  the Neon account.
- **Step 1.7** — the live smoke test against Neon's *pooled* endpoint is skipped
  until `NEON_POOLED_URL` is set. The settings it depends on are verified
  against a real PostgreSQL, but PgBouncer itself has not been in the path.
- **Step 0.4** — the "a PR with a lint error is blocked" condition was shown
  locally via `scripts/ci-local.sh`; no PR has run through GitHub Actions yet.

### Deviations from the specs

Recorded so the specs can be corrected rather than quietly diverged from.

- **Next.js 16.3.4**, where LLD §11.1 says 15. Agreed deliberately; §11.1 needs
  amending and Next 16's breaking changes are a live risk for Phase 7.
- **Enum values are lowercase throughout.** LLD §8.1's policy example writes
  `"3DES-CBC"` while `Provenance`, `Severity` and `FindingCategory` in the same
  document are lowercase. Policy files must use the enum values.
- **`Evidence.measured` accepts `int`**, not only `float | str`. Otherwise a
  technical report reads "exchange type 4.0" and NFR-4's byte-identical round
  trip breaks on integers.
- **`Evidence.total_matching` added.** Required by LLD §8.4, absent from §3's
  listing.
- **`ThreatMatrixEntry` and `FeatureAttribution` designed here.** Both are
  referenced by the LLD and defined nowhere in it.
- **`captures.sha256` is `String(64)`, not `CHAR(64)`.** PostgreSQL `CHAR`
  blank-pads and compares padded, which would let an identical hash miss the
  unique index.
- **`TrafficClass.FILE_TRANSFER = "file_transfer"`**, where the LLD §10.1 matrix
  spells it `filexfer`. The matrix loader owns the mapping.
- **`docker-compose.yml` not created.** It belongs to step 11.4 and would
  reference a frontend Dockerfile that does not exist.

### Open spec questions

Raised during this work, still unanswered. See the summary in
[manualtesting.md](manualtesting.md) for how each is currently worked around.

1. **T1600 cannot reach the weak fixture as specified.** Step 5.7 requires it;
   PRD §10.3 maps T1600 only to downgrade-permitting proposals, and the weak
   demo tunnel selects the weakest algorithm it offers, so
   `CRYPTO-DOWNGRADE-OFFER` cannot fire. Currently mapped from `CRYPTO-3DES` and
   `KEX-WEAK-DH` on a reduced-key-space reading.
2. **`ScoreBreakdown.rating` thresholds are defined nowhere.** LLD §8.3 calls an
   unspecified `_rating(total)`. No validator ties rating to total; step 5.5
   owns the decision.
3. **IKEv1 Quick Mode is encrypted too.** LLD §6.4 carves out only IKEv2's
   `IKE_AUTH`, but IKEv1 Phase 2 is protected by the Phase 1 SA, so the ESP
   transform set is not directly observable there either — while PRD §7 says
   "Certain with IKE captured". Phase 4 needs one consistent rule.
4. **`SecurityAssociation` conflates the IKE SA and the Child SA.** It carries
   ESP SPIs and `protocol: esp|ah` alongside `ike_version`, `prf_alg` and
   `dh_group`. Which SA does `encryption_alg` describe? Drives question 3.
5. **Step 7.8 wants an ESP-only fixture** that step 1.4 does not create.

---

[Unreleased]: https://github.com/Piyush800x/ipsec-analyzer/compare/2165a44...HEAD
[0.1.0]: https://github.com/Piyush800x/ipsec-analyzer/commit/2165a44
