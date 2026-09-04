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

### Added — Phase 2, testbed

Implementation-plan steps 2.1–2.10, plus the two Phase 0 spikes (0.1, 0.2) they
depend on, which had not been run.

**0.1, 0.2 De-risking spikes**
- Kernel IPsec in Docker works on this host. Two containers on a user-defined
  bridge, an IKEv2 tunnel between them, ESP on the wire during a ping across the
  protected subnets.
- The packet-geometry premise of [LLD §7.2](docs/LLD.md) holds: for an
  AES-CBC-128 + SHA1 tunnel, `(esp_len - 16 - 12) % 16 == 0` for **60 of 60**
  captured packets, across two distinct payload sizes. The cipher-family sieve
  of step 9.2 can be built as designed.
- Both are now standing checks — [manualtesting.md](manualtesting.md) MT-12 —
  rather than a spike somebody remembers doing.

**2.1 Peer container image** — `testbed/Dockerfile.peer`
- One image serves both ends: strongSwan, tcpdump, and every generator the seven
  PRD §9.2 classes need, because the peers only ever talk to each other.
- **`kernel-libipsec` is deleted from the image**, and the build fails if it
  survives. It ships in Debian's `libcharon-extra-plugins` and would have loaded
  silently. [LLD §10.3](docs/LLD.md) is emphatic about why: Track B's entire
  feature set is packet geometry, and userspace ESP need not reproduce the
  kernel's padding, IV placement or MTU behaviour. Config can be edited; a
  deleted shared object cannot be loaded at 2am by someone debugging a stubborn
  host.
- strongSwan 5.9.8 and tcpdump 4.99.3 pinned and recorded in `pyproject.toml`
  beside the tshark pin, for the same reason: between them they decide the
  cryptography and the packet geometry the models learn from, so a silent
  upgrade mid-dataset would split the corpus in two with nothing failing. Every
  session copies `/etc/testbed-versions.json` into its labels.
- Aggressive-mode PSK is enabled, deliberately and only here. strongSwan refuses
  the combination by default because it exposes the PSK hash to a passive
  observer — which is exactly the weakness `ikev1-aggressive` exists in the
  matrix to generate, and what the weak-reference demo tunnel is built on.

**2.2 Config templating** — `testbed/config.py`, `render.py`, `templates/`
- `SessionConfig` is frozen and is both the input and the ground truth, so a
  config cannot be mutated between rendering and labelling.
- Matrix labels (`aes128gcm16`) and contract values (`EncryptionAlg.AES_GCM_16`
  plus a key length) are kept explicitly apart, with one mapping table between
  them. Conflating the two is how a dataset ends up mislabelled.
- Both sides render from one config, so the two ends of a tunnel cannot disagree
  about what they are negotiating — a failure that surfaces not as an error but
  as a tunnel that never establishes, twenty minutes into a batch.

**2.3 Peer lifecycle** — `testbed/peers.py`
- `peer_pair()` creates the network and both containers with fixed addresses and
  destroys everything on the way out, including on exception and cancellation.
  Cleanup failures are logged, never raised: they must not mask the exception
  that caused them.
- Every resource is labelled, and `prune_orphans()` cleans up after a process
  that was killed outright and never ran its `finally`.
- `preflight()` checks kernel XFRM before a batch rather than halfway through
  one, with the modprobe incantation in the error text. The failure it catches
  otherwise looks like a configuration bug and costs a day.

**2.4 Bring-up and the assertion** — `testbed/tunnel.py`
- `assert_sa_established()` requires both an ESTABLISHED IKE SA and an INSTALLED
  Child SA. LLD §10.2 calls this guard non-negotiable and it is: without it, a
  failed negotiation produces a capture full of retries carrying a label that
  says it is a working tunnel.
- Errors name the proposals, the mode, and the responder's log, because the
  initiator only ever sees `AUTHENTICATION_FAILED`.
- `bring_up_tunnel(..., responder_cfg=...)` configures the far end differently.
  A normal session never uses it; it is the only way to exercise the guard, and
  step 4.4 will need it to build a peer offering 3DES alongside AES-256.

**2.5 Capture wrapper** — `testbed/capture.py`
- `start_tcpdump()` waits for tcpdump to report *listening* before returning, so
  the IKE exchange initiated moments later is inside the capture.
- `stop()` sends SIGINT rather than SIGKILL, waits for the process to actually
  finish, and **refuses to return an empty capture**. An empty PCAP beside a
  valid `labels.json` is worse than a failed session: the batch reports success
  and the row poisons whatever is trained on it.

**2.6 Traffic generators** — `testbed/traffic/`
- One module per class. Each commits to the distinguishing shape of its class
  rather than approximating all seven with a parameterised stream, because two
  classes that look alike here will look alike to the classifier in step 9.7.
- Measured over 25-second sessions, every class separates on packet rate and on
  at least one of size, directionality or idle structure — the table is in
  MT-13. `voip` and `icmp` deliberately produce very few distinct ESP lengths;
  that is what makes `sufficient_for_lattice` false for them in step 3.6, which
  is the honest-failure case the demo is built around.

**2.7 Ground truth** — `SessionConfig.to_ground_truth()`
- `labels.json` keeps three things apart: `dimensions` (what the matrix chose),
  `expected` (what a correct parser should report, keyed by
  `SecurityAssociation` field), and **`not_observable_from_ike`** (the fields no
  parser can recover from this capture, with the reason).
- That third block is load-bearing. Without it, step 8.2 would flag a parser
  correctly reporting `UNAVAILABLE` for an IKEv2 lifetime as a mismatch, and the
  obvious way to turn the harness green would be to teach the parser to guess.

**2.8 Session runner** — `testbed/orchestrator.py`
- `run_session()` in the LLD §10.2 order, with the teardown inside the capture
  window so the IKE DELETE exchange is recorded, and the result verified rather
  than assumed: IKE packets are counted before and after the teardown.
- Nothing is written to the output directory until the capture is proven
  non-empty, so a failed session leaves no half-written row.

**2.9 Matrix and sampler** — `testbed/matrix.yaml`, `sampler.py`
- The LLD §10.1 matrix, and a deterministic covering-array sampler: **60
  configurations** covering all 257 pairs, from a cross-product of 3360.
- Every value of every dimension appears; re-running with the same seed produces
  an identical list, which the resume manifest depends on.

**2.10 Batch orchestrator** — `testbed/batch.py`
- `run_batch()` with a manifest rewritten after every session, resume, and
  per-session failure isolation. `python -m testbed.batch <dir>` is the entry
  point.
- A session counts as done only when the manifest records it **and** its capture
  and labels are still on disk. A manifest can outlive the files it describes,
  and a resume that trusted it alone would produce a dataset with holes that
  nothing reports.

**Testing**
- 85 automated tests: config and ground truth, rendering, sampling, manifest and
  resume logic (no Docker), plus Docker-backed tests for each **Done when**.
- A new `testbed` CI job builds the peer image, loads the kernel modules and
  runs them with `REQUIRE_TESTBED=1`, so a testbed that silently never ran
  cannot leave a green build. Slow tests stay opt-in behind `TESTBED_SLOW=1`.
- `manualtesting.md` MT-12, MT-13, MT-14.

### Verified

- All 25 Docker-backed testbed tests pass, including the 20-iteration
  container-leak check and all seven traffic generators.
- Both LLD §10.1 reference fixtures negotiate: `weak-reference` establishes
  3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024 over IKEv1 aggressive mode in
  transport mode; `hardened-reference` establishes
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_256 with AES_GCM_16-256
  ESP in tunnel mode.
- A mismatched PSK fails in seconds with a message naming the proposals, and
  leaves no established SA.
- ESP on the wire is raw IP protocol 50, not UDP-encapsulated, and the LLD §7.2
  congruence holds for every captured packet.
- A 10-session batch `SIGKILL`ed after 7 sessions: manifest intact, resume
  cleaned up the 2 orphaned containers and 1 network the kill left behind,
  skipped exactly those 7, ran the remaining 3, finished with zero orphans.
- IPv4 and IPv6 sessions both complete; `docker compose`-free, all through the
  Docker SDK.
- Ruff, ruff-format and mypy strict clean across `analyzer` and `testbed`.

### Not verified

- **The `testbed` CI job has not run on GitHub Actions.** It passes locally via
  `./scripts/ci-local.sh testbed`. Whether an Actions runner permits
  `modprobe esp4` and `NET_ADMIN` containers is untested; if it does not, the
  job needs either a privileged step or removal, and Phase 2 falls back to being
  verified locally only.
- **Step 2.6 at full duration.** The generator profiles were measured over
  25-second sessions, not the 180 seconds the matrix specifies. Rates and shapes
  should hold; absolute packet counts will not.
- **Step 2.9 at scale.** The sampler produces 60 configurations, but no full
  60-session batch has been run end to end — the longest is 10. That is step 8.1.

### Deviations from the specs

- **`guarantee_full_coverage` is read as full-strength coverage across those
  dimensions**, not merely as a promise that each value appears. Plain greedy
  all-pairs covers this matrix in 37 rows, below the 40–60 that step 2.9
  specifies, and covers `mode`, `esp`, `pfs` and `ike` only in pairs — so there
  would be no 3DES-with-PFS-on-IKEv2 row unless the greedy step happened to want
  one. Those four are exactly what Track A parses and the policy scores. Reading
  the key the way covering-array tools read it gives all 60 of their
  combinations, covers all 257 pairs, and lands inside the planned range.
- **The IKE proposal is CBC-plus-HMAC even for the AEAD suites.** IKEv1 cannot
  negotiate an AEAD cipher for Phase 1, so deriving the IKE proposal from the
  ESP suite would make every `ikev1` × `gcm` cell of the matrix fail to
  negotiate. ESP still carries the AEAD. This is also how a great many real
  deployments are configured.
- **Rekey jitter is disabled** (`rand_time = 0`). strongSwan jitters by up to
  10% of `rekey_time` by default — exactly the tolerance step 9.3 measures
  against. Real deployments do jitter; a labelled dataset should not.
- **`testbed/` gained six modules** the LLD §2 tree does not list (`config.py`,
  `peers.py`, `tunnel.py`, `capture.py`, `sampler.py`, `batch.py`). §2 lists
  `orchestrator.py` alone; the lifecycle, capture and sampling concerns are
  genuinely separate and testable apart.
- **Captures are filtered** to `esp or ah or udp port 500 or udp port 4500`.
  The peers also emit ARP, neighbour discovery and multicast chatter that has
  nothing to do with the tunnel, and a model trained on unfiltered captures
  would have that container noise available as signal.

### Open spec questions

6. **The matrix has no NAT dimension.** ESP here is raw protocol 50 because the
   peers share a bridge and no NAT is detected, so nothing in the dataset
   exercises UDP-encapsulated ESP. Step 4.7 must parse NAT-T and step 3.3 must
   disambiguate IKE from ESP on port 4500, and neither will have testbed data to
   work from. Either the matrix needs a `nat` dimension or those steps need
   captures from elsewhere.
7. **`SessionConfig.duration_s` versus PRD §9.3.** The matrix specifies 180
   seconds per session and ≥200 sessions; 60 configurations at 180 seconds is
   about 3 hours of tunnel time before traffic-run multiplicity. Step 8.3
   budgets 8 hours, so this fits — but the number of traffic runs per
   configuration is specified nowhere.

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
