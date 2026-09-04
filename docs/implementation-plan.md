# Implementation Plan

## AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

| Field | Value |
|---|---|
| Version | 1.0 |
| Companion documents | `ipsec-analyzer-prd.md` v1.0, `LLD.md` v1.0 |
| Horizon | 12 weeks |
| Last updated | 3 September 2026 |

---

## How to use this document

Every step is sized to fit one work session — roughly 2 to 6 hours — and ends in a commit. A step is done when its **Done when** line is objectively true, not when it feels finished.

**Workstreams.** Four parallel tracks. Assign one owner each; pair for the hard steps.

| Code | Track | Scope |
|---|---|---|
| **P** | Platform | Core schema, database, API, jobs, deployment, CI |
| **N** | Network | Testbed, ingest, Track A parsing |
| **M** | ML | Features, Track B models, calibration, evaluation |
| **F** | Frontend | Next.js app, dashboard views, reports |

**Rules.**

1. Do not start Phase 2 until Step 1.3 is merged. Everything depends on the schema.
2. Any step whose **Done when** cannot be demonstrated is not done. No exceptions in week 11.
3. When a step overruns by more than 2×, stop and raise it. That is a signal, not a personal failing.

**Notation.** `[P]` = workstream. `~4h` = estimate. `→ 1.3` = depends on step 1.3.

---

## Phase 0 — De-risk and set up (Week 1)

The single largest risk in this project is that container-based IPsec does not work on your machines. Find out on day one, not in week four.

### 0.1 Spike: kernel IPsec in Docker `[N]` `~4h`

Manually, no automation. Two Alpine or Debian containers on a user-defined bridge network, strongSwan installed, one IKEv2 tunnel between them.

```bash
docker run -d --name left  --cap-add=NET_ADMIN --network ipsec-net ...
docker run -d --name right --cap-add=NET_ADMIN --network ipsec-net ...
# configure swanctl.conf by hand on both
docker exec left swanctl --initiate --child net
docker exec left swanctl --list-sas
```

**Done when:** `swanctl --list-sas` shows `ESTABLISHED`, and `tcpdump -i eth0 esp` inside the container shows ESP packets flowing during a `ping` between the protected subnets.

**If it fails:** try `--privileged` to isolate whether it is a capability issue. If it still fails, switch to Vagrant + libvirt VMs and record the decision. Do **not** reach for `kernel-libipsec` — see LLD §10.3.

### 0.2 Spike: confirm packet geometry `[N]` `~2h` → 0.1

Capture 200 packets from the 0.1 tunnel. In a Python REPL, extract ESP payload lengths and check `(len - 16 - 12) % 16 == 0` for an AES-CBC + SHA1 config.

**Done when:** the congruence holds for every packet. This validates the core premise of LLD §7.2 before anyone builds on it.

### 0.3 Repository skeleton `[P]` `~3h`

Create the tree from LLD §2. `uv init` for the backend, `create-next-app` for the frontend. Add `.gitignore`, `.editorconfig`, `LICENSE`.

**Done when:** `uv run python -c "import analyzer"` and `npm run dev` both succeed from a clean clone.

### 0.4 CI pipeline `[P]` `~3h` → 0.3

GitHub Actions: Ruff, mypy, pytest, `npm run build`, `tsc --noEmit`.

**Done when:** a PR with a deliberate lint error is blocked by CI.

### 0.5 Neon project and branches `[P]` `~2h`

Create the Neon project. Create one database branch per developer. Store the pooled and direct connection strings in `.env.example` with placeholder values.

**Done when:** each team member can `psql` into their own branch and `SELECT 1`.

### 0.6 Tshark version pin `[N]` `~1h`

Add tshark to the backend Dockerfile with an explicit version. Record it in `pyproject.toml` metadata.

**Done when:** `docker run <image> tshark --version` prints the pinned version. LLD §6.1 explains why this matters.

---

## Phase 1 — Contract and storage (Week 1–2)

Nothing else can start in earnest until this phase lands. Prioritise it over everything.

### 1.1 Enums `[P]` `~2h`

`core/enums.py`: `Provenance`, `IkeVersion`, `IkeExchangeMode`, `EncryptionAlg`, `IntegrityAlg`, `PrfAlg`, `OperatingMode`, `TrafficClass`, `Severity`, `FindingCategory`, `AuthMethod`.

**Done when:** every enum from LLD §3 exists with a docstring.

### 1.2 Evidence and Attribute `[P]` `~3h` → 1.1

`core/schema.py`: `Evidence`, `Attribute[T]` with the validator from LLD §3.

**Done when:** a test proves that constructing `Attribute(provenance=INFERRED, confidence=None)` raises, and `Attribute(provenance=OBSERVED, confidence=0.9)` also raises.

### 1.3 Full contract `[P]` `~5h` → 1.2

The rest of LLD §3: `SecurityAssociation`, `TrafficPrediction`, `Finding`, `Assessment`, `ScoreBreakdown`, `MetadataExposure`, `CaptureQuality`, `ThreatMatrixEntry`.

**Done when:** `Assessment.model_json_schema()` renders without error, and a hand-written fixture `Assessment` round-trips through `model_dump_json` and `model_validate_json` unchanged.

**This is the unblocking milestone. Announce it to the team.**

### 1.4 Fixture assessments `[P]` `~3h` → 1.3

Write two realistic `Assessment` JSON fixtures by hand: `tests/fixtures/assessment_weak.json` and `assessment_strong.json`, matching the demo tunnels from PRD §16.

**Done when:** both validate against the model. The frontend and report workstreams now have real data to build against, months before the engine produces any.

### 1.5 SQLAlchemy models `[P]` `~4h` → 1.3

`db/models.py` implementing LLD §4.3. `sa.JSON` not `JSONB`, `sa.Uuid` for keys.

**Done when:** `Base.metadata.create_all()` runs against both SQLite and Postgres.

### 1.6 Alembic setup and first migration `[P]` `~3h` → 1.5

Initialise Alembic. Autogenerate the initial migration. Add the dialect-guarded `JSON → JSONB` step for Postgres.

**Done when:** `alembic upgrade head` then `alembic downgrade base` succeeds cleanly on both backends.

### 1.7 Session factory with Neon handling `[P]` `~2h` → 1.6

`db/session.py` with the `statement_cache_size=0` and `pool_pre_ping` handling from LLD §4.2.

**Done when:** a smoke test opens a session against the Neon pooled endpoint and executes a query without a prepared-statement error.

### 1.8 Settings `[P]` `~2h`

`core/config.py` using `pydantic-settings`: `DATABASE_URL`, `STORAGE_PATH`, `POLICY_PATH`, `MODEL_DIR`, `MAX_UPLOAD_BYTES`, `MAX_CONCURRENT_ANALYSES`.

**Done when:** the app refuses to start with a clear error when `DATABASE_URL` is unset.

---

## Phase 2 — Testbed (Week 2–4)

Critical path for the ML workstream. Start the moment 0.1 passes.

### 2.1 Peer container image `[N]` `~4h` → 0.1

`testbed/Dockerfile.peer`: strongSwan, tcpdump, iproute2, plus the traffic generators (`sipp`, `ffmpeg`, `curl`, `swaks`, `iperf3`).

**Done when:** the image builds and `swanctl --version` runs inside it.

### 2.2 Config templating `[N]` `~4h` → 2.1

`templates/swanctl.conf.j2` plus `SessionConfig` → rendered config. Cover every dimension in LLD §10.1.

**Done when:** rendering the `weak-reference` and `hardened-reference` fixtures produces configs that strongSwan loads without error (`swanctl --load-all`).

### 2.3 Peer lifecycle context manager `[N]` `~4h` → 2.2

`peer_pair(cfg)` — creates the network, starts both containers, yields handles, tears everything down. Must clean up on exception.

**Done when:** running it 20 times in a loop leaves zero orphaned containers or networks (`docker ps -a` and `docker network ls` are clean).

### 2.4 Tunnel bring-up and assertion `[N]` `~3h` → 2.3

`bring_up_tunnel()` and `assert_sa_established()` polling `swanctl --list-sas` with a timeout.

**Done when:** a deliberately broken config (mismatched PSK) fails fast with a clear exception instead of proceeding. LLD §10.2 explains why this guard is non-negotiable.

### 2.5 Capture wrapper `[N]` `~2h` → 2.3

`start_tcpdump()` / `capture.stop()` returning a PCAP path.

**Done when:** a captured file opens in Wireshark and contains both IKE and ESP.

### 2.6 Traffic generators `[N]` `~6h` → 2.1

One module per class in `testbed/traffic/`: `icmp.py`, `web.py`, `voip.py`, `video.py`, `email.py`, `filexfer.py`, `messaging.py`. Each exposes `async def generate(left, right, duration_s)`.

**Done when:** each generator produces a capture whose packet-rate and size profile visibly differs from the others when plotted. Eyeball this — if two classes look identical, the classifier will never separate them either.

### 2.7 Ground-truth emitter `[N]` `~2h` → 2.2

`SessionConfig.to_ground_truth()` → `labels.json` recording every configured parameter.

**Done when:** the label file for the `weak-reference` fixture contains all nine dimensions with correct values.

### 2.8 Session runner `[N]` `~3h` → 2.4, 2.5, 2.6, 2.7

`run_session(cfg)` from LLD §10.2, including tunnel teardown inside the capture window.

**Done when:** one end-to-end session produces `capture.pcap` + `labels.json`, and the PCAP contains an IKE DELETE exchange.

### 2.9 Matrix sampler `[N]` `~3h`

`matrix.yaml` per LLD §10.1 plus pairwise sampling with the fixed seed.

**Done when:** sampling produces 40–60 configurations, every value of every dimension appears at least once, and re-running with the same seed produces an identical list.

### 2.10 Batch orchestrator `[N]` `~3h` → 2.8, 2.9

Run the sampled matrix, with resume-on-failure and a manifest of completed sessions.

**Done when:** a 10-session batch completes, and killing it midway then restarting skips the sessions already done.

---

## Phase 3 — Ingest (Week 3–4)

### 3.1 PacketRecord and FlowKey `[N]` `~2h` → 1.3

`ingest/reader.py` types per LLD §5.

**Done when:** types are defined and typed.

### 3.2 PCAP reader — IPv4 `[N]` `~5h` → 3.1

`dpkt`-based reader. Handle Ethernet, SLL, SLL2, raw IP. Decode outer IPv4, identify ESP (50), AH (51), UDP/500, UDP/4500.

**Done when:** reading a Phase 2 capture yields the same packet count as `tshark -r file | wc -l`.

### 3.3 UDP 4500 disambiguation `[N]` `~2h` → 3.2

First four bytes `00000000` → IKE, otherwise ESP SPI. LLD §5.

**Done when:** a NAT-T capture classifies IKE and ESP packets correctly on the same port.

### 3.4 IPv6 support `[N]` `~4h` → 3.2

Walk the extension header chain to find ESP/AH.

**Done when:** an IPv6 testbed capture parses with correct SPI extraction.

### 3.5 Flow assembly `[N]` `~4h` → 3.2

Group by `FlowKey`, pair directional SAs into `SAPair` by reversed endpoints and overlapping time ranges. Retain and flag unpaired SAs.

**Done when:** a bidirectional capture yields exactly one `SAPair`; a one-directional capture yields one flagged unpaired SA rather than an error.

### 3.6 Capture quality `[N]` `~3h` → 3.5

`ingest/quality.py` producing `CaptureQuality`, including `truncated`, `has_ike`, `ike_complete`, and `sufficient_for_lattice` (≥200 ESP packets, ≥8 distinct lengths).

**Done when:** a capture taken with `tcpdump -s 96` sets `truncated = true`, and a VoIP-only capture sets `sufficient_for_lattice = false`.

**This second assertion matters.** It is the guard that prevents the cipher detector from producing a confident wrong answer during your demo. See LLD §7.2.

---

## Phase 4 — Track A (Week 3–5)

### 4.1 Tshark invocation wrapper `[N]` `~3h` → 0.6

Subprocess call, JSON parse, error handling for malformed output.

**Done when:** running against a Phase 2 IKEv2 capture returns a parsed structure with the ISAKMP payloads present.

### 4.2 IKEv2 SA payload extraction `[N]` `~5h` → 4.1

Proposals → transforms, keyed by type 1 (ENCR), 2 (PRF), 3 (INTEG), 4 (DH), 5 (ESN). Key length from ENCR attribute 14.

**Done when:** a capture from a known `aes256gcm16` + DH-19 config extracts exactly those values.

### 4.3 IKEv1 SA payload extraction `[N]` `~5h` → 4.1

Different attribute encoding from IKEv2. Handle both basic and variable-length attribute forms. Extract exchange mode from the header (2 = main, 4 = aggressive).

**Done when:** IKEv1 main and aggressive captures both parse, and the exchange mode is correct for each.

### 4.4 Proposed vs selected `[N]` `~3h` → 4.2, 4.3

`IkeNegotiation` with `proposed`, `selected`, `downgrade_available` per LLD §6.3.

**Done when:** a config offering both 3DES and AES-256 with AES-256 selected sets `downgrade_available = true`.

### 4.5 Lifetime handling `[N]` `~2h` → 4.2, 4.3

IKEv1 attributes 1 and 2. **IKEv2 must return `UNAVAILABLE`** — RFC 7296 removed lifetime negotiation. LLD §6.4.

**Done when:** an IKEv2 capture yields `negotiated_lifetime_s.provenance == UNAVAILABLE`, and an IKEv1 capture yields the configured value.

### 4.6 SPI correlation `[N]` `~3h` → 4.2

Link IKE SA to its Child SAs; associate Child SPIs with the ESP flows from 3.5.

**Done when:** ESP flows in a testbed capture resolve to the IKE negotiation that created them.

### 4.7 NAT-T and auth method `[N]` `~3h` → 4.2

NAT_DETECTION notify payloads; IKEv1 auth method from transform attribute 3. IKEv2 auth is inside encrypted `IKE_AUTH` — return `UNAVAILABLE`.

**Done when:** both cases behave correctly and the IKEv2 case does not fabricate a value.

### 4.8 Track A → SecurityAssociation `[N]` `~4h` → 4.4, 4.5, 4.6, 4.7

Assemble parsed output into `SecurityAssociation`, every field tagged `OBSERVED`.

**Done when:** running Track A on a testbed capture produces a `SecurityAssociation` whose values match `labels.json` exactly, for every parseable field. Write this as an automated test — it becomes your regression suite for the whole parser.

---

## Phase 5 — Assessment engine (Week 5–7)

Build this against fixtures. It does not need Track B, and finishing it early means you have a shippable product even if the ML underdelivers.

### 5.1 Policy schema and loader `[P]` `~4h` → 1.3

Pydantic models for the YAML in LLD §8.1. Operators: `eq`, `in`, `lt`, `gt`, `confidence_gte`, `all`, `any`.

**Done when:** a malformed policy file fails at load with a line-referenced error.

### 5.2 Confidence-guard validator `[P]` `~2h` → 5.1

At load time, reject any rule keyed on an attribute that can be `INFERRED` unless it carries a `confidence_gte` guard.

**Done when:** a policy with an unguarded `pfs_enabled` rule fails to load. LLD §8.1 explains why this is a startup error rather than a runtime one.

### 5.3 Baseline policy file `[P]` `~5h` → 5.1

Write `policies/baseline.yaml`. Minimum rule set:

`CRYPTO-3DES`, `CRYPTO-DES`, `CRYPTO-NULL-ENC`, `CRYPTO-WEAK-INTEG-MD5`, `CRYPTO-SHA1`, `CRYPTO-DOWNGRADE-OFFER`, `KEX-WEAK-DH`, `KEX-PFS-DISABLED`, `PROTO-IKEV1`, `PROTO-AGGRESSIVE-MODE`, `KEYMGMT-LONG-LIFETIME`, `KEYMGMT-NO-REKEY-OBSERVED`, `REPLAY-SEQ-ANOMALY`, `META-HIGH-EXPOSURE`.

Each with severity, penalty, remediation text naming the exact strongSwan parameter, standards references, and ATT&CK IDs.

**Done when:** all 14 rules load and the penalties sum within the category caps from PRD §10.1.

### 5.4 Rule evaluator `[P]` `~4h` → 5.2, 5.3

`_eval_sa()` producing `Finding` objects with populated `Evidence`.

**Done when:** evaluating `assessment_weak.json`'s SAs produces the expected finding IDs, asserted exactly in a test.

### 5.5 Scoring `[P]` `~3h` → 5.4

Category caps, descending-penalty ordering, floor at zero. LLD §8.3.

**Done when:** property tests pass — score always in [0,100], adding a finding never raises the score, caps never exceeded.

### 5.6 Metadata exposure `[P]` `~3h` → 1.3

Chance-level-scaled formula from LLD §8.4.

**Done when:** mean confidence at 1/7 yields exposure 0; mean confidence at 1.0 yields 100.

### 5.7 Threat matrix `[P]` `~2h` → 5.4

Group findings by ATT&CK technique.

**Done when:** the weak fixture produces entries for T1040, T1557, and T1600.

### 5.8 Evidence caps `[P]` `~2h` → 5.4

Cap `packet_indices` at 20 with `total_matching` alongside.

**Done when:** a synthetic finding matching 100,000 packets serialises to under 2 KB.

### 5.9 Determinism test `[P]` `~2h` → 5.5

Run `evaluate()` twice on identical input; assert byte-identical JSON after stripping IDs and timestamps.

**Done when:** the test passes and is wired into CI. This is NFR-4.

---

## Phase 6 — API and jobs (Week 6–8)

### 6.1 FastAPI skeleton `[P]` `~2h` → 1.7, 1.8

App factory, router mounting, `/health` with a DB reachability check.

**Done when:** `/api/v1/health` returns 200 against both SQLite and Neon.

### 6.2 Problem Details errors `[P]` `~2h` → 6.1

RFC 9457 exception handlers.

**Done when:** a 404 returns `application/problem+json` with `type`, `title`, `status`, `detail`.

### 6.3 Capture upload `[P]` `~5h` → 6.1

Streaming multipart to disk in 8 MB chunks, magic-byte validation, SHA-256 dedupe, 2 GB cap.

**Done when:** a 500 MB PCAP uploads with backend memory staying flat, and a `.txt` renamed to `.pcap` is rejected before persistence.

### 6.4 Capture CRUD `[P]` `~3h` → 6.3

List with pagination, detail, delete removing both row and file.

**Done when:** delete leaves no orphaned file on disk.

### 6.5 Pipeline orchestrator `[P]` `~4h` → 3.6, 4.8, 5.4

`run_pipeline(capture_id)` chaining ingest → Track A → Track B (stubbed) → assess → persist.

**Done when:** invoking it on a testbed capture writes an `Assessment` row plus its `findings` and `security_associations` rows in one transaction.

### 6.6 Background jobs and SSE `[P]` `~5h` → 6.5

`BackgroundTasks`, `asyncio.Semaphore(2)`, CPU stages in a `ProcessPoolExecutor`, SSE progress endpoint.

**Done when:** two concurrent analyses run, a third queues, and `curl -N /runs/{id}/events` streams progress events live.

### 6.7 Assessment endpoints `[P]` `~3h` → 6.5

Full document, filterable findings from the relational table, comparison endpoint.

**Done when:** findings filter by severity and sort by penalty without touching JSON columns.

### 6.8 OpenAPI type generation `[P]` `~2h` → 6.7

`scripts/gen-types.sh` running `openapi-typescript`; CI fails on stale output.

**Done when:** changing a Pydantic field without regenerating types breaks the build.

---

## Phase 7 — Frontend (Week 7–10)

Build entirely against the 1.4 fixtures until Phase 6 is live.

### 7.1 Next.js scaffold `[F]` `~3h` → 0.3

App Router, Tailwind, shadcn/ui, base layout and navigation.

**Done when:** `npm run build` produces a clean production build.

### 7.2 API proxy route `[F]` `~3h` → 7.1

`app/api/[...path]/route.ts` forwarding to `API_BASE_URL`, with `runtime = "nodejs"` and streaming passthrough for SSE.

**Done when:** an SSE stream from the backend reaches the browser without buffering.

### 7.3 Fixture-backed data layer `[F]` `~3h` → 1.4, 7.1

A `getAssessment()` that reads fixtures when `USE_FIXTURES=1` and the API otherwise.

**Done when:** the app renders the weak fixture with the backend entirely offline.

### 7.4 AttributeCell component `[F]` `~5h` → 7.3

The three provenance renderings from LLD §11.3. Observed plain, inferred with a confidence bar, unavailable with an explicit reason.

**Done when:** all three render correctly, and the unavailable state shows explanatory text rather than a dash.

**This is the most important component in the product.** Give it real design attention — it is the visual expression of the entire thesis.

### 7.5 Capture list and upload `[F]` `~5h` → 7.2

List view, drag-and-drop upload via `XMLHttpRequest` with a progress bar.

**Done when:** uploading a 200 MB file shows accurate live progress.

### 7.6 Run progress view `[F]` `~4h` → 7.2

`EventSource` consumption, stage indicator, error surfacing.

**Done when:** the UI reflects each pipeline stage as it happens and displays a failure clearly.

### 7.7 Assessment layout and overview `[F]` `~5h` → 7.4

Score header, rating, severity breakdown, capture quality summary, tab navigation.

**Done when:** the weak and strong fixtures render with visibly different scores and severity distributions.

### 7.8 Configuration view `[F]` `~4h` → 7.4

Full parameter table using `AttributeCell` throughout.

**Done when:** AES key length on an ESP-only fixture renders as unavailable with its reason visible.

### 7.9 Findings view `[F]` `~5h` → 7.7

Sortable, filterable table; expandable rows showing evidence and remediation.

**Done when:** filtering by critical severity and sorting by penalty both work client-side on 50 findings.

### 7.10 Traffic view `[F]` `~5h` → 7.7

Recharts timeline of inferred traffic classes with confidence bands.

**Done when:** overlapping prediction windows render without visual collision.

### 7.11 Threat matrix view `[F]` `~3h` → 7.7

ATT&CK technique grid linked to contributing findings.

**Done when:** clicking a technique filters the findings view to its contributors.

### 7.12 Comparison view `[F]` `~4h` → 7.7

Two assessments side by side with a per-parameter diff.

**Done when:** weak vs strong fixtures render a clear diff. This view is the backbone of the demo.

---

## Phase 8 — Dataset generation (Week 6–8)

Runs in the background while other phases proceed. Start as soon as 2.10 lands.

### 8.1 Pilot batch `[N]` `~4h` → 2.10

20 sessions across diverse configurations.

**Done when:** all 20 produce valid PCAPs, and Track A (4.8) reproduces `labels.json` for each.

### 8.2 Label verification harness `[N]` `~3h` → 8.1

Automated check: Track A output vs ground truth, across the whole batch.

**Done when:** it reports zero mismatches on the pilot, or the mismatches are explained and fixed.

### 8.3 Full generation run `[N]` `~8h wall, mostly unattended` → 8.2

The full sampled matrix, multiple traffic runs per configuration.

**Done when:** ≥200 sessions on disk, all passing 8.2.

### 8.4 Dataset packaging `[N]` `~4h` → 8.3

`dataset/dataset.md` documenting schema, generation method, and licence. DVC tracking.

**Done when:** a teammate can `dvc pull` and reproduce the directory structure.

### 8.5 ISCXVPN2016 ingestion `[M]` `~4h`

Adapter mapping the external dataset into the internal feature format for cross-validation.

**Done when:** external captures produce feature vectors with the same schema as testbed captures.

---

## Phase 9 — Track B (Week 8–11)

### 9.1 Feature extractor `[M]` `~6h` → 3.5

All feature groups from LLD §7.1, in Polars.

**Done when:** extraction over a 100 MB capture completes in under 10 seconds and produces no NaNs.

### 9.2 Cipher family detector `[M]` `~5h` → 3.6

The congruence sieve from LLD §7.2, including the `sufficient_for_lattice` gate, survivor ranking, and the confidence formula.

**Done when:** it correctly identifies AES-CBC-SHA1 and AES-GCM-16 captures, and returns `UNAVAILABLE` on a VoIP-only capture rather than guessing.

### 9.3 Replay and lifetime analysis `[M]` `~4h` → 3.5

Sequence monotonicity, duplicates, gaps, SPI rotation timing. **ESN and anti-replay window size must be reported per LLD §7.5** — ESN from Track A only, window size never.

**Done when:** observed rekey interval on a capture with a 300-second lifetime lands within 10% of 300, and the anti-replay window renders as unavailable.

### 9.4 PFS inference `[M]` `~4h` → 4.2

`CREATE_CHILD_SA` size analysis with the group-size table from LLD §7.4. Lower confidence for ECP groups.

**Done when:** PFS-on and PFS-off captures with DH-14 are separated correctly, and DH-19 returns a correspondingly lower confidence.

### 9.5 Dataset assembly for ML `[M]` `~4h` → 9.1, 8.3

Feature matrices with labels, split **by configuration and session**, never by window.

**Done when:** the splitter is tested to prove no session appears in more than one split.

### 9.6 Traffic classifier baseline `[M]` `~5h` → 9.5

LightGBM over tabular features, 7 classes.

**Done when:** held-out macro-F1 is recorded as a baseline number, whatever it is.

### 9.7 CNN traffic classifier `[M]` `~8h` → 9.6

The architecture from LLD §7.6.

**Done when:** macro-F1 ≥ 0.85 on the held-out configuration split, per PRD §8.4.

### 9.8 Calibration `[M]` `~4h` → 9.7

Temperature scaling for the CNN, isotonic for LightGBM, on a disjoint calibration split.

**Done when:** ECE ≤ 0.10 and a reliability diagram is committed to the docs.

### 9.9 Mode classifier `[M]` `~5h` → 9.6

Features from LLD §7.3, with traffic classification running **first** as an input feature.

**Done when:** accuracy ≥ 0.90 and the ordering dependency is documented in the module docstring.

### 9.10 Feature attribution `[M]` `~3h` → 9.7

SHAP values surfaced as `FeatureAttribution` on predictions.

**Done when:** a prediction returns its top five contributing features.

### 9.11 Inference service `[M]` `~4h` → 9.8, 9.9

Model loading, versioning, `predict()` producing `Attribute` objects with correct provenance.

**Done when:** it slots into 6.5 replacing the stub, and the full pipeline runs end to end.

### 9.12 External validation `[M]` `~4h` → 9.8, 8.5

Evaluate the traffic classifier on ISCXVPN2016.

**Done when:** results are recorded honestly, including degradation relative to the internal test set. Report the gap; do not hide it.

---

## Phase 10 — Reports (Week 9–11)

### 10.1 Template scaffolding `[F]` `~4h` → 1.4

Jinja2 templates plus WeasyPrint CSS, rendering from fixtures.

**Done when:** both templates render to PDF from `assessment_weak.json`.

### 10.2 Executive report `[F]` `~5h` → 10.1

One to two pages: score, rating, top three risks, business-language summary. No hex, no packet indices.

**Done when:** a non-technical reader can state what is wrong and what to do about it after reading only this document.

### 10.3 Technical report `[F]` `~6h` → 10.1

Full findings, evidence, methodology, capability matrix (PRD §7), model versions, calibration figures.

**Done when:** every finding shows its evidence, and the limitations section explicitly covers the AES key length case.

### 10.4 Report endpoints `[P]` `~3h` → 10.2, 10.3, 6.7

`GET /assessments/{id}/report?format=...` streaming `application/pdf`.

**Done when:** both formats download from the dashboard.

---

## Phase 11 — Hardening and demo (Week 11–12)

### 11.1 Degradation test suite `[N]` `~5h` → 9.11

ESP-only, truncated, single-length, one-directional, IKE-mid-stream. Each must yield `UNAVAILABLE`, never a confident wrong answer.

**Done when:** all five pass. **Do not skip this step.** It is the one most likely to be dropped under time pressure and the one most likely to save the demo.

### 11.2 DB portability suite `[P]` `~3h` → 6.7

Full API test suite against SQLite and Postgres in CI.

**Done when:** both pass in a single CI run.

### 11.3 Performance validation `[P]` `~3h` → 9.11

Time a 10-minute, 100 MB capture end to end.

**Done when:** under 60 seconds (NFR-1), or the gap is profiled and the bottleneck named.

### 11.4 Offline compose `[P]` `~3h` → 6.6

`docker-compose.offline.yml` with SQLite. Verify no outbound network calls during analysis.

**Done when:** the full stack runs with networking restricted to localhost.

### 11.5 Demo capture preparation `[N]` `~3h` → 8.3

Generate and freeze the two PRD §16 captures. Store them outside the training set.

**Done when:** both are committed, and neither appears in any training split.

### 11.6 Demo rehearsal `[all]` `~4h` → 11.4, 11.5, 7.12

Full run on the offline stack, timed against the two-minute target.

**Done when:** three consecutive clean runs. Rehearse on offline compose — Neon scales to zero and a cold start mid-demo is an avoidable risk.

### 11.7 Documentation `[all]` `~6h`

README, architecture doc, API reference, dataset doc, model card.

**Done when:** a stranger can clone, run `docker compose up`, and analyse a sample capture using only the README.

### 11.8 Demonstration video `[F]` `~5h` → 11.6

Screen recording of the rehearsed script with narration.

**Done when:** under three minutes, and the metadata-exposure point (PRD §4.1) is stated explicitly.

---

## Milestone gates

Four checkpoints. If a gate is missed, cut scope rather than compressing the next phase.

| Gate | Week | Condition |
|---|---|---|
| **G1 — Contract locked** | End of week 2 | 1.3, 1.4, 1.6 merged. All four workstreams unblocked |
| **G2 — Track A shippable** | End of week 5 | 4.8 passes against testbed ground truth. A working product exists without any ML |
| **G3 — End to end** | End of week 8 | 6.6 runs ingest → Track A → assess → persist, visible in the dashboard |
| **G4 — Feature complete** | End of week 11 | 9.11 integrated, both reports generating, 11.1 passing |

---

## Descope ladder

If you fall behind, cut in this order. Cutting from the top costs the least.

1. Comparison view (7.12) — demo can show two browser tabs instead.
2. Feature attribution (9.10) — FR-4.10 is a should-have.
3. IPv6 support (3.4) — reduce the matrix to IPv4 only.
4. Mode classifier (9.9) — report operating mode as unavailable.
5. External validation (9.12) — weakens the evaluation story but not the product.
6. CNN (9.7) — ship the LightGBM baseline from 9.6.
7. PFS inference (9.4) — Track A still reports PFS when IKE is captured.

**Never cut:** 1.3, 4.8, 5.5, 9.2, 11.1, 11.5. The contract, the parser, the scoring, the cipher detector, the degradation suite, and the demo captures are the product.
