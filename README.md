# AI-Powered IPsec VPN Protocol Analyzer

Determines the security posture of an IPsec deployment from captured network
traffic alone — no access to the gateways, no configuration files, no decryption.

Smart India Hackathon 2026. *(Product name still open — PRD §14, OQ-1.)*

---

## The problem

IPsec's security depends entirely on how it is configured. A tunnel running
3DES with DH Group 2 and no Perfect Forward Secrecy is "encrypted" and passes a
naive audit, while offering materially weaker protection than one running
AES-256-GCM with DH Group 19. Telling those two apart today needs an expert with
Wireshark, hand-written filter expressions, and knowledge of how IKE payloads
are laid out. That does not scale to hundreds of tunnels, and it produces
nothing a CISO or an auditor can act on.

## How it works

One architectural decision governs everything: **IPsec leaks in two distinct
ways, and each needs a different technique.**

**Track A — deterministic parsing.** IKE negotiation is partly cleartext. The
IKEv2 `IKE_SA_INIT` exchange and IKEv1 Phase 1 SA payloads carry the proposed
transforms in the open: encryption algorithm, integrity algorithm, PRF, DH
group, SPIs. A parser extracts these with certainty. No model is involved.

**Track B — statistical inference.** Once the SA is established, everything is
inside ESP: an outer IP header, an SPI, a sequence number, and an opaque blob.
Inner traffic type, operating mode, and cipher family are inferred from flow
statistics and packet geometry, each carrying a calibrated confidence.

Every field in every output is tagged **observed**, **inferred** (with a
probability), or **unavailable** (with a reason). An analyst acting on the report
needs to know which claims are facts and which are estimates — and the type
system enforces the distinction rather than trusting anyone to remember it.

> AES-128 and AES-256 are indistinguishable from ESP alone. The tool reports
> that as unavailable, with the reason, rather than guessing. Credibility from a
> stated limit beats the credit from an unsupportable claim.

### The metadata thesis

The traffic classifier doubles as the leakage metric. If it identifies inner
traffic as VoIP at 94% confidence, that confidence *is* the measurement of what
a passive adversary learns. A well-padded tunnel should leave the classifier
uncertain, and that uncertainty is a good security outcome. This inverts the
usual ML objective in one specific place and gives the security score a
component no comparable tool reports.

---

## Current status

Gate **G4 — Feature complete**. Both tracks run, both report formats generate,
the degradation suite passes, and the PRD §16 demo has been rehearsed
end to end on the air-gapped stack — three consecutive clean runs at 21 seconds
against a two-minute target.

| Module | State |
|---|---|
| Core contract (`core/schema.py`) | **Done** — the single source of truth |
| Database, migrations, session factory | **Done** — PostgreSQL and SQLite |
| M1 Testbed | **Done** — builds real tunnels; needs Docker to run |
| M2 Ingest | **Done** — pcap reader, flow assembly, capture quality |
| M3 Track A | **Done** — IKE parsing, correlation, `SecurityAssociation` |
| M4 Track B | **Done** — sieve, replay, PFS, and both trained models |
| M5 Assessment | **Done** — 14-rule policy, scoring, threat matrix |
| M6 Presentation | **Done** — dashboard, both PDF report formats |
| Dataset | **Done** — 248 labelled sessions, 0 failures |

**The models, and how to read their scores.**

| Model | Metric | Result | Target | |
|---|---|---|---|---|
| ML-1 traffic class (LightGBM) | macro-F1 | 1.0000 | — | baseline |
| ML-1 traffic class (CNN) | macro-F1 | 1.0000 | ≥0.85 (PRD §8.4) | met |
| ML-1 traffic class (CNN) | ECE | 0.0024 | ≤0.10 (PRD §8.4) | met |
| ML-2 operating mode | accuracy | 1.0000 | ≥0.90 (step 9.9) | met |

**Those numbers are a reason to be suspicious, not to be pleased, and
[docs/model-card.md](docs/model-card.md) says so at length rather than in a
footnote.** Leakage was ruled out directly — train, calibration and test hold
disjoint sets of *configurations*, asserted on the real split. What is left is
that the task as posed is nearly separable: seven traffic classes produced by
different tools at rates differing by orders of magnitude, and a mode
classifier whose strongest feature is close to a direct measurement of the
inner IP header. The scores measure **how distinct this testbed's generators
are**. They are not evidence of generalisation to real traffic.

**What is honestly not finished.**

- **External validation (step 9.12) is unmeasured.** ISCXVPN2016 needs a
  registration form and several gigabytes and has not been downloaded. The
  adapter and the evaluation are implemented and tested against synthetic
  captures shaped like that corpus, so it is one command away for anyone with
  the data — but until it runs, this project has *no evidence its models
  generalise beyond its own testbed*.
- **The demonstration video (step 11.8) has not been recorded.**
  [docs/demo-script.md](docs/demo-script.md) is the shot list and narration.
- **Two manual checks need a Neon connection string** (MT-08, MT-09) and are
  the only rows in [manualtesting.md](manualtesting.md) still unrun.

See [CHANGELOG.md](CHANGELOG.md) for exactly what landed and what did not, and
[manualtesting.md](manualtesting.md) for what has been confirmed by hand.

## Try it

The air-gapped stack is the one to use — it is what the demo runs on, it needs
no database server, and its backing network has no route off the machine:

```bash
docker compose -f docker-compose.offline.yml up -d --build
```

Open <http://localhost:3000> and upload one of the two prepared captures in
[dataset/demo/](dataset/demo/): `demo-tunnel-a` is deliberately weak (IKEv1
aggressive, 3DES, DH-2, no PFS) and `demo-tunnel-b` is hardened (IKEv2,
AES-256-GCM, DH-19, PFS). They score 25 and 80.

To check the whole path without clicking:

```bash
python scripts/demo_rehearsal.py --runs 3
```

For development, without Docker:

```bash
cd backend && uv sync --all-groups && uv run alembic upgrade head
uv run uvicorn analyzer.api.main:create_app --factory --port 8000 &

cd ../frontend && npm ci && npm run dev
```

`USE_FIXTURES=1 npm run dev` renders the two demo assessments with the backend
switched off entirely, which is the fastest way to see what the product claims.

Both PDF reports:

```bash
curl -o exec.pdf  "localhost:8000/api/v1/assessments/<id>/report?format=executive"
curl -o tech.pdf  "localhost:8000/api/v1/assessments/<id>/report?format=technical"
```

---

## Quick start

Full instructions, including the Neon setup and the failure modes worth knowing
about, are in **[startup.md](startup.md)**. The short version:

```bash
git clone https://github.com/Piyush800x/ipsec-analyzer.git
cd ipsec-analyzer

cp .env.example .env          # then set DATABASE_URL — see startup.md §3
cd backend && mkdir -p data && uv sync --all-groups && uv run alembic upgrade head
uv run pytest                 # expect 675 passed, 62 skipped
```

`--all-groups`, not a bare `uv sync`: the optional groups carry the testbed,
the report renderer and the policy loader, and without them four test modules
fail at collection.

For the offline path, one line in `.env` is enough:

```
DATABASE_URL=sqlite+aiosqlite:///./data/analyzer.db
```

---

## Layout

```
ipsec-analyzer/
├── backend/              Python 3.11, uv, FastAPI (Phase 6)
│   ├── src/analyzer/
│   │   ├── core/         schema.py — the contract everything derives from
│   │   ├── ingest/       M2 — PCAP reading, flow assembly
│   │   ├── track_a/      M3 — deterministic IKE parsing
│   │   ├── track_b/      M4 — statistical inference over ESP
│   │   ├── assess/       M5 — rules, scoring, threat matrix
│   │   ├── report/       M6 — executive and technical PDFs
│   │   ├── db/           SQLAlchemy models, session factory
│   │   └── api/          FastAPI application
│   ├── alembic/          migrations
│   ├── testbed/          M1 — tunnel orchestration, traffic generation
│   └── tests/            including the two demo fixtures
├── frontend/             Next.js 16, App Router, TypeScript, Tailwind
│   └── models/           the trained Track B artefacts, committed
├── dataset/
│   ├── sessions/         248 labelled captures (Phase 8, DVC-tracked)
│   └── demo/             the two frozen PRD §16 captures (step 11.5)
├── docs/                 the specifications, plus the model card and demo script
└── scripts/              ci-local.sh, pg-dev.sh, demo_rehearsal.py
```

Every module above is implemented, and `backend/models/` carries the trained
artefacts — 3.7 MB, committed, so a clean clone has working inference. What
each one scored and on what is in [docs/model-card.md](docs/model-card.md),
generated from `models/metrics.json` rather than written by hand.

---

## Documentation

| Document | What it is for |
|---|---|
| [docs/ipsec-analyzer-prd.md](docs/ipsec-analyzer-prd.md) | Requirements (FR-x.y, NFR-x), scoring rubric, demo script |
| [docs/LLD.md](docs/LLD.md) | Schemas, interfaces, algorithms, contracts |
| [docs/implementation-plan.md](docs/implementation-plan.md) | Ordered steps, each with a **Done when** condition |
| [docs/database-setup.md](docs/database-setup.md) | Neon branches, pooled vs direct, migrations |
| [startup.md](startup.md) | Getting a working environment |
| [CHANGELOG.md](CHANGELOG.md) | What has landed, and what has not been verified |
| [manualtesting.md](manualtesting.md) | Checks a person runs by hand, with results |
| [CLAUDE.md](CLAUDE.md) | Conventions — naming, IDs, time, the DB rules |

When this README and the specifications disagree, the specifications win.

---

## Development

```bash
./scripts/ci-local.sh              # everything CI runs, backend and frontend
./scripts/ci-local.sh backend      # just the backend half

cd backend
uv run ruff check . && uv run ruff format .
uv run mypy
uv run pytest
```

The database layer must behave **identically on PostgreSQL and SQLite**, so
every database test runs against both. The PostgreSQL half is skipped unless
`TEST_POSTGRES_URL` is set — a green run without it proves half of what it looks
like it proves:

```bash
./scripts/pg-dev.sh up
export TEST_POSTGRES_URL="$(./scripts/pg-dev.sh url)"
cd backend && uv run pytest
```

Conventions worth knowing before your first commit: Ruff at line length 100,
full type annotations with mypy strict, UUIDv7 primary keys, UTC timezone-aware
timestamps, `snake_case` in Python *and* the database, and RFC 9457 Problem
Details for every API error. [CLAUDE.md](CLAUDE.md) has the reasoning.

---

## A note on where data goes

Uploaded captures are processed locally and PCAP bytes never leave the machine
(NFR-6). Neon, however, is a hosted database — so with the default
configuration, assessment metadata such as endpoint addresses, SPIs and findings
does leave. For a demo in front of a security audience, or any real deployment,
run the offline configuration on SQLite. The choice is yours to make explicitly
rather than discover later.

---

## Licence

MIT. See [LICENSE](LICENSE).

The dataset licence is a separate, still-open question (PRD §14, OQ-6).
