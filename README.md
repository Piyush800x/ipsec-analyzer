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

Gate **G1 — Contract locked**. The contract and the storage layer exist; the
analysis pipeline does not yet.

| Module | State |
|---|---|
| Core contract (`core/schema.py`) | **Done** — the single source of truth |
| Database, migrations, session factory | **Done** — PostgreSQL and SQLite |
| Settings, CI, container toolchain | **Done** |
| Demo fixtures | **Done** — two hand-written assessments |
| M1 Testbed · M2 Ingest · M3 Track A | Not started |
| M4 Track B · M5 Assessment · M6 Presentation | Not started |

There is no API and no dashboard yet — `npm run dev` serves the stock Next.js
page. What you can do today is run the test suite, exercise the migrations
against either backend, and build against the two fixture assessments.

See [CHANGELOG.md](CHANGELOG.md) for exactly what landed, and
[manualtesting.md](manualtesting.md) for what has been confirmed by hand.

---

## Quick start

Full instructions, including the Neon setup and the failure modes worth knowing
about, are in **[startup.md](startup.md)**. The short version:

```bash
git clone https://github.com/Piyush800x/ipsec-analyzer.git
cd ipsec-analyzer

cp .env.example .env          # then set DATABASE_URL — see startup.md §3
cd backend && mkdir -p data && uv sync && uv run alembic upgrade head
uv run pytest
```

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
├── dataset/              labelled captures (Phase 8, DVC-tracked)
├── docs/                 the specifications
└── scripts/              ci-local.sh, pg-dev.sh
```

Modules carrying only a docstring are skeletons for a later phase. That is
deliberate: the import graph and the plan agree from day one.

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
