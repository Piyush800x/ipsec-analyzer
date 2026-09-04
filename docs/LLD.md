# Low-Level Design

## AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

| Field | Value |
|---|---|
| Version | 1.0 (draft) |
| Companion document | `ipsec-analyzer-prd.md` v1.0 |
| Status | For team review |
| Last updated | 3 September 2026 |

This document specifies implementation-level structure: schemas, interfaces, algorithms, and contracts. It assumes the PRD's requirement IDs (FR-x.y, NFR-x) and does not restate rationale.

**Decisions this document closes:**

- **OQ-2** — frontend is Next.js (App Router) with a FastAPI backend.
- **Storage** — PostgreSQL on Neon by default; SQLite when `DATABASE_URL` points at a local file (offline / air-gapped mode).

---

## 1. Conventions

| Convention | Rule |
|---|---|
| Language | Python 3.11+ backend, TypeScript 5.x frontend |
| Python style | Ruff (line length 100), full type annotations, `from __future__ import annotations` |
| IDs | UUIDv7 for all entity primary keys (time-sortable) |
| Timestamps | UTC, timezone-aware, ISO 8601 in all JSON |
| Naming | `snake_case` in Python and the database, `camelCase` in TypeScript; conversion at the API boundary via Pydantic aliases |
| Errors | RFC 9457 Problem Details for all API error responses |
| Enums | Defined once in `core/enums.py`, mirrored to TypeScript by codegen |

---

## 2. Repository layout

```
ipsec-analyzer/
├── docker-compose.yml
├── docker-compose.offline.yml
├── backend/
│   ├── pyproject.toml
│   ├── alembic/
│   ├── src/analyzer/
│   │   ├── core/
│   │   │   ├── enums.py
│   │   │   ├── schema.py           # Pydantic contract — §3
│   │   │   ├── config.py
│   │   │   └── errors.py
│   │   ├── ingest/
│   │   │   ├── reader.py           # §5
│   │   │   ├── flow.py
│   │   │   └── quality.py
│   │   ├── track_a/
│   │   │   ├── ike_parser.py       # §6
│   │   │   ├── transforms.py
│   │   │   └── correlate.py
│   │   ├── track_b/
│   │   │   ├── features.py         # §7.1
│   │   │   ├── cipher_family.py    # §7.2
│   │   │   ├── mode.py             # §7.3
│   │   │   ├── pfs.py              # §7.4
│   │   │   ├── replay.py           # §7.5
│   │   │   ├── traffic_clf.py      # §7.6
│   │   │   └── calibration.py
│   │   ├── assess/
│   │   │   ├── engine.py           # §8
│   │   │   ├── policy.py
│   │   │   ├── scoring.py
│   │   │   └── policies/*.yaml
│   │   ├── report/
│   │   │   ├── render.py
│   │   │   └── templates/
│   │   ├── db/
│   │   │   ├── models.py           # §4
│   │   │   └── session.py
│   │   └── api/
│   │       ├── main.py             # §9
│   │       ├── routes/
│   │       └── jobs.py
│   ├── testbed/
│   │   ├── matrix.yaml             # §10.1
│   │   ├── orchestrator.py
│   │   ├── templates/swanctl.conf.j2
│   │   └── traffic/
│   ├── models/                     # trained artefacts, DVC-tracked
│   └── tests/
├── frontend/                       # §11
│   ├── package.json
│   ├── src/app/
│   ├── src/components/
│   ├── src/lib/
│   └── src/types/generated.ts
└── dataset/
```

---

## 3. Core contract

`core/schema.py` is the single source of truth. Every downstream consumer — database rows, API responses, report templates, frontend types — derives from it. Write this file first; it unblocks parallel work across the team.

```python
class Provenance(str, Enum):
    OBSERVED = "observed"   # Track A — parsed from cleartext IKE
    INFERRED = "inferred"   # Track B — statistical, carries confidence
    UNAVAILABLE = "unavailable"


class Attribute(BaseModel, Generic[T]):
    """Every reported fact. Provenance is mandatory, not decorative."""
    value: T | None
    provenance: Provenance
    confidence: float | None = None      # required iff INFERRED
    evidence: Evidence | None = None
    note: str | None = None

    @model_validator(mode="after")
    def _check(self) -> Attribute[T]:
        if self.provenance is Provenance.INFERRED and self.confidence is None:
            raise ValueError("inferred attribute requires confidence")
        if self.provenance is Provenance.OBSERVED and self.confidence is not None:
            raise ValueError("observed attribute must not carry confidence")
        return self


class Evidence(BaseModel):
    packet_indices: list[int] = []       # capped at 20, see §8.4
    measured: dict[str, float | str] = {}
    method: str                          # e.g. "esp_length_lattice"


class SecurityAssociation(BaseModel):
    spi_initiator: str                   # hex
    spi_responder: str | None
    src: IPvAnyAddress
    dst: IPvAnyAddress
    ip_version: Literal[4, 6]
    protocol: Literal["esp", "ah"]
    first_seen: datetime
    last_seen: datetime
    packet_count: int
    byte_count: int

    ike_version:        Attribute[IkeVersion]
    ike_exchange_mode:  Attribute[IkeExchangeMode]
    encryption_alg:     Attribute[EncryptionAlg]
    encryption_keylen:  Attribute[int]           # UNAVAILABLE when ESP-only
    integrity_alg:      Attribute[IntegrityAlg]
    prf_alg:            Attribute[PrfAlg]
    dh_group:           Attribute[int]
    operating_mode:     Attribute[OperatingMode]
    pfs_enabled:        Attribute[bool]
    auth_method:        Attribute[AuthMethod]
    negotiated_lifetime_s: Attribute[int]
    observed_rekey_s:      Attribute[int]
    esn_negotiated:     Attribute[bool]
    replay_sane:        Attribute[bool]
    nat_traversal:      Attribute[bool]

    inner_traffic: list[TrafficPrediction]


class TrafficPrediction(BaseModel):
    label: TrafficClass
    probability: float
    window_start: datetime
    window_end: datetime
    top_features: list[FeatureAttribution] = []


class Finding(BaseModel):
    id: str                              # stable, e.g. "CRYPTO-3DES"
    title: str
    severity: Severity
    category: FindingCategory
    penalty: int
    description: str
    remediation: str
    standards: list[StandardRef]
    attack_techniques: list[str]         # MITRE IDs
    sa_spi: str | None
    evidence: Evidence


class Assessment(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    assessment_id: UUID
    capture_id: UUID
    generated_at: datetime
    engine_version: str
    policy_version: str
    model_versions: dict[str, str]

    capture_quality: CaptureQuality
    security_associations: list[SecurityAssociation]
    findings: list[Finding]
    score: ScoreBreakdown
    metadata_exposure: MetadataExposure
    threat_matrix: list[ThreatMatrixEntry]


class ScoreBreakdown(BaseModel):
    total: int = Field(ge=0, le=100)
    category_penalties: dict[FindingCategory, int]
    rating: Literal["critical", "poor", "fair", "good", "strong"]


class MetadataExposure(BaseModel):
    """The PRD §4.1 thesis, made concrete."""
    score: int = Field(ge=0, le=100)     # higher = more leakage
    mean_classifier_confidence: float
    identified_classes: list[TrafficClass]
    rationale: str
```

`Attribute[T]` is the load-bearing type. It makes it structurally impossible to emit an inferred value without a confidence, or to dress an inference up as a fact. FR-4.9 becomes a type-level guarantee: with ESP-only input, `encryption_keylen.provenance` is `UNAVAILABLE` and `value` is `None`.

---

## 4. Database

### 4.1 Dual-backend strategy

| Mode | `DATABASE_URL` | Driver | Use |
|---|---|---|---|
| Default | `postgresql+asyncpg://...neon.tech/...` | asyncpg | Normal operation |
| Offline | `sqlite+aiosqlite:///./data/analyzer.db` | aiosqlite | Air-gapped, demo laptop, CI |

One SQLAlchemy model set serves both. Portability rules:

- Use `sa.JSON` (not `JSONB`) in model definitions; on Postgres, Alembic upgrades the column to `JSONB` in a dialect-guarded migration step.
- No Postgres-only constructs in application queries — no array columns, no `ILIKE`, no window functions in the hot path.
- UUIDs stored as `sa.Uuid` (native `uuid` on PG, `CHAR(32)` on SQLite).
- No cross-JSON indexing in queries. If a filter needs it, promote the field to a real column.

### 4.2 Neon specifics

Two gotchas that will cost a day each if not handled up front:

```python
# Neon's pooled endpoint runs PgBouncer in transaction mode.
# asyncpg's prepared-statement cache breaks against it.
engine = create_async_engine(
    settings.database_url,
    connect_args={"statement_cache_size": 0} if is_neon else {},
    pool_pre_ping=True,          # Neon scales to zero; first query may hit a cold start
    pool_recycle=280,
)
```

Use the **pooled** connection string for the API and the **direct** string for Alembic migrations. Set `NEON_BRANCH` per developer so everyone gets an isolated database branch rather than fighting over one schema.

### 4.3 Schema

```sql
CREATE TABLE captures (
    id              UUID PRIMARY KEY,
    filename        TEXT NOT NULL,
    sha256          CHAR(64) NOT NULL,
    size_bytes      BIGINT NOT NULL,
    source          TEXT NOT NULL,        -- 'upload' | 'live' | 'testbed'
    storage_path    TEXT NOT NULL,        -- filesystem; PCAPs never enter the DB
    packet_count    INTEGER,
    duration_s      REAL,
    has_ike         BOOLEAN,
    truncated       BOOLEAN,
    ground_truth    JSON,                 -- testbed labels, NULL for user uploads
    created_at      TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX ix_captures_sha256 ON captures (sha256);

CREATE TABLE analysis_runs (
    id              UUID PRIMARY KEY,
    capture_id      UUID NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    status          TEXT NOT NULL,        -- queued|running|succeeded|failed
    stage           TEXT,                 -- ingest|track_a|track_b|assess|report
    progress        REAL DEFAULT 0,
    engine_version  TEXT NOT NULL,
    policy_version  TEXT NOT NULL,
    model_versions  JSON NOT NULL,
    error           JSON,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);
CREATE INDEX ix_runs_capture ON analysis_runs (capture_id, started_at DESC);

CREATE TABLE assessments (
    id              UUID PRIMARY KEY,
    run_id          UUID NOT NULL UNIQUE REFERENCES analysis_runs(id) ON DELETE CASCADE,
    capture_id      UUID NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    schema_version  TEXT NOT NULL,
    score_total     SMALLINT NOT NULL,
    rating          TEXT NOT NULL,
    exposure_score  SMALLINT NOT NULL,
    document        JSON NOT NULL,        -- full Assessment model
    created_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX ix_assessments_capture ON assessments (capture_id, created_at DESC);

CREATE TABLE findings (
    id              UUID PRIMARY KEY,
    assessment_id   UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    finding_key     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    category        TEXT NOT NULL,
    penalty         SMALLINT NOT NULL,
    sa_spi          TEXT,
    detail          JSON NOT NULL
);
CREATE INDEX ix_findings_assessment ON findings (assessment_id, severity);

CREATE TABLE security_associations (
    id              UUID PRIMARY KEY,
    assessment_id   UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    spi_initiator   TEXT NOT NULL,
    src_addr        TEXT NOT NULL,
    dst_addr        TEXT NOT NULL,
    packet_count    INTEGER NOT NULL,
    byte_count      BIGINT NOT NULL,
    detail          JSON NOT NULL
);
```

`findings` and `security_associations` duplicate content already inside `assessments.document`. That is deliberate: the JSON document is the immutable artefact for reports and export, while the relational rows exist for dashboard filtering, sorting, and cross-capture aggregation without JSON path queries. The write path populates both in one transaction.

---

## 5. Ingest (M2)

```python
class PacketRecord(NamedTuple):
    index: int
    ts: float
    ip_version: int
    src: str
    dst: str
    proto: Literal["esp", "ah", "isakmp", "isakmp_natt", "other"]
    spi: int | None
    seq: int | None
    ip_payload_len: int      # bytes after the outer IP header
    esp_payload_len: int | None   # ip_payload_len - 8 (SPI + seq)
    captured_len: int
    orig_len: int


class FlowKey(NamedTuple):
    src: str
    dst: str
    spi: int
    proto: str
```

**Reader.** `dpkt` over a buffered file handle. Only outer headers are decoded — no deep dissection. Handles Ethernet, Linux cooked capture (SLL/SLL2), and raw IP link types. IPv6 requires walking the extension header chain to locate ESP (protocol 50) or AH (51).

**UDP encapsulation.** Port 4500 traffic is disambiguated by the first four bytes: `00000000` is the non-ESP marker introducing IKE; anything else is an ESP SPI. Port 500 is always IKE.

**Flow assembly.** Group by `FlowKey`. Then pair directional SAs into `SAPair` by matching `(src,dst)` against `(dst,src)` with overlapping time ranges. Unpaired SAs are retained and flagged — a one-directional capture is a legitimate and common analyst situation, not an error.

**Truncation check.** If `captured_len < orig_len` for any packet, set `truncated = true`. This matters because a snaplen-limited capture destroys the length-lattice analysis in §7.2, and the cipher-family detector must refuse to run rather than produce a confident wrong answer.

```python
class CaptureQuality(BaseModel):
    packet_count: int
    duration_s: float
    truncated: bool
    has_ike: bool
    ike_complete: bool           # SA_INIT observed, not mid-stream
    esp_sa_count: int
    sufficient_for_lattice: bool # ≥200 ESP packets, ≥8 distinct lengths
    warnings: list[str]
```

Every downstream analyser reads `CaptureQuality` and self-disables where its preconditions fail. This is the mechanism that keeps the system honest on degraded input.

---

## 6. Track A — IKE parser (M3)

### 6.1 Approach

Shell out to `tshark`, do not hand-roll ISAKMP dissection:

```python
CMD = [
    "tshark", "-r", str(pcap), "-Y", "isakmp",
    "-T", "json", "-x", "--no-duplicate-keys",
]
```

Wireshark's ISAKMP dissector handles every transform-attribute encoding variant, both the basic and variable-length attribute forms, and vendor-specific payload quirks. Reimplementing it is roughly two weeks of work for a strictly worse result. Parse the JSON into an intermediate representation, then normalise.

Pin the tshark version in the Dockerfile. Field names in Wireshark's JSON output change across releases and will silently break the parser otherwise.

### 6.2 Extraction

| Target | Source |
|---|---|
| IKE version | ISAKMP header version field |
| IKEv1 exchange mode | Header exchange type: 2 = identity protection (main), 4 = aggressive |
| Transforms | IKEv2: SA payload → proposals → transforms, keyed by type (1 ENCR, 2 PRF, 3 INTEG, 4 DH, 5 ESN). IKEv1: SA → proposal → transform attributes |
| Key length | ENCR transform attribute 14 (`KEY_LENGTH`) |
| DH group | Transform type 4 value |
| Lifetime | IKEv1 attributes 1/2 (type/duration); IKEv2 has no lifetime negotiation — see below |
| SPIs | Header initiator/responder SPI; Child SA SPIs from the SA payload proposal |
| NAT-T | NAT_DETECTION_* notify payloads, or observed UDP/4500 |
| Auth method | IKEv1: transform attribute 3. IKEv2: AUTH payload method field (only when unencrypted, which it is not — so usually inferred or unavailable) |

### 6.3 Proposed vs selected

An initiator sends multiple proposals; the responder returns one. The parser must record both.

```python
@dataclass
class IkeNegotiation:
    proposed: list[Proposal]     # from the initiator
    selected: Proposal | None    # from the responder
    downgrade_available: bool    # a weaker proposal than the selected one was offered
```

`downgrade_available` drives finding `CRYPTO-DOWNGRADE-OFFER`. Offering 3DES alongside AES-256 is a real weakness even when AES-256 was chosen, because an active attacker who can influence the negotiation may force the weaker option. Most tools miss this.

### 6.4 Two IKEv2 realities to encode correctly

**Lifetime is not negotiated in IKEv2.** RFC 7296 removed lifetime negotiation; each peer expires SAs on its own local policy. So `negotiated_lifetime_s` must be `UNAVAILABLE` for IKEv2 and the assessment must fall back to `observed_rekey_s` from §7.5. Emitting a fabricated IKEv2 lifetime is a correctness bug that a knowledgeable reviewer will catch immediately.

**IKE_AUTH is encrypted.** Only `IKE_SA_INIT` is cleartext. Child SA transforms negotiated inside `IKE_AUTH` are not directly readable. In the common case the Child SA uses the same algorithm family as the IKE SA, but the parser must mark Child SA encryption as `INFERRED` with the reasoning recorded, not as `OBSERVED`.

---

## 7. Track B — inference engine (M4)

### 7.1 Feature extraction

Operates on Polars DataFrames, one row per packet, grouped per SA.

```python
def extract(packets: pl.DataFrame, sa: SAPair) -> FeatureVector:
    ...
```

| Group | Features |
|---|---|
| Geometry | `esp_payload_len` mean/std/min/max/percentiles(10,25,50,75,90,99); histogram of `esp_payload_len % 16`; distinct-length count; modal length and its share |
| Flow | packet count, byte count, duration, pps, bps |
| Timing | inter-arrival mean/std/percentiles; coefficient of variation; burst count (gap > 200 ms), burst duration stats, idle-period stats |
| Directionality | up/down byte ratio, up/down packet ratio, per-direction size stats |
| Sequence | first 128 `(signed size)` values, zero-padded — CNN input |
| SA behaviour | distinct SPI count per endpoint pair, SPI rotation intervals, sequence gap count, duplicate-sequence count |

### 7.2 Cipher family detection

The strongest deterministic signal available from ESP alone, and worth implementing carefully.

An ESP packet's payload after the 8-byte SPI and sequence header is `IV || ciphertext || ICV`, where `ciphertext` covers the plaintext, pad, pad length, and next header. RFC 4303 requires the encrypted portion to be a multiple of 4 bytes; a block cipher additionally requires a multiple of its block size.

```python
CANDIDATES = [
    # (name, iv_len, icv_len, block_size)
    ("AES-CBC + HMAC-SHA1-96",    16, 12, 16),
    ("AES-CBC + HMAC-SHA256-128", 16, 16, 16),
    ("AES-CBC + HMAC-SHA384-192", 16, 24, 16),
    ("AES-GCM-16",                 8, 16,  4),
    ("AES-GCM-8",                  8,  8,  4),
    ("AES-CTR + HMAC-SHA1-96",     8, 12,  4),
    ("3DES-CBC + HMAC-SHA1-96",    8, 12,  8),
    ("ChaCha20-Poly1305",          8, 16,  4),
]

def detect(lengths: np.ndarray, quality: CaptureQuality) -> Attribute[str]:
    if not quality.sufficient_for_lattice:
        return Attribute(value=None, provenance=UNAVAILABLE,
                         note="insufficient length diversity")

    survivors = [
        c for c in CANDIDATES
        if np.all((lengths - c.iv_len - c.icv_len) % c.block_size == 0)
        and np.all(lengths - c.iv_len - c.icv_len >= c.block_size)
    ]
    ...
```

**Resolving survivors.** Candidates sharing `(iv+icv) mod block == 0` are indistinguishable by congruence alone. Rank survivors by *constraint strength* — larger block size and larger total overhead are more constrained, so a 16-byte-block survivor beats a 4-byte-block one. Confidence derives from how many candidates were eliminated:

```
confidence = 1 - (len(survivors) - 1) / (len(CANDIDATES) - 1)
```

Report the full survivor set in `Evidence.measured`, not just the winner.

**The degenerate case, which must be handled.** Constant-bitrate traffic — a VoIP call is the canonical example — produces ESP packets of one or two lengths. A single length satisfies almost every congruence, so the test collapses. This is why `sufficient_for_lattice` requires at least 8 distinct lengths across at least 200 packets. When it fails, return `UNAVAILABLE`. A confident wrong cipher identification is far more damaging to the product than an honest gap, and this specific failure mode will be present in the demo capture, so handle it deliberately rather than discovering it live.

### 7.3 Operating mode

Weaker signals than §7.2, so this is a trained classifier (ML-2) rather than a rule. Features, in descending order of usefulness:

1. **Maximum observed ESP packet length relative to path MTU.** Tunnel mode carries an inner IP header, so for the same inner MTU the outer packets sit 20 bytes (IPv4) or 40 bytes (IPv6) higher, and inner-path MTU discovery lands on a characteristically different maximum.
2. **Endpoint role.** Count distinct SPI pairs per outer address. Gateways aggregate many SAs; hosts in transport mode typically carry one or two.
3. **Correlated cleartext.** In transport mode the outer addresses are the actual endpoints and commonly emit cleartext ARP, DNS, or NTP in the same capture. In tunnel mode all inner traffic is hidden and the outer addresses show little else.
4. **Overhead offset.** Comparing the modal payload length against the expected value for a given inner traffic class shifts by the inner-header size.

Feature 4 is circular with §7.6 — it depends on knowing the inner traffic class. Break the cycle by running the traffic classifier first and feeding its output as a feature, never the reverse. Document that ordering; a reviewer will ask.

### 7.4 PFS inference

With the DH group known from `IKE_SA_INIT`, this becomes near-deterministic rather than a threshold guess.

A `CREATE_CHILD_SA` exchange (IKEv2 exchange type 36) carrying a KE payload includes a DH public value whose size is fixed by the group:

| Group | Public value |
|---|---|
| 14 (MODP-2048) | 256 bytes |
| 15 (MODP-3072) | 384 bytes |
| 19 (ECP-256) | 64 bytes |
| 20 (ECP-384) | 96 bytes |

```python
def infer_pfs(exchanges, dh_group) -> Attribute[bool]:
    baseline = median(len(x) for x in exchanges_without_ke_estimate)
    expected_delta = DH_PUBLIC_SIZE[dh_group] + KE_PAYLOAD_HEADER  # 8 bytes
    observed = median(len(x) for x in create_child_exchanges)
    ...
```

For ECP groups the delta is only 64–96 bytes and overlaps plausible variation in traffic-selector payload sizes, so confidence must be lower for groups 19 and 20 than for 14 and 15. Encode that in the confidence calculation explicitly rather than returning a flat value.

If no `CREATE_CHILD_SA` appears in the capture window — likely for short captures with long rekey intervals — return `UNAVAILABLE`.

### 7.5 Replay and lifetime

Be precise about what is and is not observable here. Getting this wrong is the most common way a project of this kind loses credibility.

| Property | Observable? | Method |
|---|---|---|
| Sequence numbers present and monotonic | Yes | Per-SPI sequence analysis |
| Duplicate sequence numbers | Yes | Set membership |
| Sequence gaps | Yes | But gaps also arise from capture drops, so report both and do not conclude attack |
| **ESN in use** | **Track A only** | Negotiated as IKEv2 transform type 5. Not distinguishable on the wire, since only the low 32 bits are transmitted either way |
| **Anti-replay window size** | **No** | A receiver-side local setting, never transmitted. Must be reported as unavailable |
| Observed rekey interval | Yes | Time between first appearance of successive SPIs on the same endpoint pair |

The `replay_sane` attribute means "sequence numbers behave correctly on the wire", not "anti-replay is enabled". The report wording must reflect that distinction.

### 7.6 Traffic classification (ML-1)

**Windowing.** Fixed 10-second windows with 50% overlap, per SA per direction pair. A window needs at least 20 packets to be scored. Per-window predictions are aggregated into `TrafficPrediction` spans by merging adjacent windows sharing an argmax label.

**Models.**

- Baseline: LightGBM over the tabular features in §7.1.
- Target: 1D-CNN over the 128-length signed-size sequence, concatenated with the tabular features at the dense layer.

```
Input: (128, 1) signed sizes ─┐
  Conv1D(64, k=5) → BN → ReLU │
  Conv1D(64, k=5) → BN → ReLU │
  MaxPool(2)                  │
  Conv1D(128, k=3) → BN → ReLU│
  GlobalMaxPool                ├→ Concat → Dense(128) → Dropout(0.3) → Dense(7) → softmax
Input: tabular features ──────┘
```

**Calibration.** Temperature scaling for the CNN, `CalibratedClassifierCV(method="isotonic")` for LightGBM, both fitted on a calibration split disjoint from train and test. Report ECE alongside accuracy in every evaluation.

**Splitting.** Split by *configuration and session*, never by window. Windows from one capture sharing a train/test boundary leak, and the resulting accuracy figure is meaningless.

---

## 8. Assessment engine (M5)

### 8.1 Policy format

```yaml
version: "1.0"
profile: baseline
rules:
  - id: CRYPTO-3DES
    category: cryptographic_strength
    severity: critical
    penalty: 30
    when:
      attribute: encryption_alg
      operator: in
      values: ["3DES-CBC", "DES-CBC"]
    title: "Deprecated block cipher in use"
    description: >
      The SA negotiated {value}, a 64-bit block cipher subject to
      birthday-bound collision attacks on long-lived connections.
    remediation: >
      Reconfigure the proposal to AES-256-GCM. In strongSwan, set
      esp = aes256gcm16-prfsha384-ecp384 in the child SA section.
    standards: [{ref: "RFC 8221", clause: "§5"}]
    attack: ["T1040"]

  - id: KEX-WEAK-DH
    category: key_exchange
    severity: high
    penalty: 15
    when:
      attribute: dh_group
      operator: in
      values: [1, 2, 5]
    ...

  - id: PFS-DISABLED
    category: key_exchange
    severity: high
    penalty: 12
    when:
      all:
        - {attribute: pfs_enabled, operator: eq, value: false}
        - {attribute: pfs_enabled, operator: confidence_gte, value: 0.7}
    ...
```

The `confidence_gte` operator is essential. A rule must not fire on a low-confidence inference. Any rule keyed on an `INFERRED` attribute requires a confidence guard, enforced by a policy-file validator at load time so the failure is a startup error rather than a bad report.

### 8.2 Evaluation

```python
class AssessmentEngine:
    def __init__(self, policy: Policy) -> None: ...

    def evaluate(self, sas: list[SecurityAssociation],
                 quality: CaptureQuality) -> Assessment:
        findings = [f for sa in sas for f in self._eval_sa(sa)]
        findings = self._dedupe(findings)
        score = self._score(findings)
        exposure = self._exposure(sas)
        matrix = self._threat_matrix(findings)
        ...
```

Pure function of its inputs. No I/O, no randomness, no wall-clock reads inside evaluation. This is what makes NFR-4 (byte-identical output for identical input) achievable, and it makes the engine trivially unit-testable against fixture `SecurityAssociation` objects without any PCAP.

### 8.3 Scoring

```python
def score(findings: list[Finding]) -> ScoreBreakdown:
    per_category: dict[FindingCategory, int] = defaultdict(int)
    for f in sorted(findings, key=lambda f: (f.category, -f.penalty)):
        cap = CATEGORY_CAPS[f.category]           # PRD §10.1
        per_category[f.category] = min(cap, per_category[f.category] + f.penalty)
    total = max(0, 100 - sum(per_category.values()))
    return ScoreBreakdown(total=total, category_penalties=dict(per_category),
                          rating=_rating(total))
```

Capping per category prevents three medium cryptographic findings from outweighing one critical key-exchange failure. Sorting by descending penalty within a category means the cap is consumed by the most severe finding first, so the reported attribution is the meaningful one.

### 8.4 Metadata exposure

```python
def exposure(sas) -> MetadataExposure:
    confs = [p.probability for sa in sas for p in sa.inner_traffic]
    if not confs:
        return MetadataExposure(score=0, ..., rationale="no inner traffic classified")
    mean_conf = statistics.mean(confs)
    # Chance level for 7 classes is ~0.143; scale from there.
    score = round(100 * max(0.0, (mean_conf - 1/7) / (1 - 1/7)))
```

Scaling from chance level rather than from zero is the correct baseline: a classifier at chance has learned nothing about the tunnel and the deployment leaks nothing, which should score 0 exposure, not 14.

**Evidence caps.** `Evidence.packet_indices` is capped at 20 entries with a `total_matching` count alongside. Uncapped, a finding on a million-packet capture serialises a million integers into a JSON column and the dashboard dies.

---

## 9. API

FastAPI on `:8000`. Next.js proxies to it; the browser never calls it directly.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/captures` | Multipart upload. Returns `201` with capture summary. Dedupes on SHA-256 |
| `GET` | `/api/v1/captures` | Paginated list |
| `GET` | `/api/v1/captures/{id}` | Capture detail with quality metrics |
| `DELETE` | `/api/v1/captures/{id}` | Removes the row and the stored PCAP |
| `POST` | `/api/v1/captures/{id}/analyze` | Starts a run. Returns `202` with `run_id` |
| `GET` | `/api/v1/runs/{id}` | Run status |
| `GET` | `/api/v1/runs/{id}/events` | SSE progress stream |
| `GET` | `/api/v1/assessments/{id}` | Full `Assessment` document |
| `GET` | `/api/v1/assessments/{id}/findings` | Filterable, sortable — served from the relational table |
| `GET` | `/api/v1/assessments/{id}/report?format=executive\|technical` | `application/pdf` |
| `GET` | `/api/v1/assessments/compare?a={id}&b={id}` | Side-by-side diff |
| `GET` | `/api/v1/health` | Liveness and DB reachability |

**Upload constraints.** 2 GB cap, streamed to disk in 8 MB chunks — never buffered in memory. Magic-byte validation against PCAP (`d4c3b2a1` / `a1b2c3d4`) and PCAPNG (`0a0d0d0a`) before anything is persisted.

**Job execution.** FastAPI `BackgroundTasks` with an `asyncio.Semaphore(2)` bounding concurrent analyses. The CPU-bound stages run in a `ProcessPoolExecutor` so the event loop stays free to serve SSE. No Celery, no Redis — a 60-second job budget (NFR-1) does not justify that infrastructure, and the compose file stays at three services.

**SSE payload:**

```
event: progress
data: {"runId":"...","stage":"track_b","progress":0.62,"message":"classifying flows"}

event: complete
data: {"runId":"...","assessmentId":"..."}
```

**Type generation.** `scripts/gen-types.sh` pulls the OpenAPI schema and runs `openapi-typescript` into `frontend/src/types/generated.ts`. Wire it into CI so a backend schema change that the frontend has not absorbed fails the build rather than surfacing at runtime.

---

## 10. Testbed (M1)

### 10.1 Matrix

```yaml
version: "1.0"
defaults:
  duration_s: 180
  peers: {left: 10.10.0.2, right: 10.10.0.3}

dimensions:
  mode:       [tunnel, transport]
  ike:        [ikev1-main, ikev1-aggressive, ikev2]
  esp:        [aes128-sha1, aes256-sha256, aes128gcm16, aes256gcm16, 3des-sha1]
  dh:         [2, 14, 19, 20]
  pfs:        [true, false]
  ip:         [v4, v6]
  traffic:    [icmp, web, voip, video, email, filexfer, messaging]

sampling:
  strategy: pairwise
  guarantee_full_coverage: [mode, esp, pfs, ike]
  seed: 20260903

fixtures:
  - name: weak-reference
    mode: transport
    ike: ikev1-aggressive
    esp: 3des-sha1
    dh: 2
    pfs: false
    lifetime_s: 86400
    traffic: voip
  - name: hardened-reference
    mode: tunnel
    ike: ikev2
    esp: aes256gcm16
    dh: 19
    pfs: true
    lifetime_s: 3600
    traffic: voip
```

Pairwise sampling over the full cross-product (2×3×5×4×2×2×7 = 3360) yields roughly 40–60 configurations. With multiple traffic runs per configuration this reaches the 200-session target from PRD §9.3 without a week of compute.

### 10.2 Session lifecycle

```python
async def run_session(cfg: SessionConfig) -> SessionResult:
    async with peer_pair(cfg) as (left, right):        # docker network + 2 containers
        render_swanctl(left, cfg); render_swanctl(right, cfg)
        capture = await start_tcpdump(left, iface="eth0")
        await bring_up_tunnel(left, right)
        await assert_sa_established(left)              # swanctl --list-sas
        await generate_traffic(left, right, cfg.traffic, cfg.duration_s)
        await stop_tunnel(left)                         # captures the DELETE exchange
        pcap = await capture.stop()
    return SessionResult(pcap=pcap, labels=cfg.to_ground_truth())
```

Three details that matter:

- **`assert_sa_established` before generating traffic.** Otherwise a failed negotiation silently produces a capture full of retries labelled as a working tunnel, and that poisoned row will be very hard to find later.
- **Tear the tunnel down inside the capture window** so the DELETE exchange is recorded. Real analyst captures contain them.
- **Containers need `--cap-add=NET_ADMIN` and a writable `/proc/sys/net`.** Kernel XFRM state is network-namespace scoped, which is what makes this work at all.

### 10.3 Do not use `kernel-libipsec`

strongSwan can process ESP in userspace via the `kernel-libipsec` plugin, which sidesteps every kernel and capability problem in containers. Do not enable it for dataset generation. The entire Track B feature set is packet geometry — padding behaviour, IV placement, MTU handling. A userspace ESP implementation may differ from the kernel path in exactly those details, and models trained on it would be learning artefacts absent from the real deployments this tool is meant to analyse. If containers prove intractable, move to VMs rather than to userspace ESP.

---

## 11. Frontend

### 11.1 Structure

Next.js 15, App Router, TypeScript, Tailwind, shadcn/ui, TanStack Query for client-side state, Recharts for charts.

```
src/app/
├── layout.tsx
├── page.tsx                          # capture list + upload
├── captures/[id]/page.tsx            # capture detail, run trigger
├── assessments/[id]/
│   ├── layout.tsx                    # score header + tab nav (server)
│   ├── page.tsx                      # overview
│   ├── configuration/page.tsx        # observed vs inferred table
│   ├── findings/page.tsx
│   ├── traffic/page.tsx
│   └── threats/page.tsx
├── compare/page.tsx
└── api/[...path]/route.ts            # proxy to FastAPI
```

### 11.2 Rendering strategy

Assessment data is immutable once written, so fetch it in Server Components with `cache: "force-cache"` keyed on the assessment ID. Client Components are used only where interaction demands them: the findings table (sort and filter), the traffic timeline, and the upload widget.

**Progress streaming.** The SSE stream must be consumed in a Client Component with `EventSource`. Route it through `app/api/[...path]/route.ts`, which returns a `ReadableStream` — Next.js route handlers pass SSE through correctly provided the handler sets `runtime = "nodejs"` and does not buffer.

**Upload.** Direct `fetch` with `FormData` to the proxy route, using `XMLHttpRequest` where a progress bar is needed, since `fetch` has no upload progress event. Server Actions are the wrong tool here — the default body size limit and the lack of progress reporting both work against a 2 GB PCAP.

### 11.3 The provenance component

The single most important UI element, because it is the visual expression of the product thesis.

```tsx
export function AttributeCell<T>({ attr }: { attr: Attribute<T> }) {
  if (attr.provenance === "unavailable")
    return <Unavailable note={attr.note} />;
  if (attr.provenance === "observed")
    return <Observed value={attr.value} evidence={attr.evidence} />;
  return <Inferred value={attr.value} confidence={attr.confidence!} ... />;
}
```

Observed values render plainly. Inferred values carry a confidence bar and an expandable feature-attribution panel. Unavailable values render as an explicit statement of why, never as a blank cell or a dash — the fact that AES key length cannot be determined from ESP alone is a finding the tool is making, not an absence of data.

---

## 12. Testing

| Layer | Approach |
|---|---|
| Unit — parsers | Golden PCAP fixtures, one per IKE variant, checked into `tests/fixtures/` |
| Unit — engine | Fixture `SecurityAssociation` objects, no PCAP. Assert exact finding sets and exact scores |
| Property — scoring | Hypothesis: score always in [0,100]; adding a finding never raises the score; category caps never exceeded |
| Determinism | Run the full pipeline twice on one PCAP, assert byte-identical assessment JSON after stripping timestamps and IDs (NFR-4) |
| Integration | Testbed generates a known-weak tunnel; assert the expected finding IDs appear |
| Degradation | ESP-only capture, truncated capture, single-length capture, one-directional capture. Each must produce `UNAVAILABLE` rather than a confident wrong answer |
| DB portability | Full API test suite runs against both SQLite and Postgres in CI |
| Contract | OpenAPI schema diff fails CI if `generated.ts` is stale |

The degradation suite is the one most likely to be skipped and the one most likely to save the demo.

---

## 13. Deployment

```yaml
# docker-compose.yml — default (Neon)
services:
  api:
    build: ./backend
    environment:
      DATABASE_URL: ${NEON_DATABASE_URL}
      STORAGE_PATH: /data/captures
    volumes: ["captures:/data/captures"]
    ports: ["8000:8000"]
  web:
    build: ./frontend
    environment:
      API_BASE_URL: http://api:8000
    ports: ["3000:3000"]
volumes: { captures: {} }
```

```yaml
# docker-compose.offline.yml — air-gapped / demo
services:
  api:
    environment:
      DATABASE_URL: sqlite+aiosqlite:////data/analyzer.db
```

**A tension worth naming.** NFR-6 states that captures are processed locally with no external service calls. Neon is a hosted database, so while PCAP bytes never leave the machine, assessment metadata — endpoint IP addresses, SPIs, findings — would. For a hackathon deployment this is fine and Neon's branching is genuinely useful for parallel development. For any real deployment, or for a demo in front of a security audience who will ask, run the offline compose file. Make the choice explicit in the documentation rather than letting a reviewer discover it.

**Demo posture.** Rehearse on `docker-compose.offline.yml`. Neon scales to zero, and a cold start during a live demo is an avoidable risk.

---

## 14. Build order

Dependencies between modules dictate this sequence:

1. `core/schema.py` — unblocks everyone.
2. `db/models.py` and the initial Alembic migration.
3. `ingest/` — everything downstream needs `PacketRecord` and `FlowKey`.
4. `track_a/` and `testbed/` in parallel. The testbed needs Track A to validate that generated tunnels match their labels.
5. `assess/` against fixture SAs, before Track B exists. Track A alone already produces a working, useful product.
6. `api/` and `frontend/` against fixture assessments.
7. `track_b/` — needs the testbed dataset, which is why it starts last and why the testbed is the schedule's critical path.
8. `report/` — templates built early against mock JSON, wired to real data last.

Step 5 is the important one strategically. If Track B underdelivers, a system that parses IKE deterministically and scores it against RFC 8221 is still a complete and defensible submission.
