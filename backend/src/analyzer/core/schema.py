"""The core contract. LLD section 3.

This module is the single source of truth for the whole system. Database rows,
API responses, report templates and frontend types all derive from what is
defined here; nothing downstream may invent a shape of its own.

Two ideas carry the design.

**Provenance is mandatory, not decorative.** ``Attribute[T]`` pairs every
reported fact with how it was arrived at, and the pairing rules are enforced by
a validator. It is structurally impossible to emit an inferred value without a
confidence, to dress an inference up as a fact, or to leave an unavailable field
silently blank. FR-4.9 -- "AES key length is not determinable from ESP alone" --
stops being a caveat in prose and becomes a type-level guarantee.

**Timestamps are UTC and aware.** ``UtcDatetime`` rejects naive values at the
boundary and normalises everything else to UTC, so a naive datetime can never
reach a comparison and quietly produce the wrong answer.

Keys stay ``snake_case`` throughout. The camelCase conversion the frontend wants
happens at the API boundary via Pydantic aliases (LLD section 1); nothing inside
the backend ever sees a camelCase key.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Generic, Literal, Self, TypeVar
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    PlainSerializer,
    field_validator,
    model_validator,
)

from analyzer.core.enums import (
    CATEGORY_CAPS,
    AuthMethod,
    EncryptionAlg,
    FindingCategory,
    IkeExchangeMode,
    IkeVersion,
    IntegrityAlg,
    OperatingMode,
    PrfAlg,
    Provenance,
    Severity,
    TrafficClass,
)

T = TypeVar("T")

MAX_PACKET_INDICES = 20
"""LLD section 8.4. Uncapped, a finding on a million-packet capture serialises a
million integers into a JSON column and the dashboard dies. Step 5.8 supplies
the truncation helper that keeps constructions under this limit; the limit
itself lives here so that exceeding it is a validation error rather than a
performance mystery."""


def _to_utc(value: datetime) -> datetime:
    """Normalise an aware datetime to UTC.

    ``AwareDatetime`` has already rejected naive values by the time this runs.
    Normalising rather than merely accepting matters for NFR-4: two runs that
    produce the same instant in different offsets must serialise identically.
    """
    return value.astimezone(UTC)


def _iso_utc(value: datetime) -> str:
    """Serialise as ISO 8601 with a literal ``Z``.

    Pydantic renders ``+00:00``; the frontend, the report templates and the
    JSON fixtures all use ``Z``. Pinning one spelling keeps assessment JSON
    byte-identical across runs, which is NFR-4.
    """
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


UtcDatetime = Annotated[
    AwareDatetime,
    Field(description="UTC, timezone-aware, ISO 8601"),
    PlainSerializer(_iso_utc, return_type=str, when_used="json"),
]
"""A timezone-aware datetime, normalised to UTC on the way in and serialised
with a trailing ``Z`` on the way out. Naive datetimes are rejected."""


Confidence = Annotated[float, Field(ge=0.0, le=1.0)]
"""A calibrated probability. PRD section 8.3 -- an uncalibrated confidence is
worse than no confidence, because it invites misplaced trust in a security
report."""


def _require_uuid7(value: UUID) -> UUID:
    if value.version != 7:
        msg = (
            f"expected a UUIDv7, got version {value.version}. "
            "Entity keys must be time-sortable -- use analyzer.core.ids.new_id()"
        )
        raise ValueError(msg)
    return value


Uuid7 = Annotated[UUID, AfterValidator(_require_uuid7)]
"""A UUIDv7 primary key. LLD section 1.

Validated rather than assumed: a v4 key slipped into a v7 column breaks the
time ordering the rest of the system relies on, and does so silently.
"""


HexSpi = Annotated[str, Field(pattern=r"^([0-9a-f]{8}|[0-9a-f]{16})$")]
"""A Security Parameter Index as lowercase hex, zero-padded, with no ``0x``.

Exactly 8 characters for an ESP or AH SPI (32-bit, RFC 4303) or 16 for an IKE
SPI (64-bit, RFC 7296). Padding is mandatory: an SPI rendered as ``4f2a`` and
the same SPI rendered as ``00004f2a`` are the same SA, and the report must not
show them as two. Lowercase is fixed for NFR-4 -- case is not information, but
it does change the bytes.
"""


AttackTechniqueId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]
"""A MITRE ATT&CK technique ID, e.g. ``T1040`` or a sub-technique ``T1557.002``."""


MeasuredValue = int | float | str
"""A value recorded as evidence.

LLD section 3 writes this as ``float | str``. Widened to admit ``int`` because
most of what gets measured is an integer -- IKE exchange types, transform IDs,
DH group numbers, packet counts -- and coercing those to float makes a technical
report say "exchange type 4.0" and "17500.0 packets". It also breaks NFR-4's
byte-identical round trip, since ``4`` serialises back as ``4.0``.
"""


FindingKey = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$")]
"""A stable finding identifier such as ``CRYPTO-3DES`` or ``KEX-PFS-DISABLED``.

Stable is the operative word. These IDs appear in reports, in the threat matrix,
in policy files and in the frontend's deep links, so renaming one silently
breaks every reference to it. Uppercase, hyphen-separated.
"""


class AnalyzerModel(BaseModel):
    """Base for every model in the contract.

    ``extra="forbid"`` is the important setting. The hand-written fixtures
    (step 1.4), the policy files and any external JSON are all validated against
    these models, and a typo'd key that is silently ignored is exactly the kind
    of defect that surfaces as a blank panel in the dashboard three weeks later.

    ``validate_assignment`` keeps the invariants true after construction. Without
    it, ``attr.confidence = 0.9`` on an OBSERVED attribute would sail straight
    past the validator that exists to prevent precisely that.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=False,
        populate_by_name=True,
    )

    @field_validator("*", mode="after")
    @classmethod
    def _normalise_datetimes(cls, value: object) -> object:
        """Push every aware datetime onto UTC. See ``_to_utc``."""
        if isinstance(value, datetime) and value.tzinfo is not None:
            return _to_utc(value)
        return value


class Evidence(AnalyzerModel):
    """Why the system believes what it says. FR-5.8, NFR-7.

    Every finding and every non-trivial attribute carries one of these. An
    assessment that cannot be traced back to specific packets and measured
    values is an opinion, and a security report full of opinions is worthless
    to the auditor it is written for.
    """

    method: str = Field(min_length=1)
    """How the value was arrived at, as a stable identifier rather than prose --
    ``esp_length_lattice``, ``ike_sa_init_transform``, ``spi_rotation_timing``.
    The report groups findings by method, so free text here degrades the
    output."""

    packet_indices: list[int] = Field(default_factory=list, max_length=MAX_PACKET_INDICES)
    """Zero-based indices into the capture, so an analyst can open the PCAP and
    look. Capped at ``MAX_PACKET_INDICES``; ``total_matching`` records how many
    there really were."""

    measured: dict[str, MeasuredValue] = Field(default_factory=dict)
    """The numbers behind the claim: observed lengths, congruence residues,
    survivor sets, timings. Keyed by ``snake_case`` metric name."""

    total_matching: int | None = Field(default=None, ge=0)
    """How many packets matched in total, when ``packet_indices`` was truncated.

    ``None`` means no truncation happened and the list is complete. LLD section
    8.4 requires this alongside the cap -- "20 packets" and "20 of 412,000
    packets" are very different findings.
    """

    @model_validator(mode="after")
    def _check_total_matching(self) -> Self:
        if self.total_matching is not None and self.total_matching < len(self.packet_indices):
            msg = (
                f"total_matching={self.total_matching} is smaller than the "
                f"{len(self.packet_indices)} packet indices listed"
            )
            raise ValueError(msg)
        return self


class Attribute(AnalyzerModel, Generic[T]):
    """Every reported fact, tagged with how it was arrived at. LLD section 3.

    The load-bearing type of the product. PRD section 4 splits IPsec's leakage
    into deterministic parsing of cleartext IKE (Track A) and statistical
    inference over encrypted ESP (Track B), and insists that an analyst can
    always tell which of the two produced a given claim. This class is where
    that insistence is made structural.

    The invariants, all enforced below:

    ================  ==========  ===========  ==================================
    Provenance        ``value``   Confidence   Meaning
    ================  ==========  ===========  ==================================
    ``OBSERVED``      required    forbidden    Parsed from cleartext IKE. A fact.
    ``INFERRED``      required    required     Estimated. Carries a probability.
    ``UNAVAILABLE``   forbidden   forbidden    Not determinable. Carries a note.
    ================  ==========  ===========  ==================================

    Two of these come straight from LLD section 3. The rest close the gaps that
    would otherwise let the same dishonesty back in through another door:

    - An ``UNAVAILABLE`` attribute holding a value is a contradiction, and the
      one most likely to be introduced by a partially-written parser.
    - An ``UNAVAILABLE`` attribute must say *why*. LLD section 11.3 requires the
      UI to render an explicit reason and never a dash, and a note that the
      model does not require is a note that will not be there when the
      dashboard needs it.
    - ``OBSERVED``/``INFERRED`` with a null value would render as "Observed:
      null", which is an unavailable value wearing the wrong label.
    """

    value: T | None = None
    """The fact itself. ``None`` only when provenance is ``UNAVAILABLE``."""

    provenance: Provenance
    """How this value was arrived at. Never defaulted -- a caller who has not
    thought about provenance has not finished writing the line."""

    confidence: Confidence | None = None
    """Calibrated probability in [0, 1]. Required for ``INFERRED``, and rejected
    for anything else. PRD section 8.3 covers the calibration requirement."""

    evidence: Evidence | None = None
    """Packet indices and measured values supporting the claim. FR-5.8."""

    note: str | None = None
    """Human-readable qualification. Mandatory for ``UNAVAILABLE``, where it is
    the text the dashboard renders in place of the missing value."""

    @model_validator(mode="after")
    def _check_provenance_invariants(self) -> Self:
        if self.provenance is Provenance.INFERRED:
            if self.confidence is None:
                msg = "inferred attribute requires confidence"
                raise ValueError(msg)
            if self.value is None:
                msg = "inferred attribute requires a value; use UNAVAILABLE if there is none"
                raise ValueError(msg)

        elif self.provenance is Provenance.OBSERVED:
            if self.confidence is not None:
                msg = "observed attribute must not carry confidence"
                raise ValueError(msg)
            if self.value is None:
                msg = "observed attribute requires a value; use UNAVAILABLE if there is none"
                raise ValueError(msg)

        else:  # Provenance.UNAVAILABLE
            if self.confidence is not None:
                msg = "unavailable attribute must not carry confidence"
                raise ValueError(msg)
            if self.value is not None:
                msg = "unavailable attribute must not carry a value"
                raise ValueError(msg)
            if not (self.note or "").strip():
                msg = "unavailable attribute requires a note explaining why"
                raise ValueError(msg)

        return self

    @classmethod
    def observed(
        cls,
        value: T,
        *,
        evidence: Evidence | None = None,
        note: str | None = None,
    ) -> Attribute[T]:
        """A Track A fact, parsed from cleartext IKE."""
        return cls(
            value=value,
            provenance=Provenance.OBSERVED,
            evidence=evidence,
            note=note,
        )

    @classmethod
    def inferred(
        cls,
        value: T,
        confidence: float,
        *,
        evidence: Evidence | None = None,
        note: str | None = None,
    ) -> Attribute[T]:
        """A Track B estimate. ``confidence`` must be calibrated, not raw softmax."""
        return cls(
            value=value,
            provenance=Provenance.INFERRED,
            confidence=confidence,
            evidence=evidence,
            note=note,
        )

    @classmethod
    def unavailable(cls, note: str, *, evidence: Evidence | None = None) -> Attribute[T]:
        """Not determinable from this capture, and here is why.

        The honest answer, and often the correct one. LLD section 7.2: a
        confident wrong cipher identification is far more damaging to the
        product than an admitted gap.
        """
        return cls(
            value=None,
            provenance=Provenance.UNAVAILABLE,
            note=note,
            evidence=evidence,
        )


# ===========================================================================
# Capture quality -- LLD section 5
# ===========================================================================

MIN_ESP_PACKETS_FOR_LATTICE = 200
"""LLD section 7.2. Below this the length-lattice sieve has too little to work
with and must refuse to run rather than guess."""

MIN_DISTINCT_LENGTHS_FOR_LATTICE = 8
"""LLD section 7.2, and the more important of the two thresholds.

Constant-bitrate traffic -- a VoIP call is the canonical case -- produces ESP
packets of one or two lengths, and a single length satisfies almost every
congruence, so the test collapses into a confident wrong answer. This threshold
is what makes it return UNAVAILABLE instead. The PRD section 16 demo capture
carries a VoIP call, so this failure mode is guaranteed to appear on stage.
"""


class CaptureQuality(AnalyzerModel):
    """What the capture can and cannot support. LLD section 5, FR-2.5.

    Every downstream analyser reads this and self-disables where its
    preconditions fail. That is the mechanism that keeps the system honest on
    degraded input, and it is why a truncated or single-length capture produces
    UNAVAILABLE rather than a plausible fabrication.
    """

    packet_count: int = Field(ge=0)

    duration_s: float = Field(ge=0.0)
    """Wall-clock span from the first packet to the last."""

    truncated: bool
    """True when any packet had ``captured_len < orig_len``.

    A snaplen-limited capture destroys the length-lattice analysis of LLD
    section 7.2, because the recorded lengths are the snaplen rather than the
    real ESP payload lengths. The cipher-family detector refuses to run.
    """

    has_ike: bool
    """Whether any IKE traffic was seen at all. False means Track B only."""

    ike_complete: bool
    """Whether ``IKE_SA_INIT`` was captured, rather than joining mid-stream.

    Without it the cleartext transform negotiation was never on the wire during
    the capture window, so Track A has nothing to parse even though IKE packets
    are present. FR-2.4.
    """

    esp_sa_count: int = Field(ge=0)

    sufficient_for_lattice: bool
    """``esp_packet_count >= 200 and distinct_lengths >= 8``. See the constants
    above."""

    warnings: list[str] = Field(default_factory=list)
    """Human-readable qualifications, surfaced in both report formats."""

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if self.ike_complete and not self.has_ike:
            msg = "ike_complete cannot be true when has_ike is false"
            raise ValueError(msg)
        if self.sufficient_for_lattice and self.esp_sa_count == 0:
            msg = "sufficient_for_lattice cannot be true with no ESP SAs"
            raise ValueError(msg)
        if self.sufficient_for_lattice and self.truncated:
            msg = "a truncated capture cannot be sufficient for the length lattice"
            raise ValueError(msg)
        return self


# ===========================================================================
# Track B predictions -- LLD sections 7.6 and 3
# ===========================================================================


class FeatureAttribution(AnalyzerModel):
    """One feature's contribution to a single prediction. FR-4.10, step 9.10.

    Produced from SHAP values so an analyst can see *why* a classification was
    made. A traffic classification that costs the deployment points on the
    metadata-exposure component needs to be arguable, not oracular.
    """

    feature: str = Field(min_length=1)
    """Feature name as used by the extractor, e.g. ``iat_cv`` or ``pkt_len_p90``."""

    contribution: float
    """Signed SHAP value. Positive pushed the prediction towards this label."""

    observed_value: MeasuredValue | None = None
    """The feature's actual value for this window, for display alongside."""


class TrafficPrediction(AnalyzerModel):
    """An inferred inner-traffic label over a time window. FR-4.1, LLD section 7.6.

    Windows are 10 seconds with 50% overlap; adjacent windows sharing an argmax
    label are merged into one span before reaching here, so a prediction covers
    a contiguous stretch of the capture rather than a single window.
    """

    label: TrafficClass

    probability: Confidence
    """Calibrated, not raw softmax. This number is also the metadata-exposure
    measurement (PRD section 4.1): it is exactly what a passive observer learns.
    """

    window_start: UtcDatetime
    window_end: UtcDatetime
    top_features: list[FeatureAttribution] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_window(self) -> Self:
        if self.window_end < self.window_start:
            msg = f"window_end {self.window_end} precedes window_start {self.window_start}"
            raise ValueError(msg)
        return self


# ===========================================================================
# Security associations -- LLD section 3
# ===========================================================================


class SecurityAssociation(AnalyzerModel):
    """One IPsec SA, with every reported parameter tagged by provenance.

    The identity fields at the top are facts about the capture itself -- they
    come from outer IP headers and need no provenance. Everything below them is
    an ``Attribute``, because every one of them is either parsed, inferred, or
    honestly unavailable, and the report has to say which.

    PRD section 7's capability matrix is the specification for which is which.
    Two rows of it are worth restating because they are the ones reviewers
    challenge:

    - ``encryption_keylen`` is UNAVAILABLE whenever IKE was not captured.
      AES-128 and AES-256 are indistinguishable from ESP alone (risk R-4), and
      claiming otherwise is the fastest way to lose a knowledgeable audience.
    - ``operating_mode`` is INFERRED even when IKE *was* captured. Tunnel versus
      transport is not carried in any cleartext field.
    """

    spi_initiator: HexSpi

    spi_responder: HexSpi | None = None
    """``None`` for a one-directional capture, which is a legitimate and common
    analyst situation rather than an error (LLD section 5)."""

    src: IPvAnyAddress
    dst: IPvAnyAddress
    ip_version: Literal[4, 6]

    protocol: Literal["esp", "ah"]
    """``ah`` covers FR-3.8: AH alongside or instead of ESP."""

    first_seen: UtcDatetime
    last_seen: UtcDatetime
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)

    ike_version: Attribute[IkeVersion]
    ike_exchange_mode: Attribute[IkeExchangeMode]
    encryption_alg: Attribute[EncryptionAlg]

    encryption_keylen: Attribute[int]
    """Key length in bits. UNAVAILABLE on an ESP-only capture -- FR-4.9."""

    integrity_alg: Attribute[IntegrityAlg]
    prf_alg: Attribute[PrfAlg]

    dh_group: Attribute[int]
    """IANA Diffie-Hellman group number, e.g. 2, 14, 19, 20."""

    operating_mode: Attribute[OperatingMode]
    pfs_enabled: Attribute[bool]
    auth_method: Attribute[AuthMethod]

    negotiated_lifetime_s: Attribute[int]
    """UNAVAILABLE for IKEv2, always. RFC 7296 removed lifetime negotiation and
    each peer expires SAs on local policy, so there is no negotiated value to
    report -- LLD section 6.4. The assessment falls back to
    ``observed_rekey_s``."""

    observed_rekey_s: Attribute[int]
    """Measured from SPI rotation on the same endpoint pair. FR-4.6."""

    esn_negotiated: Attribute[bool]
    """Track A only. Extended Sequence Numbers are negotiated as IKEv2 transform
    type 5 and are not distinguishable on the wire, because only the low 32 bits
    are transmitted either way (LLD section 7.5)."""

    replay_sane: Attribute[bool]
    """Means "sequence numbers behave correctly on the wire", *not* "anti-replay
    is enabled". The window size is a receiver-side local setting that is never
    transmitted and can never be reported. LLD section 7.5 is emphatic about the
    distinction and the report wording must preserve it."""

    nat_traversal: Attribute[bool]
    """UDP/4500 encapsulation, or NAT_DETECTION notify payloads. FR-3.6."""

    downgrade_available: Attribute[bool]
    """Whether a weaker proposal than the selected one was offered.

    LLD section 6.3 puts this on Track A's ``IkeNegotiation`` and the policy's
    ``CRYPTO-DOWNGRADE-OFFER`` rule keys on it, but LLD section 3 gives it
    nowhere to live in the document the rule evaluates -- so it is carried
    here. Offering 3DES alongside AES-256 is a real weakness even when AES-256
    was chosen, because an active attacker who can influence the negotiation
    may force the weaker option.
    """

    inner_traffic: list[TrafficPrediction] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if self.last_seen < self.first_seen:
            msg = f"last_seen {self.last_seen} precedes first_seen {self.first_seen}"
            raise ValueError(msg)
        if self.src.version != self.ip_version or self.dst.version != self.ip_version:
            msg = (
                f"ip_version={self.ip_version} disagrees with src (v{self.src.version}) "
                f"or dst (v{self.dst.version})"
            )
            raise ValueError(msg)
        if self.packet_count == 0 and self.byte_count > 0:
            msg = "byte_count is non-zero but packet_count is zero"
            raise ValueError(msg)
        return self


# ===========================================================================
# Findings -- LLD sections 3 and 8
# ===========================================================================


class StandardRef(AnalyzerModel):
    """A citation into a published standard. FR-5.2, FR-5.3, LLD section 8.1.

    The auditor persona in PRD section 3 needs to attest against a named
    standard, so a finding that says "weak cipher" without saying which clause
    says so is not usable evidence.
    """

    ref: str = Field(min_length=1)
    """The document, e.g. ``RFC 8221`` or ``NIST SP 800-77 Rev. 1``."""

    clause: str | None = None
    """Section or clause within it, e.g. ``5`` or ``Table 2``."""


class Finding(AnalyzerModel):
    """One security defect or observation. LLD section 3.

    Note the naming: this ``id`` is the *stable rule key* from the policy file,
    not a database primary key. The ``findings`` table stores it in the
    ``finding_key`` column and keeps its own UUIDv7 ``id`` alongside (LLD
    section 4.3). Two findings from the same rule against two different SAs
    share this ``id`` and are told apart by ``sa_spi``.
    """

    id: FindingKey
    title: str = Field(min_length=1)
    severity: Severity
    category: FindingCategory

    penalty: int = Field(ge=0, le=100)
    """Points deducted, before per-category capping. LLD section 8.3 applies the
    caps at scoring time; this is the raw weight from the policy file."""

    description: str = Field(min_length=1)

    remediation: str = Field(min_length=1)
    """Specific and actionable: name the parameter and the value to set it to.
    FR-5.7. "Use stronger crypto" is not remediation."""

    standards: list[StandardRef] = Field(default_factory=list)
    attack_techniques: list[AttackTechniqueId] = Field(default_factory=list)

    sa_spi: HexSpi | None = None
    """Which SA this finding is about. ``None`` for capture-wide findings such
    as metadata exposure."""

    evidence: Evidence
    """Mandatory. FR-5.8 and NFR-7: every finding carries the evidence that
    produced it, or it is an opinion."""

    @model_validator(mode="after")
    def _check_penalty(self) -> Self:
        cap = CATEGORY_CAPS[self.category]
        if self.penalty > cap:
            msg = (
                f"penalty {self.penalty} exceeds the {cap}-point cap for "
                f"category {self.category} (PRD section 10.1)"
            )
            raise ValueError(msg)
        if self.severity is Severity.INFORMATIONAL and self.penalty != 0:
            msg = (
                f"informational finding {self.id} carries a penalty of {self.penalty}; "
                "an observation is not a defect and must not cost points"
            )
            raise ValueError(msg)
        return self


class ThreatMatrixEntry(AnalyzerModel):
    """One MITRE ATT&CK technique and the findings that put it on the board.

    FR-5.5, PRD section 10.3. The dashboard's threat matrix (FR-6.5) renders one
    of these per cell, and clicking through filters the findings view to
    ``finding_ids``.
    """

    technique_id: AttackTechniqueId

    technique_name: str = Field(min_length=1)
    """e.g. ``Network Sniffing``."""

    tactics: list[str] = Field(default_factory=list)
    """ATT&CK tactics the technique sits under, e.g. ``Credential Access``."""

    finding_ids: list[FindingKey] = Field(min_length=1)
    """The findings that mapped here. Never empty -- an entry with no
    contributing finding is a technique nothing in this capture supports, and it
    does not belong on the matrix."""

    max_severity: Severity
    """The highest severity among the contributors, so the grid can be
    colour-coded without a second pass over the findings."""


# ===========================================================================
# Scoring -- PRD section 10, LLD section 8.3
# ===========================================================================


class ScoreBreakdown(AnalyzerModel):
    """The 0-100 risk score and where each deducted point went. FR-5.4.

    PRD section 10 requires the score to be reproducible and explainable: two
    identical captures produce identical scores, and every point deducted is
    traceable to a named finding.

    The ``rating`` bands are deliberately *not* validated against ``total``
    here. Neither the PRD nor the LLD defines the thresholds -- LLD section 8.3
    calls an unspecified ``_rating(total)`` -- so pinning them in the contract
    would be inventing product policy in the wrong file. Step 5.5 owns that
    decision.
    """

    total: int = Field(ge=0, le=100)
    category_penalties: dict[FindingCategory, int] = Field(default_factory=dict)
    rating: Literal["critical", "poor", "fair", "good", "strong"]

    @model_validator(mode="after")
    def _check_penalties(self) -> Self:
        for category, penalty in self.category_penalties.items():
            cap = CATEGORY_CAPS[category]
            if penalty < 0:
                msg = f"category {category} has a negative penalty {penalty}"
                raise ValueError(msg)
            if penalty > cap:
                msg = f"category {category} penalty {penalty} exceeds its {cap}-point cap"
                raise ValueError(msg)

        expected = max(0, 100 - sum(self.category_penalties.values()))
        if self.total != expected:
            msg = (
                f"total {self.total} does not match 100 minus the category penalties "
                f"({expected}). Every deducted point must be traceable (PRD section 10)"
            )
            raise ValueError(msg)
        return self


class MetadataExposure(AnalyzerModel):
    """PRD section 4.1's thesis, made concrete. FR-5.6.

    The system's own traffic classifier doubles as the leakage metric: if it
    identifies the inner traffic as VoIP with 94% confidence, that confidence
    *is* the measurement of what a passive adversary learns. A well-padded
    tunnel should make the classifier uncertain, and that uncertainty is a good
    security outcome.

    LLD section 8.4 scales from the 1/7 chance level rather than from zero,
    because a classifier at chance has learned nothing and the deployment leaks
    nothing -- that should score 0 exposure, not 14. The formula lives in the
    scorer (step 5.6), not here.
    """

    score: int = Field(ge=0, le=100)
    """Higher means more leakage. Inverted relative to the risk score, which is
    deliberate but needs saying in the UI."""

    mean_classifier_confidence: Confidence
    identified_classes: list[TrafficClass] = Field(default_factory=list)

    rationale: str = Field(min_length=1)
    """Why this score, in a sentence the executive report can print verbatim."""


# ===========================================================================
# The assessment document -- LLD section 3
# ===========================================================================


class Assessment(AnalyzerModel):
    """The complete, immutable artefact for one analysis run.

    This is what gets stored in ``assessments.document``, exported by FR-6.9,
    rendered into both report formats, and fetched by the dashboard. Once
    written it never changes, which is what lets the frontend cache it by ID.

    NFR-4 requires that identical input produces byte-identical JSON. Nothing in
    this model defaults to a clock read or a random value: ``generated_at``,
    ``assessment_id`` and ``capture_id`` are all supplied by the caller, so the
    determinism test (step 5.9) can hold them fixed and compare the rest.
    """

    schema_version: Literal["1.0"] = "1.0"
    assessment_id: Uuid7
    capture_id: Uuid7
    generated_at: UtcDatetime
    engine_version: str = Field(min_length=1)

    policy_version: str = Field(min_length=1)
    """Version of the policy file the findings came from. Without it a finding
    set cannot be reproduced, because the rules may have moved (FR-5.9)."""

    model_versions: dict[str, str] = Field(default_factory=dict)
    """Trained artefact versions, keyed by model ID -- ``{"ML-1": "..."}``.
    Empty when no inference ran, which is the correct state for a Track A-only
    assessment."""

    capture_quality: CaptureQuality
    security_associations: list[SecurityAssociation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    score: ScoreBreakdown
    metadata_exposure: MetadataExposure
    threat_matrix: list[ThreatMatrixEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_cross_references(self) -> Self:
        """Nothing may point at something that is not in the document.

        The assessment is exported and rendered standalone, so a dangling
        reference is not a lookup that fails later -- it is a report with a
        blank where a finding should be.
        """
        seen: set[tuple[str, str | None]] = set()
        for finding in self.findings:
            key = (finding.id, finding.sa_spi)
            if key in seen:
                msg = f"duplicate finding {finding.id} for SA {finding.sa_spi}; dedupe first"
                raise ValueError(msg)
            seen.add(key)

        spis = {sa.spi_initiator for sa in self.security_associations}
        spis |= {sa.spi_responder for sa in self.security_associations if sa.spi_responder}
        for finding in self.findings:
            if finding.sa_spi is not None and finding.sa_spi not in spis:
                msg = f"finding {finding.id} references unknown SA SPI {finding.sa_spi}"
                raise ValueError(msg)

        finding_ids = {finding.id for finding in self.findings}
        for entry in self.threat_matrix:
            missing = sorted(set(entry.finding_ids) - finding_ids)
            if missing:
                msg = (
                    f"threat matrix entry {entry.technique_id} cites findings "
                    f"not present in the document: {', '.join(missing)}"
                )
                raise ValueError(msg)

        return self
