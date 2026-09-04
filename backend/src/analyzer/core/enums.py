"""Every enumerated value in the system, defined exactly once.

LLD section 1 makes this file the sole home for enums: the database stores their
values as text, the API serialises them as strings, and ``scripts/gen-types.sh``
mirrors them into ``frontend/src/types/generated.ts``. Re-declaring any of these
values as a string literal elsewhere is how the frontend and backend drift apart
without anyone noticing.

Two conventions hold throughout:

- Values are lowercase, hyphenated or ``snake_case``, never the Python member
  name. The wire format is the value; the member name is for Python only.
- ``StrEnum`` rather than LLD section 3's ``(str, Enum)``. They behave
  identically for comparison and serialisation, but ``StrEnum`` makes
  ``f"{Provenance.OBSERVED}"`` render as ``observed`` instead of
  ``Provenance.OBSERVED``, which is the difference between a correct report and
  a confusing one.

Where a parsed value has no member -- a vendor-private IKE transform ID, say --
use the enum's ``UNKNOWN`` member and record the raw value in the owning
``Attribute.note``. Never invent a member to make an unknown fit.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class Provenance(StrEnum):
    """How a reported fact was arrived at. LLD section 3, PRD section 4.

    The load-bearing distinction of the whole product. An analyst acting on a
    report needs to know which claims are facts and which are estimates, so
    every ``Attribute`` carries one of these, and the pairing with ``confidence``
    is enforced by a validator rather than by convention.
    """

    OBSERVED = "observed"
    """Track A. Parsed from cleartext IKE. Certain, and carries no confidence."""

    INFERRED = "inferred"
    """Track B. Statistical. Must carry a calibrated confidence."""

    UNAVAILABLE = "unavailable"
    """Not determinable from this capture. Carries a note saying why.

    This is a finding the tool is making, not an absence of data -- see FR-4.9
    and the AES key-length case in PRD section 7. It renders as an explicit
    statement, never as a blank cell or a dash.
    """


class IkeVersion(StrEnum):
    """IKE protocol version, from the ISAKMP header version field. FR-3.1."""

    IKEV1 = "ikev1"
    """RFC 2409. Phase 1 / Phase 2, and negotiates SA lifetimes."""

    IKEV2 = "ikev2"
    """RFC 7296. Note that it does *not* negotiate lifetimes -- LLD section 6.4."""


class IkeExchangeMode(StrEnum):
    """IKEv1 Phase 1 exchange mode, from the header exchange type. FR-3.1.

    IKEv2 has no equivalent; for an IKEv2 SA this attribute is ``UNAVAILABLE``
    rather than carrying a member of this enum.
    """

    MAIN = "main"
    """Exchange type 2, identity protection. Identities are encrypted."""

    AGGRESSIVE = "aggressive"
    """Exchange type 4. Three messages, and the PSK hash is exposed to a passive
    observer -- offline cracking material. Critical severity in PRD section 10.2.
    """


class EncryptionAlg(StrEnum):
    """ESP / IKE encryption transform, *without* key length. FR-3.2.

    Key length lives in a separate ``encryption_keylen`` attribute, deliberately.
    From ESP alone the cipher family is inferable from packet geometry but the
    AES key length is not (PRD section 7, risk R-4), so the two must be
    reportable independently: ``aes-cbc`` OBSERVED alongside a keylen that is
    UNAVAILABLE is a valid and common state. Folding the length into the name
    would make FR-4.9 unrepresentable.

    ``3des-cbc`` and ``des-cbc`` carry no length because theirs is fixed by the
    algorithm. The AEAD members keep their ICV length because IANA assigns each
    a distinct transform ID and their packet geometry differs (LLD section 7.2).
    """

    NULL = "null"
    """ENCR_NULL. No confidentiality at all. Critical."""

    DES_CBC = "des-cbc"
    """56-bit effective key. Broken."""

    TRIPLE_DES_CBC = "3des-cbc"
    """64-bit block, so subject to birthday-bound collisions on long-lived
    connections. Deprecated by RFC 8221. The weak-reference tunnel of PRD
    section 16."""

    AES_CBC = "aes-cbc"
    AES_CTR = "aes-ctr"

    AES_GCM_8 = "aes-gcm-8"
    """AEAD, 8-byte ICV."""

    AES_GCM_12 = "aes-gcm-12"
    """AEAD, 12-byte ICV."""

    AES_GCM_16 = "aes-gcm-16"
    """AEAD, 16-byte ICV. The hardened-reference tunnel of PRD section 16."""

    AES_CCM_8 = "aes-ccm-8"
    AES_CCM_12 = "aes-ccm-12"
    AES_CCM_16 = "aes-ccm-16"
    CHACHA20_POLY1305 = "chacha20-poly1305"

    UNKNOWN = "unknown"
    """A transform ID with no member here. Record the raw ID in the note."""


class IntegrityAlg(StrEnum):
    """ESP / IKE integrity transform. FR-3.2.

    Names carry the truncation length in bits because that length is what shows
    up as fixed per-packet overhead, which is how Track B infers the algorithm
    class from ESP alone (FR-4.4, LLD section 7.2).
    """

    NONE = "none"
    """Correct and expected for AEAD ciphers, which integrity-protect
    internally. Distinct from UNKNOWN: this is a negotiated absence."""

    HMAC_MD5_96 = "hmac-md5-96"
    HMAC_SHA1_96 = "hmac-sha1-96"
    HMAC_SHA256_128 = "hmac-sha256-128"
    HMAC_SHA384_192 = "hmac-sha384-192"
    HMAC_SHA512_256 = "hmac-sha512-256"
    AES_XCBC_96 = "aes-xcbc-96"
    AES_CMAC_96 = "aes-cmac-96"

    UNKNOWN = "unknown"


class PrfAlg(StrEnum):
    """IKE pseudo-random function, transform type 2. FR-3.2.

    IKEv2 only; IKEv1 derives the PRF from the negotiated hash algorithm rather
    than negotiating it separately, so for an IKEv1 SA this is UNAVAILABLE.
    """

    HMAC_MD5 = "hmac-md5"
    HMAC_SHA1 = "hmac-sha1"
    HMAC_SHA256 = "hmac-sha256"
    HMAC_SHA384 = "hmac-sha384"
    HMAC_SHA512 = "hmac-sha512"
    AES128_XCBC = "aes128-xcbc"
    AES128_CMAC = "aes128-cmac"

    UNKNOWN = "unknown"


class OperatingMode(StrEnum):
    """IPsec operating mode. FR-1.3, FR-4.2.

    Never OBSERVED from the wire: it is not carried in any cleartext field, so it
    is inferred from encapsulation overhead even when IKE was captured
    (PRD section 7). ML-2 produces it.
    """

    TUNNEL = "tunnel"
    """Inner IP header is encapsulated. Outer addresses are gateways."""

    TRANSPORT = "transport"
    """No inner IP header. Outer addresses are the real endpoints."""


class TrafficClass(StrEnum):
    """Inner application traffic carried inside ESP. FR-1.10, FR-4.1.

    Exactly seven classes. LLD section 8.4 scales the metadata-exposure score
    from the 1/7 chance level, so adding or removing a member changes that
    formula -- ``tests/test_enums.py`` asserts the count so the coupling breaks
    loudly rather than silently skewing the score.

    The testbed matrix (LLD section 10.1) spells file transfer ``filexfer`` and
    its generator module is ``testbed/traffic/filexfer.py``; the canonical label
    is ``file_transfer``. The matrix loader owns that mapping.
    """

    ICMP = "icmp"
    WEB = "web"
    VOIP = "voip"
    VIDEO = "video"
    EMAIL = "email"
    FILE_TRANSFER = "file_transfer"
    MESSAGING = "messaging"


class Severity(StrEnum):
    """Finding severity. PRD section 10.2."""

    CRITICAL = "critical"
    """Practically exploitable today. 3DES; DH Group 1; IKEv1 aggressive + PSK."""

    HIGH = "high"
    """Significantly below current standards. DH Group 2; PFS disabled."""

    MEDIUM = "medium"
    """Below best practice, not immediately exploitable. SHA-1 integrity."""

    LOW = "low"
    """Hygiene. Verbose Vendor ID exposure; suboptimal lifetime."""

    INFORMATIONAL = "informational"
    """An observation, not a defect. NAT-T in use; IPv6 transport. Carries a
    penalty of zero."""


class FindingCategory(StrEnum):
    """Scoring category a finding is charged against. PRD section 10.1.

    Penalties are capped per category (see ``CATEGORY_CAPS``) so that three
    medium cryptographic findings cannot outweigh one critical key-exchange
    failure.
    """

    CRYPTOGRAPHIC_STRENGTH = "cryptographic_strength"
    KEY_EXCHANGE = "key_exchange"
    PROTOCOL_VERSION_MODE = "protocol_version_mode"
    KEY_MANAGEMENT = "key_management"
    REPLAY_INTEGRITY = "replay_integrity"
    METADATA_EXPOSURE = "metadata_exposure"


CATEGORY_CAPS: Final[dict[FindingCategory, int]] = {
    FindingCategory.CRYPTOGRAPHIC_STRENGTH: 30,
    FindingCategory.KEY_EXCHANGE: 20,
    FindingCategory.PROTOCOL_VERSION_MODE: 15,
    FindingCategory.KEY_MANAGEMENT: 15,
    FindingCategory.REPLAY_INTEGRITY: 10,
    FindingCategory.METADATA_EXPOSURE: 10,
}
"""Maximum penalty each category may contribute. PRD section 10.1, summing to 100.

Lives beside the enum rather than in ``assess/scoring.py`` so that adding a
category without deciding its cap is caught immediately rather than silently
scoring zero. Consumed by the scorer in step 5.5.
"""


class AuthMethod(StrEnum):
    """Peer authentication method. FR-3.5.

    Readable for IKEv1 (transform attribute 3). For IKEv2 the AUTH payload sits
    inside the encrypted ``IKE_AUTH`` exchange, so this is normally UNAVAILABLE
    -- LLD section 6.2 is explicit that the parser must not fabricate a value
    there.
    """

    PSK = "psk"
    """Pre-shared key. In IKEv1 aggressive mode the hash is exposed to a passive
    observer, which is offline cracking material -- ATT&CK T1110."""

    RSA_SIG = "rsa_sig"
    DSS_SIG = "dss_sig"
    ECDSA_SIG = "ecdsa_sig"
    EAP = "eap"

    NULL_AUTH = "null_auth"
    """RFC 7619. Authentication deliberately omitted."""

    UNKNOWN = "unknown"


class CaptureSource(StrEnum):
    """Where a capture came from. LLD section 4.3, ``captures.source``."""

    UPLOAD = "upload"
    """Analyst-supplied PCAP. ``ground_truth`` is NULL for these."""

    LIVE = "live"
    """Captured from a named interface. FR-2.2."""

    TESTBED = "testbed"
    """Produced by M1, and carries a ground-truth label sidecar. FR-1.11."""


class RunStatus(StrEnum):
    """Analysis run lifecycle. LLD section 4.3, ``analysis_runs.status``."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class RunStage(StrEnum):
    """Pipeline stage a run is currently in. LLD section 4.3,
    ``analysis_runs.stage``.

    Reported over SSE so the dashboard can show progress (FR-6.1, LLD section 9).
    """

    INGEST = "ingest"
    TRACK_A = "track_a"
    TRACK_B = "track_b"
    ASSESS = "assess"
    REPORT = "report"
