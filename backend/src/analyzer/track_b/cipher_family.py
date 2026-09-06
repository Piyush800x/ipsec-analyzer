"""Cipher family detection from ESP packet geometry. Step 9.2, LLD 7.2.

The strongest deterministic signal available from ESP alone, and the one step
the implementation plan marks "never cut".

An ESP packet's payload after the 8-byte SPI and sequence header is
``IV || ciphertext || ICV``. RFC 4303 requires the encrypted portion to be a
multiple of 4 bytes; a block cipher additionally requires a multiple of its
block size. So for a candidate suite with a known IV and ICV length, every
observed payload length must satisfy ``(len - iv - icv) % block == 0``. One
counterexample eliminates the candidate outright -- this is a sieve, not a
score.

**The degenerate case is the important one.** Constant-bitrate traffic (a VoIP
call is the canonical example) produces one or two distinct lengths, and a
single length satisfies almost every congruence, so the sieve collapses and
would report near-certainty about whichever candidate happens to rank first.
``sufficient_for_lattice`` on ``CaptureQuality`` is the gate that stops that,
and this module refuses to run rather than guessing when it is false. The PRD
section 16 demo capture carries a VoIP call, so this failure mode is
guaranteed to appear on stage.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, TypeVar

from analyzer.core.enums import EncryptionAlg, IntegrityAlg
from analyzer.core.schema import Attribute, CaptureQuality, Evidence

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class CipherCandidate:
    name: str
    iv_len: int
    icv_len: int
    block_size: int
    encryption_alg: EncryptionAlg
    integrity_alg: IntegrityAlg
    """``name`` is the human-readable suite, for evidence and report prose.

    ``encryption_alg`` and ``integrity_alg`` are what the contract actually
    stores, and they are separate fields on ``SecurityAssociation`` rather than
    one combined string. Carrying both here is what lets the sieve answer the
    two questions independently -- see ``detect_encryption``. An AEAD suite
    authenticates internally and takes ``IntegrityAlg.NONE``, which is a real
    statement about the suite, not a missing value.
    """

    @property
    def overhead(self) -> int:
        return self.iv_len + self.icv_len

    @property
    def constraint_strength(self) -> tuple[int, int]:
        """How much a survivor's shape actually pins it down.

        Larger block size first, then larger total overhead: a candidate whose
        lengths must be congruent modulo 16 was tested far more strictly by the
        same evidence than one that only needs a multiple of 4, so when both
        survive, the 16 is the better-supported answer.
        """
        return (self.block_size, self.overhead)


CANDIDATES: Final[tuple[CipherCandidate, ...]] = (
    CipherCandidate(
        "AES-CBC + HMAC-SHA1-96", 16, 12, 16, EncryptionAlg.AES_CBC, IntegrityAlg.HMAC_SHA1_96
    ),
    CipherCandidate(
        "AES-CBC + HMAC-SHA256-128",
        16,
        16,
        16,
        EncryptionAlg.AES_CBC,
        IntegrityAlg.HMAC_SHA256_128,
    ),
    CipherCandidate(
        "AES-CBC + HMAC-SHA384-192",
        16,
        24,
        16,
        EncryptionAlg.AES_CBC,
        IntegrityAlg.HMAC_SHA384_192,
    ),
    CipherCandidate("AES-GCM-16", 8, 16, 4, EncryptionAlg.AES_GCM_16, IntegrityAlg.NONE),
    CipherCandidate("AES-GCM-8", 8, 8, 4, EncryptionAlg.AES_GCM_8, IntegrityAlg.NONE),
    CipherCandidate(
        "AES-CTR + HMAC-SHA1-96", 8, 12, 4, EncryptionAlg.AES_CTR, IntegrityAlg.HMAC_SHA1_96
    ),
    CipherCandidate(
        "3DES-CBC + HMAC-SHA1-96",
        8,
        12,
        8,
        EncryptionAlg.TRIPLE_DES_CBC,
        IntegrityAlg.HMAC_SHA1_96,
    ),
    CipherCandidate(
        "ChaCha20-Poly1305", 8, 16, 4, EncryptionAlg.CHACHA20_POLY1305, IntegrityAlg.NONE
    ),
)
"""LLD section 7.2's table, verbatim."""

INSUFFICIENT_NOTE: Final = (
    "insufficient length diversity for the cipher-family sieve: a capture with "
    "few distinct ESP payload lengths satisfies almost every congruence, so any "
    "answer here would be confident and arbitrary (LLD section 7.2)"
)

TRUNCATED_NOTE: Final = (
    "the capture is truncated, so the recorded ESP payload lengths are the "
    "snaplen rather than the real lengths and the congruence test is meaningless"
)

NO_SURVIVORS_NOTE: Final = (
    "no candidate cipher suite is consistent with the observed ESP payload "
    "lengths; the traffic may use a suite outside the candidate set, or the "
    "lengths may not be pure ESP payloads"
)


def survivors(lengths: Sequence[int]) -> list[CipherCandidate]:
    """Every candidate consistent with *all* observed lengths.

    A single counterexample eliminates a candidate. That is what makes this a
    deterministic sieve rather than a fit: there is no threshold to tune and no
    way for a majority of agreeing packets to outvote one that disagrees.
    """
    if not lengths:
        return []
    return [
        candidate
        for candidate in CANDIDATES
        if all(
            (length - candidate.overhead) % candidate.block_size == 0
            and length - candidate.overhead >= candidate.block_size
            for length in lengths
        )
    ]


def confidence_for(survivor_count: int) -> float:
    """LLD section 7.2: ``1 - (survivors - 1) / (candidates - 1)``.

    One survivor is certainty; all of them is no information at all.
    """
    if survivor_count <= 0:
        return 0.0
    return 1.0 - (survivor_count - 1) / (len(CANDIDATES) - 1)


def detect(lengths: Sequence[int], quality: CaptureQuality) -> Attribute[str]:
    """Identify the ESP cipher *suite*, as a human-readable label.

    This is the display form -- "AES-CBC + HMAC-SHA1-96" -- for evidence blocks
    and report prose. It is deliberately **not** what goes into a
    ``SecurityAssociation``: the contract stores encryption and integrity as
    two separate enum-typed fields, and ``detect_encryption`` and
    ``detect_integrity`` produce those. Writing this string into
    ``encryption_alg`` fails validation, which is the type system doing its job.

    Returns UNAVAILABLE far more readily than a scoring approach would. That
    is the design: LLD section 7.2 is explicit that a confident wrong cipher
    identification is far more damaging to this product than an admitted gap.
    """
    outcome = _sieve(lengths, quality)
    if isinstance(outcome, Attribute):
        return Attribute.unavailable(outcome.note or "", evidence=outcome.evidence)
    matching, evidence = outcome
    order = ranked(matching)

    return Attribute.inferred(
        order[0].name,
        confidence_for(len(matching)),
        evidence=evidence,
        note=(
            f"{len(matching)} of {len(CANDIDATES)} candidate suites are consistent "
            f"with every observed ESP payload length"
            + (
                f"; the others still standing are {', '.join(c.name for c in order[1:])}"
                if len(order) > 1
                else ""
            )
        ),
    )


def _sieve(
    lengths: Sequence[int], quality: CaptureQuality
) -> tuple[list[CipherCandidate], Evidence] | Attribute[object]:
    """Shared gate and evidence for every field the sieve reports.

    Returns the survivors on success, or the UNAVAILABLE attribute explaining
    the refusal. One implementation, so ``detect``, ``detect_encryption`` and
    ``detect_integrity`` cannot drift into disagreeing about whether the
    capture was usable at all.
    """
    if quality.truncated:
        return Attribute.unavailable(TRUNCATED_NOTE)
    if not quality.sufficient_for_lattice:
        return Attribute.unavailable(INSUFFICIENT_NOTE)

    matching = survivors(lengths)
    distinct = sorted(set(lengths))
    evidence = Evidence(
        method="esp_length_lattice",
        measured={
            # The full survivor set, not just the winner (LLD section 7.2).
            "survivors": ", ".join(candidate.name for candidate in matching) or "none",
            "survivor_count": len(matching),
            "candidates_tested": len(CANDIDATES),
            "esp_packets": len(lengths),
            "distinct_lengths": len(distinct),
            "shortest_length": distinct[0] if distinct else 0,
            "longest_length": distinct[-1] if distinct else 0,
        },
    )
    if not matching:
        return Attribute.unavailable(NO_SURVIVORS_NOTE, evidence=evidence)
    return matching, evidence


def ranked(matching: Sequence[CipherCandidate]) -> list[CipherCandidate]:
    """Most-constrained first: a 16-byte block survived a stricter test than a
    4-byte one on the same evidence."""
    return sorted(matching, key=lambda c: c.constraint_strength, reverse=True)


def _detect_field(
    lengths: Sequence[int], quality: CaptureQuality, *, field: str, label: str
) -> Attribute[T]:
    """One field of the winning suite, with a confidence measuring *that field*.

    Ranking picks the answer, exactly as LLD section 7.2 specifies. What is
    computed per-field is the **confidence**: it counts the distinct values of
    this field among the survivors rather than the survivors themselves.

    That distinction carries real information, and it usually favours the
    integrity field. Lengths congruent to 28 mod 4 leave four suites standing --
    AES-GCM-16, AES-GCM-8, AES-CTR + HMAC-SHA1-96, ChaCha20-Poly1305 -- naming
    four different ciphers but only two integrity algorithms, because three of
    them are AEAD and take ``none``. The same evidence has pinned the integrity
    algorithm down harder than the cipher. Scoring both fields off the survivor
    count would report one confidence for two genuinely different degrees of
    certainty.
    """
    outcome = _sieve(lengths, quality)
    if isinstance(outcome, Attribute):
        return Attribute.unavailable(outcome.note or "", evidence=outcome.evidence)
    matching, evidence = outcome
    order = ranked(matching)

    distinct_answers = len({getattr(c, field) for c in matching})
    total_answers = len({getattr(c, field) for c in CANDIDATES})
    confidence = 1.0 - (distinct_answers - 1) / (total_answers - 1)

    value: T = getattr(order[0], field)
    others = sorted({str(getattr(c, field)) for c in order[1:]} - {str(value)})
    return Attribute.inferred(
        value,
        confidence,
        evidence=evidence,
        note=(
            f"{len(matching)} of {len(CANDIDATES)} candidate suites are consistent with every "
            f"observed ESP payload length"
            + (
                f", and all of them use this {label}"
                if distinct_answers == 1
                else f"; they propose {distinct_answers} different {label}s, "
                f"the others being {', '.join(others)}"
            )
        ),
    )


def detect_encryption(lengths: Sequence[int], quality: CaptureQuality) -> Attribute[EncryptionAlg]:
    """The ESP encryption algorithm, as ``SecurityAssociation.encryption_alg``.

    Note what this deliberately does not report: the AES **key length**. The
    sieve tests padding congruence, and AES-128 and AES-256 pad identically, so
    128 and 256 are indistinguishable here exactly as they are everywhere else
    in ESP (FR-4.9). ``encryption_keylen`` stays unavailable.
    """
    return _detect_field(lengths, quality, field="encryption_alg", label="encryption algorithm")


def detect_integrity(lengths: Sequence[int], quality: CaptureQuality) -> Attribute[IntegrityAlg]:
    """The ESP integrity algorithm, as ``SecurityAssociation.integrity_alg``.

    Answers far less often than ``detect_encryption``. The ICV length is what
    the sieve measures most directly, but it is also what the AES-CBC rows
    differ by, so a capture that pins the cipher down often leaves this open.
    """
    return _detect_field(lengths, quality, field="integrity_alg", label="integrity algorithm")
