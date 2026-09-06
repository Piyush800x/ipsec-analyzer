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
from typing import Final

from analyzer.core.schema import Attribute, CaptureQuality, Evidence


@dataclass(frozen=True, slots=True)
class CipherCandidate:
    name: str
    iv_len: int
    icv_len: int
    block_size: int

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
    CipherCandidate("AES-CBC + HMAC-SHA1-96", 16, 12, 16),
    CipherCandidate("AES-CBC + HMAC-SHA256-128", 16, 16, 16),
    CipherCandidate("AES-CBC + HMAC-SHA384-192", 16, 24, 16),
    CipherCandidate("AES-GCM-16", 8, 16, 4),
    CipherCandidate("AES-GCM-8", 8, 8, 4),
    CipherCandidate("AES-CTR + HMAC-SHA1-96", 8, 12, 4),
    CipherCandidate("3DES-CBC + HMAC-SHA1-96", 8, 12, 8),
    CipherCandidate("ChaCha20-Poly1305", 8, 16, 4),
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
    """Identify the ESP cipher family, or refuse to.

    Returns UNAVAILABLE far more readily than a scoring approach would. That
    is the design: LLD section 7.2 is explicit that a confident wrong cipher
    identification is far more damaging to this product than an admitted gap.
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

    # Most-constrained first: a 16-byte block survived a stricter test than a
    # 4-byte one on the same evidence.
    ranked = sorted(matching, key=lambda c: c.constraint_strength, reverse=True)
    return Attribute.inferred(
        ranked[0].name,
        confidence_for(len(matching)),
        evidence=evidence,
        note=(
            f"{len(matching)} of {len(CANDIDATES)} candidate suites are consistent "
            f"with every observed ESP payload length"
            + (
                f"; the others still standing are {', '.join(c.name for c in ranked[1:])}"
                if len(ranked) > 1
                else ""
            )
        ),
    )
