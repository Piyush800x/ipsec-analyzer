"""IKE transform identifier normalisation (LLD 6.2). Step 4.2.

Every numeric transform-type and transform-ID value here is an IANA-registered
protocol constant (RFC 7296 section 3.3.2 for IKEv2's "Transform Type Values",
RFC 2409 Appendix A for IKEv1's ISAKMP Phase 1 attributes). These do not
depend on Wireshark's JSON field *naming*, which is the part LLD section 6.1
warns drifts silently across releases -- ``ike_parser.py`` isolates that risk
in one adapter function. A wrong mapping in this module is an ordinary
protocol-table bug, found by a test; a wrong field name in the adapter is the
failure mode that produces a wrong answer with no error at all.
"""

from __future__ import annotations

from typing import Final, NamedTuple

from analyzer.core.enums import AuthMethod, EncryptionAlg, IntegrityAlg, PrfAlg

# ===========================================================================
# Transform and attribute type numbers -- shared by both IKE versions
# ===========================================================================

TRANSFORM_TYPE_ENCR: Final = 1
TRANSFORM_TYPE_PRF: Final = 2
TRANSFORM_TYPE_INTEG: Final = 3
TRANSFORM_TYPE_DH: Final = 4
TRANSFORM_TYPE_ESN: Final = 5

ATTR_KEY_LENGTH: Final = 14
"""RFC 2409 Appendix A and RFC 7296 section 3.3.5: attribute type 14 in both
IKE versions. The only transform attribute IKEv2 defines at all; IKEv1 also
uses types 1-5 and 11-12 below for what IKEv2 expresses as separate transform
types or does not negotiate."""

FIXED_KEY_LENGTH_BITS: Final[dict[EncryptionAlg, int]] = {
    EncryptionAlg.DES_CBC: 56,
    EncryptionAlg.TRIPLE_DES_CBC: 168,
}
"""Ciphers whose key length is fixed by the algorithm rather than negotiated.

A variable-length cipher carries ``ATTR_KEY_LENGTH``; a fixed-length one must
not, because there is nothing to choose. So the absence of the attribute is
not missing information for these two -- ``3des-cbc`` *is* 168-bit, the way
``EncryptionAlg``'s own docstring says it is -- and reporting the length is
reading the algorithm's definition, not guessing at a value.

Kept to the two ciphers where that is unambiguous. The AEAD members are
excluded on purpose even though they are commonly deployed at one size: their
IANA transform IDs do not pin a key length, and inventing one for them would
be the fabrication this table is careful not to be. Their length comes from
the attribute or not at all, which is what FR-4.9 requires.

DES is 56 rather than 64: the eight parity bits are not key material, and a
report that said 64 would overstate the strength of the weakest cipher in the
matrix."""

# IKEv1-only Phase 1 transform attribute types (RFC 2409 Appendix A). IKEv2
# expresses ENCR/PRF/INTEG/DH/ESN as distinct *transform types* instead of
# attributes of a single monolithic transform, so these have no IKEv2
# equivalent.
IKEV1_ATTR_ENCRYPTION_ALGORITHM: Final = 1
IKEV1_ATTR_HASH_ALGORITHM: Final = 2
IKEV1_ATTR_AUTH_METHOD: Final = 3
IKEV1_ATTR_GROUP_DESCRIPTION: Final = 4
IKEV1_ATTR_LIFE_TYPE: Final = 11
IKEV1_ATTR_LIFE_DURATION: Final = 12

IKEV1_LIFE_TYPE_SECONDS: Final = 1
"""The other Life Type value, kilobytes (2), is a volume limit, not a time
limit -- ``negotiated_lifetime_s`` only ever reports the seconds form."""

# ===========================================================================
# IKEv2 transform IDs -- RFC 7296 / IANA "Transform Type Values" registry
# ===========================================================================

IKEV2_ENCR: Final[dict[int, EncryptionAlg]] = {
    1: EncryptionAlg.DES_CBC,
    3: EncryptionAlg.TRIPLE_DES_CBC,
    11: EncryptionAlg.NULL,
    12: EncryptionAlg.AES_CBC,
    13: EncryptionAlg.AES_CTR,
    14: EncryptionAlg.AES_CCM_8,
    15: EncryptionAlg.AES_CCM_12,
    16: EncryptionAlg.AES_CCM_16,
    18: EncryptionAlg.AES_GCM_8,
    19: EncryptionAlg.AES_GCM_12,
    20: EncryptionAlg.AES_GCM_16,
    28: EncryptionAlg.CHACHA20_POLY1305,
}

IKEV2_PRF: Final[dict[int, PrfAlg]] = {
    1: PrfAlg.HMAC_MD5,
    2: PrfAlg.HMAC_SHA1,
    4: PrfAlg.AES128_XCBC,
    5: PrfAlg.HMAC_SHA256,
    6: PrfAlg.HMAC_SHA384,
    7: PrfAlg.HMAC_SHA512,
    8: PrfAlg.AES128_CMAC,
}

IKEV2_INTEG: Final[dict[int, IntegrityAlg]] = {
    0: IntegrityAlg.NONE,
    1: IntegrityAlg.HMAC_MD5_96,
    2: IntegrityAlg.HMAC_SHA1_96,
    5: IntegrityAlg.AES_XCBC_96,
    8: IntegrityAlg.AES_CMAC_96,
    12: IntegrityAlg.HMAC_SHA256_128,
    13: IntegrityAlg.HMAC_SHA384_192,
    14: IntegrityAlg.HMAC_SHA512_256,
}

# ===========================================================================
# IKEv1 attribute values -- RFC 2409 Appendix A
# ===========================================================================

IKEV1_ENCR: Final[dict[int, EncryptionAlg]] = {
    1: EncryptionAlg.DES_CBC,
    5: EncryptionAlg.TRIPLE_DES_CBC,
    7: EncryptionAlg.AES_CBC,
}

IKEV1_HASH: Final[dict[int, IntegrityAlg]] = {
    1: IntegrityAlg.HMAC_MD5_96,
    2: IntegrityAlg.HMAC_SHA1_96,
    4: IntegrityAlg.HMAC_SHA256_128,
    5: IntegrityAlg.HMAC_SHA384_192,
    6: IntegrityAlg.HMAC_SHA512_256,
}

IKEV1_AUTH_METHOD: Final[dict[int, AuthMethod]] = {
    1: AuthMethod.PSK,
    2: AuthMethod.DSS_SIG,
    3: AuthMethod.RSA_SIG,
    9: AuthMethod.ECDSA_SIG,
}


def ikev2_encryption_alg(transform_id: int) -> EncryptionAlg:
    return IKEV2_ENCR.get(transform_id, EncryptionAlg.UNKNOWN)


def ikev2_prf_alg(transform_id: int) -> PrfAlg:
    return IKEV2_PRF.get(transform_id, PrfAlg.UNKNOWN)


def ikev2_integrity_alg(transform_id: int) -> IntegrityAlg:
    return IKEV2_INTEG.get(transform_id, IntegrityAlg.UNKNOWN)


def ikev1_encryption_alg(attr_value: int) -> EncryptionAlg:
    return IKEV1_ENCR.get(attr_value, EncryptionAlg.UNKNOWN)


def fixed_key_length_bits(alg: EncryptionAlg) -> int | None:
    """The key length *entailed* by *alg*, or ``None`` if it is negotiated.

    Callers use this only as a fallback when no key-length attribute was on
    the wire, so a proposal that carries one always wins -- this never
    overrides an observation.
    """
    return FIXED_KEY_LENGTH_BITS.get(alg)


def ikev1_hash_alg(attr_value: int) -> IntegrityAlg:
    return IKEV1_HASH.get(attr_value, IntegrityAlg.UNKNOWN)


def ikev1_auth_method(attr_value: int) -> AuthMethod:
    return IKEV1_AUTH_METHOD.get(attr_value, AuthMethod.UNKNOWN)


# ===========================================================================
# Step 4.4: proposed vs selected -- a strength ranking for downgrade detection
# ===========================================================================


class EncryptionStrength(NamedTuple):
    """Comparable crypto strength for one encryption choice.

    Family first, key length second -- ``TRIPLE_DES_CBC`` at any key length is
    weaker than any AES variant, and within one family a longer key wins.
    This is deliberately coarse: it is enough to detect the LLD section 6.3
    example (3DES offered alongside AES-256) without pretending to be a full
    cryptographic strength lattice.
    """

    family_rank: int
    keylen: int


_FAMILY_RANK: Final[dict[EncryptionAlg, int]] = {
    EncryptionAlg.NULL: 0,
    EncryptionAlg.DES_CBC: 1,
    EncryptionAlg.TRIPLE_DES_CBC: 2,
    EncryptionAlg.AES_CBC: 3,
    EncryptionAlg.AES_CTR: 3,
    EncryptionAlg.AES_CCM_8: 3,
    EncryptionAlg.AES_CCM_12: 3,
    EncryptionAlg.AES_CCM_16: 3,
    EncryptionAlg.AES_GCM_8: 3,
    EncryptionAlg.AES_GCM_12: 3,
    EncryptionAlg.AES_GCM_16: 3,
    EncryptionAlg.CHACHA20_POLY1305: 3,
}
"""Everything AES-family or better ranks equally against 3DES/DES/NULL. Ranking
GCM/CCM/ChaCha above CBC would be defensible but is not needed for anything
this project currently detects, and inventing an ordering with no rule that
consumes it is speculative work with no test to justify it."""

_UNKNOWN_RANK: Final = -1
"""An unmapped transform ID is never treated as "weaker than" a known one --
its strength is genuinely unknown, not zero -- so it never trips the
downgrade check by comparison alone."""


def encryption_strength(alg: EncryptionAlg, keylen: int | None) -> EncryptionStrength:
    return EncryptionStrength(_FAMILY_RANK.get(alg, _UNKNOWN_RANK), keylen or 0)


def is_weaker_encryption(
    candidate: tuple[EncryptionAlg, int | None], selected: tuple[EncryptionAlg, int | None]
) -> bool:
    """Whether *candidate* is weaker than *selected*, for ``downgrade_available``."""
    candidate_alg, candidate_keylen = candidate
    if candidate_alg is EncryptionAlg.UNKNOWN or selected[0] is EncryptionAlg.UNKNOWN:
        return False
    return encryption_strength(candidate_alg, candidate_keylen) < encryption_strength(*selected)
