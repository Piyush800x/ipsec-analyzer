"""Step 4.2: IANA transform-ID normalisation and the downgrade strength ranking.

These map protocol-standard numeric IDs (RFC 7296, RFC 2409) onto
``core.enums`` members and do not depend on tshark's JSON field names at all
-- see ``track_a/ike_parser.py``'s module docstring for where that risk
actually lives.
"""

from __future__ import annotations

from analyzer.core.enums import AuthMethod, EncryptionAlg, IntegrityAlg, PrfAlg
from analyzer.track_a.transforms import (
    ikev1_auth_method,
    ikev1_encryption_alg,
    ikev1_hash_alg,
    ikev2_encryption_alg,
    ikev2_integrity_alg,
    ikev2_prf_alg,
    is_weaker_encryption,
)


def test_ikev2_encryption_ids() -> None:
    assert ikev2_encryption_alg(12) is EncryptionAlg.AES_CBC
    assert ikev2_encryption_alg(20) is EncryptionAlg.AES_GCM_16
    assert ikev2_encryption_alg(3) is EncryptionAlg.TRIPLE_DES_CBC
    assert ikev2_encryption_alg(28) is EncryptionAlg.CHACHA20_POLY1305


def test_ikev2_unknown_id_maps_to_unknown_not_a_guess() -> None:
    assert ikev2_encryption_alg(9999) is EncryptionAlg.UNKNOWN
    assert ikev2_prf_alg(9999) is PrfAlg.UNKNOWN
    assert ikev2_integrity_alg(9999) is IntegrityAlg.UNKNOWN


def test_ikev2_prf_and_integrity_ids() -> None:
    assert ikev2_prf_alg(5) is PrfAlg.HMAC_SHA256
    assert ikev2_integrity_alg(2) is IntegrityAlg.HMAC_SHA1_96
    assert ikev2_integrity_alg(0) is IntegrityAlg.NONE


def test_ikev1_attribute_values() -> None:
    assert ikev1_encryption_alg(5) is EncryptionAlg.TRIPLE_DES_CBC
    assert ikev1_encryption_alg(7) is EncryptionAlg.AES_CBC
    assert ikev1_hash_alg(2) is IntegrityAlg.HMAC_SHA1_96
    assert ikev1_auth_method(1) is AuthMethod.PSK


def test_ikev1_unknown_attribute_value() -> None:
    assert ikev1_encryption_alg(255) is EncryptionAlg.UNKNOWN
    assert ikev1_auth_method(255) is AuthMethod.UNKNOWN


def test_downgrade_3des_offered_alongside_aes256() -> None:
    """The LLD section 6.3 example, verbatim."""
    assert is_weaker_encryption((EncryptionAlg.TRIPLE_DES_CBC, 168), (EncryptionAlg.AES_CBC, 256))


def test_downgrade_false_when_candidate_is_not_weaker() -> None:
    assert not is_weaker_encryption((EncryptionAlg.AES_CBC, 256), (EncryptionAlg.AES_CBC, 256))
    assert not is_weaker_encryption((EncryptionAlg.AES_GCM_16, 128), (EncryptionAlg.AES_CBC, 128))


def test_downgrade_shorter_key_same_family_is_weaker() -> None:
    assert is_weaker_encryption((EncryptionAlg.AES_CBC, 128), (EncryptionAlg.AES_CBC, 256))


def test_downgrade_unknown_never_trips_the_check() -> None:
    """An unmapped transform ID is unknown strength, not zero strength."""
    assert not is_weaker_encryption((EncryptionAlg.UNKNOWN, None), (EncryptionAlg.AES_CBC, 256))
    assert not is_weaker_encryption(
        (EncryptionAlg.TRIPLE_DES_CBC, 168), (EncryptionAlg.UNKNOWN, None)
    )
