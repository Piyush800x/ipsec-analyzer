"""The testbed session configuration and its ground truth.

Implementation-plan steps 2.2 and 2.7. These tests need no Docker: they are
about the translation between matrix labels and contract values, which is where
a mislabelled dataset would come from.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from analyzer.core.enums import (
    AuthMethod,
    EncryptionAlg,
    IkeExchangeMode,
    IkeVersion,
    IntegrityAlg,
    OperatingMode,
    PrfAlg,
    TrafficClass,
)
from testbed.config import (
    DH_GROUP_KEYWORDS,
    ESP_SUITES,
    HARDENED_REFERENCE,
    TRAFFIC_LABELS,
    WEAK_REFERENCE,
    EspSuite,
    IkeFlavour,
    IpVersion,
    SessionConfig,
)

MATRIX_DIMENSIONS = frozenset(
    {"mode", "ike", "esp", "dh", "pfs", "ip", "traffic", "lifetime_s", "duration_s"}
)


def test_every_esp_suite_decomposes_into_contract_values() -> None:
    """Each matrix label maps onto core.enums members, not new strings."""
    for suite in EspSuite:
        spec = ESP_SUITES[suite]
        assert isinstance(spec.encryption_alg, EncryptionAlg)
        assert isinstance(spec.integrity_alg, IntegrityAlg)
        assert spec.encryption_keylen > 0


def test_aead_suites_report_integrity_none_not_unknown() -> None:
    """An AEAD cipher integrity-protects internally.

    ``NONE`` is a negotiated absence; ``UNKNOWN`` would mean the parser could
    not tell. Recording the wrong one here would teach step 4.8 to accept a
    parser that cannot distinguish them.
    """
    for suite in (EspSuite.AES128GCM16, EspSuite.AES256GCM16):
        assert ESP_SUITES[suite].integrity_alg is IntegrityAlg.NONE


def test_traffic_labels_cover_every_traffic_class() -> None:
    """The matrix vocabulary maps onto every contract class, and only those."""
    assert set(TRAFFIC_LABELS.values()) == set(TrafficClass)


def test_filexfer_maps_to_file_transfer() -> None:
    """LLD 10.1 spells it ``filexfer``; the contract spells it ``file_transfer``."""
    assert TRAFFIC_LABELS["filexfer"] is TrafficClass.FILE_TRANSFER


def test_unknown_dh_group_is_rejected_at_construction() -> None:
    with pytest.raises(ValidationError, match="DH_GROUP_KEYWORDS"):
        SessionConfig(
            name="bad-dh",
            mode=OperatingMode.TUNNEL,
            ike=IkeFlavour.IKEV2,
            esp=EspSuite.AES128_SHA1,
            dh=5,
            pfs=True,
            traffic=TrafficClass.ICMP,
        )


def test_session_config_is_frozen() -> None:
    """A config mutated after rendering would label a tunnel never built."""
    with pytest.raises(ValidationError):
        WEAK_REFERENCE.name = "changed"  # type: ignore[misc]  # frozen model, by design


class TestProposals:
    def test_pfs_adds_the_dh_group_to_the_esp_proposal(self) -> None:
        """PFS at the wire level is a fresh key exchange for the Child SA."""
        with_pfs = HARDENED_REFERENCE
        without = with_pfs.model_copy(update={"pfs": False})
        assert with_pfs.esp_proposal.endswith(f"-{DH_GROUP_KEYWORDS[with_pfs.dh]}")
        assert without.esp_proposal == without.esp.value

    def test_ike_proposal_is_cbc_even_for_aead_suites(self) -> None:
        """IKEv1 cannot negotiate an AEAD cipher for Phase 1.

        Deriving the IKE proposal from the ESP suite would make every
        ikev1-by-gcm cell of the matrix fail to negotiate.
        """
        cfg = HARDENED_REFERENCE.model_copy(update={"ike": IkeFlavour.IKEV1_MAIN})
        assert "gcm" not in cfg.ike_proposal
        assert "gcm" in cfg.esp_proposal

    def test_weak_reference_matches_the_lld_fixture(self) -> None:
        assert WEAK_REFERENCE.ike_proposal == "3des-sha1-modp1024"
        assert WEAK_REFERENCE.esp_proposal == "3des-sha1"

    def test_hardened_reference_matches_the_lld_fixture(self) -> None:
        assert HARDENED_REFERENCE.ike_proposal == "aes256-sha256-ecp256"
        assert HARDENED_REFERENCE.esp_proposal == "aes256gcm16-ecp256"


class TestTrafficSelectors:
    def test_transport_mode_protects_the_outer_addresses(self) -> None:
        assert WEAK_REFERENCE.local_ts("left") == "10.10.0.2/32"
        assert WEAK_REFERENCE.remote_ts("left") == "10.10.0.3/32"

    def test_tunnel_mode_protects_the_subnets_behind_each_peer(self) -> None:
        assert HARDENED_REFERENCE.local_ts("left") == "192.168.10.0/24"
        assert HARDENED_REFERENCE.remote_ts("left") == "192.168.20.0/24"

    def test_traffic_targets_the_protected_address_in_tunnel_mode(self) -> None:
        """Otherwise the packets never match a policy and leave in the clear."""
        assert HARDENED_REFERENCE.traffic_endpoint("right") == "192.168.20.1"

    def test_traffic_targets_the_outer_address_in_transport_mode(self) -> None:
        assert WEAK_REFERENCE.traffic_endpoint("right") == "10.10.0.3"

    def test_ipv6_selectors_use_the_v6_addressing(self) -> None:
        cfg = HARDENED_REFERENCE.model_copy(update={"ip": IpVersion.V6})
        assert cfg.local_ts("left").startswith("fd00:")


class TestGroundTruth:
    """Step 2.7. The label file is what step 4.8 asserts the parser against."""

    def test_weak_reference_records_all_nine_dimensions(self) -> None:
        labels = WEAK_REFERENCE.to_ground_truth()
        assert set(labels["dimensions"]) == MATRIX_DIMENSIONS
        assert labels["dimensions"] == {
            "mode": "transport",
            "ike": "ikev1-aggressive",
            "esp": "3des-sha1",
            "dh": 2,
            "pfs": False,
            "ip": "v4",
            "traffic": "voip",
            "lifetime_s": 86400,
            "duration_s": 180,
        }

    def test_expected_values_are_contract_enum_values(self) -> None:
        expected = WEAK_REFERENCE.to_ground_truth()["expected"]
        assert expected["ike_version"] == IkeVersion.IKEV1.value
        assert expected["ike_exchange_mode"] == IkeExchangeMode.AGGRESSIVE.value
        assert expected["encryption_alg"] == EncryptionAlg.TRIPLE_DES_CBC.value
        assert expected["integrity_alg"] == IntegrityAlg.HMAC_SHA1_96.value
        assert expected["auth_method"] == AuthMethod.PSK.value
        assert expected["operating_mode"] == OperatingMode.TRANSPORT.value

    def test_ikev2_declares_lifetime_unobservable(self) -> None:
        """RFC 7296 removed lifetime negotiation. Step 4.5 requires UNAVAILABLE.

        Without this declaration, step 8.2 would flag a correctly honest parser
        as mismatching, and the obvious fix would be to teach it to guess.
        """
        unobservable = HARDENED_REFERENCE.to_ground_truth()["not_observable_from_ike"]
        assert "negotiated_lifetime_s" in unobservable
        assert "auth_method" in unobservable
        assert "RFC 7296" in unobservable["negotiated_lifetime_s"]

    def test_ikev1_lifetime_is_observable_but_prf_is_not(self) -> None:
        """IKEv1 negotiates a lifetime and derives its PRF from the hash."""
        unobservable = WEAK_REFERENCE.to_ground_truth()["not_observable_from_ike"]
        assert "negotiated_lifetime_s" not in unobservable
        assert "prf_alg" in unobservable

    def test_operating_mode_is_never_observable(self) -> None:
        """PRD 7: tunnel versus transport is in no cleartext field."""
        for cfg in (WEAK_REFERENCE, HARDENED_REFERENCE):
            assert "operating_mode" in cfg.to_ground_truth()["not_observable_from_ike"]

    def test_ikev1_prf_is_none_and_ikev2_prf_is_derived(self) -> None:
        assert WEAK_REFERENCE.prf_alg is None
        assert HARDENED_REFERENCE.prf_alg is PrfAlg.HMAC_SHA256

    def test_every_unobservable_field_is_present_in_expected(self) -> None:
        """The two blocks describe the same fields, or the harness compares
        against a key that does not exist."""
        for cfg in (WEAK_REFERENCE, HARDENED_REFERENCE):
            labels = cfg.to_ground_truth()
            assert set(labels["not_observable_from_ike"]) <= set(labels["expected"])

    def test_ground_truth_carries_the_image_versions_it_was_given(self) -> None:
        labels = WEAK_REFERENCE.to_ground_truth(image_versions={"strongswan-swanctl": "5.9.8"})
        assert labels["image_versions"]["strongswan-swanctl"] == "5.9.8"
