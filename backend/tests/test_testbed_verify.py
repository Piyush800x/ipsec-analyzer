"""Step 8.2: the label verification harness.

Run against constructed ground truth and constructed Track A output rather
than a real batch -- generating one needs Docker (see CHANGELOG). What is
being tested here is the *classification rule*, which is where this harness
earns its keep: a strict equality check would be easy and would force the
parser to guess in order to go green.
"""

from __future__ import annotations

import json
from pathlib import Path

from analyzer.core.enums import (
    AuthMethod,
    EncryptionAlg,
    IkeExchangeMode,
    IkeVersion,
    IntegrityAlg,
    OperatingMode,
)
from analyzer.core.schema import Attribute, SecurityAssociation
from testbed.config import WEAK_REFERENCE
from testbed.verify import Outcome, verify_batch, verify_session
from tests.test_assess_engine import T0


def _sa(**overrides: object) -> SecurityAssociation:
    """A Track A-shaped SA: IKE facts observed, Child SA crypto inferred,
    Track B's fields unavailable."""
    base: dict[str, object] = {
        "spi_initiator": "0000000a",
        "spi_responder": "0000000b",
        "src": "10.10.0.2",
        "dst": "10.10.0.3",
        "ip_version": 4,
        "protocol": "esp",
        "first_seen": T0,
        "last_seen": T0,
        "packet_count": 100,
        "byte_count": 10_000,
        "ike_version": Attribute[IkeVersion].observed(IkeVersion.IKEV1),
        "ike_exchange_mode": Attribute[IkeExchangeMode].observed(IkeExchangeMode.AGGRESSIVE),
        "encryption_alg": Attribute[EncryptionAlg].inferred(EncryptionAlg.TRIPLE_DES_CBC, 0.6),
        "encryption_keylen": Attribute[int].inferred(168, 0.6),
        "integrity_alg": Attribute[IntegrityAlg].inferred(IntegrityAlg.HMAC_SHA1_96, 0.6),
        "prf_alg": Attribute[str].unavailable("IKEv1 does not negotiate a PRF separately"),
        "dh_group": Attribute[int].observed(2),
        "operating_mode": Attribute[OperatingMode].unavailable("not in any cleartext field"),
        "pfs_enabled": Attribute[bool].unavailable("Track B infers this"),
        "auth_method": Attribute[AuthMethod].observed(AuthMethod.PSK),
        "negotiated_lifetime_s": Attribute[int].observed(86400),
        "observed_rekey_s": Attribute[int].unavailable("Track B"),
        "esn_negotiated": Attribute[bool].unavailable("not observable"),
        "replay_sane": Attribute[bool].unavailable("Track B"),
        "nat_traversal": Attribute[bool].observed(False),
        "downgrade_available": Attribute[bool].observed(False),
        "inner_traffic": [],
    }
    base.update(overrides)
    return SecurityAssociation(**base)  # type: ignore[arg-type] # a fully-populated kwargs dict


def _labels() -> dict:
    return WEAK_REFERENCE.to_ground_truth()


def test_matching_observed_fields_pass() -> None:
    result = verify_session(_labels(), _sa())
    by_field = {r.field: r for r in result.results}

    assert by_field["ike_version"].outcome is Outcome.MATCH
    assert by_field["ike_exchange_mode"].outcome is Outcome.MATCH
    assert by_field["dh_group"].outcome is Outcome.MATCH
    assert by_field["auth_method"].outcome is Outcome.MATCH
    assert by_field["negotiated_lifetime_s"].outcome is Outcome.MATCH
    assert result.passed


def test_unobservable_field_reported_unavailable_is_an_honest_gap() -> None:
    """The rule that stops the harness rewarding a parser that guesses."""
    result = verify_session(_labels(), _sa())
    by_field = {r.field: r for r in result.results}

    # The weak reference is IKEv1, so ground truth marks prf_alg unobservable.
    assert by_field["prf_alg"].outcome is Outcome.HONEST_GAP
    assert by_field["operating_mode"].outcome is Outcome.HONEST_GAP
    assert result.passed


def test_value_where_ground_truth_says_unobservable_is_fabrication() -> None:
    """Worse than a mismatch: a guess the report would present as a fact."""
    sa = _sa(operating_mode=Attribute[OperatingMode].observed(OperatingMode.TRANSPORT))

    result = verify_session(_labels(), sa)
    by_field = {r.field: r for r in result.results}

    assert by_field["operating_mode"].outcome is Outcome.FABRICATED
    assert not result.passed


def test_inferred_child_sa_crypto_is_not_scored_as_a_mismatch() -> None:
    """CHANGELOG's Phase 4 open spec question, resolved.

    The testbed configures IKE on CBC while ESP carries AEAD, so Track A's
    same-family inference is *expected* to diverge on GCM rows. Counting that
    as a failure would mean the harness only passes if Track A lies.
    """
    sa = _sa(encryption_alg=Attribute[EncryptionAlg].inferred(EncryptionAlg.AES_CBC, 0.6))

    result = verify_session(_labels(), sa)
    by_field = {r.field: r for r in result.results}

    assert by_field["encryption_alg"].outcome is Outcome.INFERRED
    assert result.passed, "an inference that diverges is not a parser bug"


def test_observed_and_wrong_is_a_mismatch() -> None:
    sa = _sa(dh_group=Attribute[int].observed(14))  # ground truth says group 2

    result = verify_session(_labels(), sa)
    by_field = {r.field: r for r in result.results}

    assert by_field["dh_group"].outcome is Outcome.MISMATCH
    assert not result.passed
    assert result.failures[0].expected == 2


def test_unavailable_where_ground_truth_expects_a_value_is_not_a_pass() -> None:
    """A parser that gave up is not the same as a field that cannot be read."""
    sa = _sa(dh_group=Attribute[int].unavailable("could not parse"))

    result = verify_session(_labels(), sa)
    by_field = {r.field: r for r in result.results}

    assert by_field["dh_group"].outcome is Outcome.NOT_REPORTED


# --- batch walking ----------------------------------------------------------


def _write_session(batch: Path, name: str) -> None:
    session = batch / name
    session.mkdir(parents=True)
    (session / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    labels = _labels()
    labels["name"] = name
    (session / "labels.json").write_text(json.dumps(labels), encoding="utf-8")


def test_batch_verifies_every_session(tmp_path: Path) -> None:
    for index in range(3):
        _write_session(tmp_path, f"session-{index}")

    report = verify_batch(tmp_path, parse=lambda _: [_sa()])

    assert len(report.sessions) == 3
    assert report.passed
    assert "PASS" in report.render()


def test_batch_reports_a_session_the_parser_could_not_read(tmp_path: Path) -> None:
    _write_session(tmp_path, "good")
    _write_session(tmp_path, "bad")

    def parse(pcap: Path) -> list[SecurityAssociation]:
        if "bad" in str(pcap):
            raise RuntimeError("tshark exploded")
        return [_sa()]

    report = verify_batch(tmp_path, parse=parse)

    assert len(report.sessions) == 1
    assert report.unreadable == [("bad", "parser raised RuntimeError: tshark exploded")]
    assert not report.passed
    assert "FAIL" in report.render()


def test_batch_flags_a_session_missing_its_files(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()

    report = verify_batch(tmp_path, parse=lambda _: [_sa()])

    assert not report.passed
    assert "missing capture.pcap or labels.json" in report.render()


def test_batch_flags_a_session_with_no_parsed_sas(tmp_path: Path) -> None:
    _write_session(tmp_path, "quiet")

    report = verify_batch(tmp_path, parse=lambda _: [])

    assert not report.passed
    assert "no security associations" in report.render()


def test_report_totals_are_rendered(tmp_path: Path) -> None:
    _write_session(tmp_path, "one")
    report = verify_batch(tmp_path, parse=lambda _: [_sa()])

    totals = report.totals()

    assert totals[Outcome.MATCH] > 0
    assert totals[Outcome.HONEST_GAP] > 0
    assert totals[Outcome.INFERRED] > 0
