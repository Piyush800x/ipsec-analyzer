"""Step 4.6: SPI/flow correlation. Step 4.8: assembly into SecurityAssociation.

Also an end-to-end ``run_track_a`` test wiring a synthetic pcap (built the
same way as the Phase 3 ingest tests, ``tests/_pcap.py``) through a fake
tshark binary (``tests/_fakebin.py``) to a real ``SecurityAssociation``.
"""

from __future__ import annotations

from pathlib import Path

from analyzer.core.enums import (
    AuthMethod,
    EncryptionAlg,
    IkeExchangeMode,
    IkeVersion,
    IntegrityAlg,
    Provenance,
)
from analyzer.ingest.flow import Flow, SAPair, assemble_flows
from analyzer.ingest.reader import FlowKey, PacketRecord, read_packets
from analyzer.track_a.correlate import (
    CORRELATION_WINDOW_S,
    assemble_security_association,
    correlate_negotiation,
    run_track_a,
)
from analyzer.track_a.ike_parser import (
    IkeNegotiation,
    Proposal,
    Transform,
    build_negotiations,
    parse_isakmp_json,
)
from tests._fakebin import write_fake_tshark
from tests._pcap import DLT_EN10MB, esp_payload, eth_frame, ipv4_packet, udp_packet, write_pcap
from tests._tshark_json import attr, isakmp_header, packet, proposal, sa_payload, transform

IKE_SA_INIT = 34


def _esp_record(index: int, ts: float, src: str, dst: str, spi: int) -> PacketRecord:
    return PacketRecord(
        index=index,
        ts=ts,
        ip_version=4,
        src=src,
        dst=dst,
        proto="esp",
        spi=spi,
        seq=index,
        ip_payload_len=48,
        esp_payload_len=32,
        captured_len=68,
        orig_len=68,
    )


def _flow(src: str, dst: str, spi: int, start_ts: float, end_ts: float) -> Flow:
    key = FlowKey(src=src, dst=dst, spi=spi, proto="esp")
    packets = (_esp_record(0, start_ts, src, dst, spi), _esp_record(1, end_ts, src, dst, spi))
    return Flow(key=key, packets=packets, start_ts=start_ts, end_ts=end_ts)


def _encapsulated_flow(src: str, dst: str, spi: int, start_ts: float, end_ts: float) -> Flow:
    """The same flow, but carried inside UDP/4500 as a real NAT-T tunnel is."""
    key = FlowKey(src=src, dst=dst, spi=spi, proto="esp")
    packets = tuple(
        record._replace(udp_encapsulated=True)
        for record in (
            _esp_record(0, start_ts, src, dst, spi),
            _esp_record(1, end_ts, src, dst, spi),
        )
    )
    return Flow(key=key, packets=packets, start_ts=start_ts, end_ts=end_ts)


def _negotiation(
    *,
    ike_version: IkeVersion = IkeVersion.IKEV2,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    ts: float = 0.0,
    encryption_alg: EncryptionAlg | None = EncryptionAlg.AES_GCM_16,
    encryption_keylen: int | None = 256,
    integrity_alg: IntegrityAlg | None = IntegrityAlg.NONE,
    dh_group: int | None = 19,
    exchange_mode: IkeExchangeMode | None = None,
    lifetime_s: int | None = None,
    auth_method: AuthMethod | None = None,
    esn: bool | None = None,
    nat_detected: bool = False,
) -> IkeNegotiation:
    return IkeNegotiation(
        ike_version=ike_version,
        exchange_mode=exchange_mode,
        init_spi="1111111111111111",
        resp_spi="2222222222222222",
        src=src,
        dst=dst,
        ts=ts,
        request_frame=1,
        response_frame=2,
        proposed=(),
        selected=Proposal(number=1, protocol_id=1, transforms=(Transform(1, 12),)),
        downgrade_available=False,
        dh_group=dh_group,
        prf_alg=None,
        encryption_alg=encryption_alg,
        encryption_keylen=encryption_keylen,
        integrity_alg=integrity_alg,
        lifetime_s=lifetime_s,
        auth_method=auth_method,
        esn=esn,
        nat_detected=nat_detected,
    )


# ===========================================================================
# Step 4.6: correlation
# ===========================================================================


def test_correlates_by_endpoints_and_timing() -> None:
    negotiation = _negotiation(ts=10.0)
    flow = _flow("10.0.0.1", "10.0.0.2", spi=1, start_ts=15.0, end_ts=20.0)

    assert correlate_negotiation(flow, [negotiation]) is negotiation


def test_no_match_when_endpoints_differ() -> None:
    negotiation = _negotiation(src="10.0.0.1", dst="10.0.0.2", ts=10.0)
    flow = _flow("10.0.0.5", "10.0.0.6", spi=1, start_ts=15.0, end_ts=20.0)

    assert correlate_negotiation(flow, [negotiation]) is None


def test_no_match_when_negotiation_is_after_the_flow() -> None:
    negotiation = _negotiation(ts=100.0)
    flow = _flow("10.0.0.1", "10.0.0.2", spi=1, start_ts=15.0, end_ts=20.0)

    assert correlate_negotiation(flow, [negotiation]) is None


def test_no_match_outside_the_correlation_window() -> None:
    negotiation = _negotiation(ts=0.0)
    flow = _flow("10.0.0.1", "10.0.0.2", spi=1, start_ts=CORRELATION_WINDOW_S + 1.0, end_ts=100.0)

    assert correlate_negotiation(flow, [negotiation]) is None


def test_most_recent_negotiation_wins_on_rekey() -> None:
    older = _negotiation(ts=0.0)
    newer = _negotiation(ts=5.0)
    flow = _flow("10.0.0.1", "10.0.0.2", spi=1, start_ts=10.0, end_ts=20.0)

    assert correlate_negotiation(flow, [older, newer]) is newer


def test_endpoints_match_regardless_of_direction() -> None:
    """The negotiation runs over UDP 500 initiator->responder; the Child SA
    this creates may flow in either direction first."""
    negotiation = _negotiation(src="10.0.0.1", dst="10.0.0.2", ts=0.0)
    flow = _flow("10.0.0.2", "10.0.0.1", spi=1, start_ts=5.0, end_ts=10.0)

    assert correlate_negotiation(flow, [negotiation]) is negotiation


# ===========================================================================
# Step 4.8: assembly
# ===========================================================================


def _paired(spi_fwd: int = 1, spi_rev: int = 2) -> SAPair:
    forward = _flow("10.0.0.1", "10.0.0.2", spi_fwd, 10.0, 12.0)
    reverse = _flow("10.0.0.2", "10.0.0.1", spi_rev, 10.5, 12.5)
    return SAPair(forward=forward, reverse=reverse, paired=True)


def test_assembly_with_ikev2_negotiation() -> None:
    negotiation = _negotiation(
        ike_version=IkeVersion.IKEV2,
        encryption_alg=EncryptionAlg.AES_GCM_16,
        encryption_keylen=256,
        integrity_alg=IntegrityAlg.NONE,
        dh_group=19,
    )

    sa = assemble_security_association(_paired(), negotiation)

    assert sa.spi_initiator == "00000001"
    assert sa.spi_responder == "00000002"
    assert sa.ike_version.provenance is Provenance.OBSERVED
    assert sa.ike_version.value is IkeVersion.IKEV2

    # Child SA crypto: same-family INFERRED, never OBSERVED (LLD section 6.4).
    assert sa.encryption_alg.provenance is Provenance.INFERRED
    assert sa.encryption_alg.value is EncryptionAlg.AES_GCM_16
    assert sa.encryption_alg.confidence is not None
    assert sa.encryption_keylen.provenance is Provenance.INFERRED
    assert sa.encryption_keylen.value == 256
    assert sa.integrity_alg.provenance is Provenance.INFERRED

    # The IKE SA's own DH group genuinely is observed.
    assert sa.dh_group.provenance is Provenance.OBSERVED
    assert sa.dh_group.value == 19

    # IKEv2-only unavailability, per LLD section 6.4.
    assert sa.ike_exchange_mode.provenance is Provenance.UNAVAILABLE
    assert sa.negotiated_lifetime_s.provenance is Provenance.UNAVAILABLE
    assert sa.auth_method.provenance is Provenance.UNAVAILABLE

    # Track B's job, not yet built.
    assert sa.operating_mode.provenance is Provenance.UNAVAILABLE
    assert sa.pfs_enabled.provenance is Provenance.UNAVAILABLE
    assert sa.observed_rekey_s.provenance is Provenance.UNAVAILABLE
    assert sa.replay_sane.provenance is Provenance.UNAVAILABLE


def test_assembly_with_ikev1_negotiation() -> None:
    negotiation = _negotiation(
        ike_version=IkeVersion.IKEV1,
        exchange_mode=IkeExchangeMode.AGGRESSIVE,
        lifetime_s=3600,
        auth_method=AuthMethod.PSK,
        encryption_alg=EncryptionAlg.TRIPLE_DES_CBC,
        encryption_keylen=168,
        integrity_alg=IntegrityAlg.HMAC_SHA1_96,
        dh_group=2,
    )

    sa = assemble_security_association(_paired(), negotiation)

    assert sa.ike_exchange_mode.provenance is Provenance.OBSERVED
    assert sa.ike_exchange_mode.value is IkeExchangeMode.AGGRESSIVE
    assert sa.negotiated_lifetime_s.provenance is Provenance.OBSERVED
    assert sa.negotiated_lifetime_s.value == 3600
    assert sa.auth_method.provenance is Provenance.OBSERVED
    assert sa.auth_method.value is AuthMethod.PSK
    # IKEv1 has no separate PRF negotiation.
    assert sa.prf_alg.provenance is Provenance.UNAVAILABLE


def test_assembly_with_no_correlated_negotiation() -> None:
    sa = assemble_security_association(_paired(), None)

    for field in (
        "ike_version",
        "ike_exchange_mode",
        "encryption_alg",
        "encryption_keylen",
        "integrity_alg",
        "prf_alg",
        "dh_group",
        "auth_method",
        "negotiated_lifetime_s",
        "esn_negotiated",
    ):
        attribute = getattr(sa, field)
        assert attribute.provenance is Provenance.UNAVAILABLE, field
        assert attribute.note


def test_nat_traversal_is_answerable_without_any_ike() -> None:
    """``nat_traversal`` is deliberately not in the list above.

    Every other field there needs the IKE negotiation that an ESP-only capture
    does not have. Encapsulation is a property of the ESP packets themselves,
    so this one stays answerable -- and answering it "unavailable" alongside
    the rest would be giving up on something plainly visible.
    """
    sa = assemble_security_association(_paired(), None)

    assert sa.nat_traversal.provenance is Provenance.OBSERVED
    assert sa.nat_traversal.value is False


def test_assembly_unpaired_flow_has_no_spi_responder() -> None:
    forward = _flow("10.0.0.1", "10.0.0.2", spi=7, start_ts=0.0, end_ts=1.0)
    pair = SAPair(forward=forward, reverse=None, paired=False)

    sa = assemble_security_association(pair, None)

    assert sa.spi_responder is None
    assert sa.spi_initiator == "00000007"


def test_nat_discovery_payloads_alone_do_not_report_nat_traversal() -> None:
    """The bug this pins cost two OBSERVED falsehoods in the pilot batch.

    RFC 7296 requires NAT_DETECTION_* notifies in *every* IKE_SA_INIT, so
    reading their presence as NAT traversal reported ``true`` for both
    reference tunnels -- on a flat /24 with no NAT in it. The discovery having
    run is worth a note; it is not the answer.
    """
    negotiation = _negotiation(nat_detected=True)

    sa = assemble_security_association(_paired(), negotiation)

    assert sa.nat_traversal.provenance is Provenance.OBSERVED
    assert sa.nat_traversal.value is False
    assert sa.nat_traversal.note is not None
    assert "no NAT was found" in sa.nat_traversal.note


def test_udp_4500_encapsulation_reports_nat_traversal() -> None:
    forward = _encapsulated_flow("10.0.0.1", "10.0.0.2", spi=1, start_ts=10.0, end_ts=12.0)
    reverse = _encapsulated_flow("10.0.0.2", "10.0.0.1", spi=2, start_ts=10.5, end_ts=12.5)
    pair = SAPair(forward=forward, reverse=reverse, paired=True)

    sa = assemble_security_association(pair, _negotiation(nat_detected=True))

    assert sa.nat_traversal.provenance is Provenance.OBSERVED
    assert sa.nat_traversal.value is True


def test_assembly_unmapped_encryption_alg_is_unavailable_not_a_guess() -> None:
    negotiation = _negotiation(encryption_alg=EncryptionAlg.UNKNOWN, encryption_keylen=None)

    sa = assemble_security_association(_paired(), negotiation)

    assert sa.encryption_alg.provenance is Provenance.UNAVAILABLE


# ===========================================================================
# End to end: run_track_a
# ===========================================================================


def test_run_track_a_end_to_end(tmp_path: Path) -> None:
    pcap = tmp_path / "cap.pcap"
    # write_pcap timestamps each frame by its position in this list (whole
    # seconds), so the IKE exchange is placed first -- the ESP flow that
    # follows must start after the negotiation completes for step 4.6's
    # endpoint-and-timing correlation to find it.
    frames = [
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp_packet(500, 500, b"x" * 28))),
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, 1))),
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, 2))),
    ]
    write_pcap(pcap, DLT_EN10MB, frames)
    ingest_result = read_packets(pcap)
    sa_pairs = assemble_flows(ingest_result.packets)
    assert len(sa_pairs) == 1

    transforms = [
        transform(transform_type=1, transform_id=12, attrs=[attr(14, 128)]),
        transform(transform_type=4, transform_id=14),
    ]
    sa = sa_payload([proposal(number=1, protocol_id=1, transforms=transforms)])
    tshark_json = [
        packet(
            frame_number=1,
            ts=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            isakmp=isakmp_header(version="2.0", exchange_type=IKE_SA_INIT, init_spi="beef", sa=sa),
        ),
        packet(
            frame_number=2,
            ts=0.05,
            src="10.0.0.2",
            dst="10.0.0.1",
            isakmp=isakmp_header(
                version="2.0", exchange_type=IKE_SA_INIT, init_spi="beef", resp_spi="cafe", sa=sa
            ),
        ),
    ]
    fake_tshark = write_fake_tshark(tmp_path / "tshark", tshark_json)

    (result,) = run_track_a(pcap, sa_pairs, tshark_bin=str(fake_tshark))

    assert result.ike_version.value is IkeVersion.IKEV2
    assert result.dh_group.value == 14
    assert result.encryption_alg.provenance is Provenance.INFERRED
    assert result.encryption_alg.value is EncryptionAlg.AES_CBC


def test_build_negotiations_and_run_tshark_are_reachable_from_parse() -> None:
    """Smoke test: the module's public surface composes without a circular
    dependency."""
    assert parse_isakmp_json([]) == []
    assert build_negotiations([]) == []
