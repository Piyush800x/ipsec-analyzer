"""Step 11.1: the degradation suite.

Five degraded inputs. Each must yield UNAVAILABLE with a reason, never a
confident wrong answer.

The implementation plan says of this step: "Do not skip this step. It is the
one most likely to be dropped under time pressure and the one most likely to
save the demo." It is the executable form of the product's central claim -- a
tool that says "I cannot tell you that, and here is why" is worth more than one
that guesses -- so every assertion here checks two things: that the value is
absent, *and* that the reason is present. An UNAVAILABLE with an empty note
would pass a weaker test and fail a real analyst.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from analyzer.assess.engine import AssessmentEngine
from analyzer.assess.policy import load_policy
from analyzer.core.enums import Provenance
from analyzer.core.ids import new_id
from analyzer.core.schema import Assessment, SecurityAssociation
from analyzer.ingest.flow import assemble_flows
from analyzer.ingest.quality import compute_quality
from analyzer.ingest.reader import read_packets
from analyzer.track_a.correlate import assemble_security_association, correlate_negotiation
from analyzer.track_a.ike_parser import build_negotiations, parse_isakmp_json
from analyzer.track_b.service import InferenceService
from tests._pcap import (
    DLT_EN10MB,
    esp_payload,
    eth_frame,
    ipv4_packet,
    isakmp_header,
    udp_packet,
    write_pcap,
)
from tests._tshark_json import attr, packet, proposal, sa_payload, transform
from tests._tshark_json import isakmp_header as tshark_isakmp

BASELINE = Path(__file__).resolve().parents[1] / "src/analyzer/assess/policies/baseline.yaml"
IKE_SA_INIT = 34

# Attributes that must never be asserted from a degraded capture.
NEVER_GUESSED = (
    "encryption_alg",
    "encryption_keylen",
    "integrity_alg",
    "dh_group",
    "auth_method",
    "negotiated_lifetime_s",
    "operating_mode",
)


def _analyse(pcap: Path, tshark_json: list[dict] | None = None) -> list[SecurityAssociation]:
    """Run ingest -> Track A -> Track B without a tshark binary."""
    result = read_packets(pcap)
    pairs = assemble_flows(result.packets)
    quality = compute_quality(result, pairs)
    negotiations = build_negotiations(parse_isakmp_json(tshark_json or []))

    service = InferenceService()
    out = []
    for pair in pairs:
        sa = assemble_security_association(pair, correlate_negotiation(pair.forward, negotiations))
        out.append(service.apply(sa, service.analyse(pair, quality, dh_group=sa.dh_group.value)))
    return out


def _assert_no_confident_guesses(sas: list[SecurityAssociation]) -> None:
    """No attribute may be OBSERVED, and every gap must explain itself."""
    for sa in sas:
        for name in NEVER_GUESSED:
            attribute = getattr(sa, name)
            if attribute.provenance is Provenance.UNAVAILABLE:
                assert (attribute.note or "").strip(), f"{name} is unavailable with no reason"
            else:
                assert attribute.provenance is Provenance.INFERRED, (
                    f"{name} was reported as OBSERVED from a degraded capture"
                )
                assert attribute.confidence is not None


# --- 1. ESP only: no IKE anywhere in the capture ---------------------------


def test_esp_only_capture(tmp_path: Path) -> None:
    """The commonest real degradation: an analyst captured mid-session.

    FR-4.9 lives here -- AES-128 and AES-256 are indistinguishable from ESP
    alone, so the key length must come back unavailable rather than assumed.
    """
    pcap = tmp_path / "esp-only.pcap"
    frames = [
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, i, b"X" * 48)))
        for i in range(1, 40)
    ] + [
        eth_frame(ipv4_packet("10.0.0.2", "10.0.0.1", 50, esp_payload(2, i, b"Y" * 48)))
        for i in range(1, 40)
    ]
    write_pcap(pcap, DLT_EN10MB, frames)

    sas = _analyse(pcap)

    assert sas
    _assert_no_confident_guesses(sas)
    keylen = sas[0].encryption_keylen
    assert keylen.provenance is Provenance.UNAVAILABLE
    assert keylen.value is None
    assert keylen.note


def test_esp_only_capture_still_produces_an_assessment(tmp_path: Path) -> None:
    """Degraded input must not fail the pipeline -- a partial answer with
    honest gaps is the product, not an error state."""
    pcap = tmp_path / "esp-only.pcap"
    write_pcap(
        pcap,
        DLT_EN10MB,
        [
            eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, i, b"X" * 48)))
            for i in range(1, 30)
        ],
    )
    result = read_packets(pcap)
    pairs = assemble_flows(result.packets)
    quality = compute_quality(result, pairs)

    engine = AssessmentEngine(load_policy(BASELINE))
    assessment = engine.evaluate(
        _analyse(pcap),
        quality,
        assessment_id=new_id(),
        capture_id=new_id(),
        generated_at=__import__("datetime").datetime.now(tz=__import__("datetime").UTC),
        engine_version="test",
    )

    assert isinstance(assessment, Assessment)
    assert assessment.score.total == 100, "nothing was proven wrong, so nothing is deducted"


# --- 2. Truncated: snaplen cut the packets short ---------------------------


def test_truncated_capture(tmp_path: Path) -> None:
    """A snaplen-limited capture destroys packet geometry, so the cipher
    sieve must refuse rather than sieve on the snaplen."""
    pcap = tmp_path / "truncated.pcap"
    frames = [
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, i, b"X" * (48 + i))))
        for i in range(1, 60)
    ]
    write_pcap(pcap, DLT_EN10MB, frames, snaplen=96)

    result = read_packets(pcap)
    pairs = assemble_flows(result.packets)
    quality = compute_quality(result, pairs)

    assert quality.truncated is True
    assert quality.sufficient_for_lattice is False

    sas = _analyse(pcap)
    _assert_no_confident_guesses(sas)
    assert sas[0].encryption_alg.provenance is Provenance.UNAVAILABLE


# --- 3. Single-length: constant-bitrate traffic ----------------------------


def test_single_length_capture(tmp_path: Path) -> None:
    """The VoIP case, and the one guaranteed to appear in the PRD section 16
    demo. One distinct length satisfies almost every congruence, so a sieve
    that answers here is answering arbitrarily."""
    pcap = tmp_path / "voip-like.pcap"
    frames = [
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, i, b"X" * 160)))
        for i in range(1, 300)
    ]
    write_pcap(pcap, DLT_EN10MB, frames)

    result = read_packets(pcap)
    pairs = assemble_flows(result.packets)
    quality = compute_quality(result, pairs)

    assert quality.sufficient_for_lattice is False, "one distinct length is not diversity"

    sas = _analyse(pcap)
    cipher = sas[0].encryption_alg
    assert cipher.provenance is Provenance.UNAVAILABLE
    assert "length diversity" in (cipher.note or "") or "no IKE negotiation" in (cipher.note or "")


# --- 4. One-directional: only one side of the conversation -----------------


def test_one_directional_capture(tmp_path: Path) -> None:
    """A legitimate analyst situation (LLD section 5), not an error: a span
    port that only mirrors one direction."""
    pcap = tmp_path / "one-way.pcap"
    write_pcap(
        pcap,
        DLT_EN10MB,
        [
            eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, i, b"X" * 48)))
            for i in range(1, 40)
        ],
    )

    result = read_packets(pcap)
    pairs = assemble_flows(result.packets)

    assert len(pairs) == 1
    assert pairs[0].paired is False
    assert pairs[0].reverse is None

    sas = _analyse(pcap)
    assert sas[0].spi_responder is None
    _assert_no_confident_guesses(sas)


# --- 5. IKE mid-stream: the negotiation was already over -------------------


def test_ike_joined_mid_stream(tmp_path: Path) -> None:
    """IKE packets are present but IKE_SA_INIT was never captured, so there is
    no cleartext transform negotiation to read. `has_ike` is true and
    `ike_complete` is false, and Track A must not treat the former as the
    latter."""
    pcap = tmp_path / "mid-stream.pcap"
    frames = [
        # Message ID 7: an exchange well after the negotiation completed.
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp_packet(500, 500, isakmp_header(7))))
    ] + [
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, i, b"X" * 48)))
        for i in range(1, 40)
    ]
    write_pcap(pcap, DLT_EN10MB, frames)

    result = read_packets(pcap)
    pairs = assemble_flows(result.packets)
    quality = compute_quality(result, pairs)

    assert quality.has_ike is True
    assert quality.ike_complete is False, "message ID 7 is not an IKE_SA_INIT"
    assert any("mid-stream" in warning for warning in quality.warnings)

    sas = _analyse(pcap)
    _assert_no_confident_guesses(sas)


# --- the inverse: a good capture is not degraded ---------------------------


def test_a_complete_capture_does_report_what_it_observed(tmp_path: Path) -> None:
    """The suite would pass trivially if the parser reported UNAVAILABLE for
    everything always. This is the control: given a real negotiation, Track A
    must actually observe something."""
    pcap = tmp_path / "complete.pcap"
    frames = [
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp_packet(500, 500, isakmp_header(0))))
    ] + [
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, i, b"X" * 48)))
        for i in range(1, 20)
    ]
    write_pcap(pcap, DLT_EN10MB, frames)

    sa_json = sa_payload(
        [
            proposal(
                number=1,
                protocol_id=1,
                transforms=[
                    transform(transform_type=1, transform_id=12, attrs=[attr(14, 256)]),
                    transform(transform_type=4, transform_id=14),
                ],
            )
        ]
    )
    tshark_json = [
        packet(
            frame_number=1,
            ts=0.0,
            src="10.0.0.1",
            dst="10.0.0.2",
            isakmp=tshark_isakmp(
                version="2.0", exchange_type=IKE_SA_INIT, init_spi="aa", sa=sa_json
            ),
        ),
        packet(
            frame_number=2,
            ts=0.1,
            src="10.0.0.2",
            dst="10.0.0.1",
            isakmp=tshark_isakmp(
                version="2.0", exchange_type=IKE_SA_INIT, init_spi="aa", resp_spi="bb", sa=sa_json
            ),
        ),
    ]

    sas = _analyse(pcap, tshark_json)

    assert sas[0].ike_version.provenance is Provenance.OBSERVED
    assert sas[0].dh_group.provenance is Provenance.OBSERVED
    assert sas[0].dh_group.value == 14


@pytest.mark.parametrize(
    "field", ["operating_mode", "pfs_enabled", "observed_rekey_s", "esn_negotiated"]
)
def test_fields_needing_absent_capability_always_explain_themselves(
    tmp_path: Path, field: str
) -> None:
    """Whatever the input, a field this build cannot determine says why."""
    pcap = tmp_path / "any.pcap"
    write_pcap(
        pcap,
        DLT_EN10MB,
        [
            eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, i, b"X" * 48)))
            for i in range(1, 30)
        ],
    )

    attribute = getattr(_analyse(pcap)[0], field)

    if attribute.provenance is Provenance.UNAVAILABLE:
        assert (attribute.note or "").strip()
        assert attribute.value is None
