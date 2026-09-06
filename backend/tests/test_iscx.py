"""Step 8.5: the ISCXVPN2016 adapter.

**Done when:** external captures produce feature vectors with the same schema as
testbed captures. That is the assertion in
``test_external_schema_matches_testbed_schema``, and it is checked as set
equality on the column names rather than on a count, because a matrix that has
the right *number* of columns and the wrong names trains a model that scores
well and means nothing.

Everything here runs on synthetic captures shaped like ISCXVPN2016's -- plain
IP traffic, no ESP anywhere, labelled by filename. The real corpus needs a
registration form and several gigabytes; the adapter's contract does not.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from analyzer.core.enums import TrafficClass
from analyzer.dataset import iscx
from analyzer.ingest.flow import assemble_flows
from analyzer.ingest.reader import read_packets
from analyzer.track_b import features
from tests._pcap import (
    DLT_EN10MB,
    esp_payload,
    eth_frame,
    ipv4_packet,
    udp_packet,
    write_pcap,
)

IP_PROTO_ESP = 50
IP_PROTO_UDP = 17


def _external_capture(path: Path, *, count: int = 40) -> Path:
    """A capture shaped like ISCXVPN2016's: plain UDP, no ESP, both directions."""
    frames = []
    for i in range(count):
        frames.append(
            eth_frame(
                ipv4_packet(
                    "192.168.1.10",
                    "10.20.30.40",
                    IP_PROTO_UDP,
                    udp_packet(51820, 443, b"A" * (40 + (i % 7) * 24)),
                )
            )
        )
        frames.append(
            eth_frame(
                ipv4_packet(
                    "10.20.30.40",
                    "192.168.1.10",
                    IP_PROTO_UDP,
                    udp_packet(443, 51820, b"B" * (60 + (i % 5) * 32)),
                )
            )
        )
    write_pcap(path, DLT_EN10MB, frames)
    return path


def _testbed_capture(path: Path, *, count: int = 40) -> Path:
    """A capture shaped like ours: real ESP, both directions."""
    frames = []
    for i in range(1, count + 1):
        frames.append(
            eth_frame(
                ipv4_packet("10.0.0.1", "10.0.0.2", IP_PROTO_ESP, esp_payload(1, i, b"X" * 48))
            )
        )
        frames.append(
            eth_frame(
                ipv4_packet("10.0.0.2", "10.0.0.1", IP_PROTO_ESP, esp_payload(2, i, b"Y" * 64))
            )
        )
    write_pcap(path, DLT_EN10MB, frames)
    return path


# --- the Done-when ---------------------------------------------------------


def test_external_schema_matches_testbed_schema(tmp_path: Path) -> None:
    """Step 8.5's Done-when, stated exactly.

    Set equality on names, not a length comparison: a matrix with the right
    number of columns and the wrong names is worse than one that fails loudly.
    """
    external = iscx.adapt_capture(_external_capture(tmp_path / "vpn_youtube.pcap"))
    testbed_pairs = assemble_flows(
        read_packets(_testbed_capture(tmp_path / "session.pcap")).packets
    )

    assert external, "the adapter produced no flows at all"
    assert testbed_pairs

    assert set(external[0].vector) == set(features.extract(testbed_pairs[0]))


def test_external_vectors_carry_no_nans_and_no_infinities(tmp_path: Path) -> None:
    """The same guarantee ``features`` gives internal captures. A NaN entering
    here surfaces much later as a model that refuses half its inputs."""
    import math

    for flow in iscx.adapt_capture(_external_capture(tmp_path / "vpn_voipbuzz.pcap")):
        for name, value in flow.vector.items():
            assert math.isfinite(value), f"{name} is {value}"


# --- labelling -------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("vpn_youtube.pcap", TrafficClass.VIDEO),
        ("netflix2.pcap", TrafficClass.VIDEO),
        ("vpn_voipbuzz.pcap", TrafficClass.VOIP),
        ("skype_audio1a.pcap", TrafficClass.VOIP),
        ("skype_video2b.pcap", TrafficClass.VIDEO),
        ("email1a.pcap", TrafficClass.EMAIL),
        ("vpn_email2b.pcap", TrafficClass.EMAIL),
        ("facebook_chat4a.pcap", TrafficClass.MESSAGING),
        ("skype_file1.pcap", TrafficClass.FILE_TRANSFER),
        ("torrent01.pcap", TrafficClass.FILE_TRANSFER),
        ("vpn_ftps_A.pcap", TrafficClass.FILE_TRANSFER),
        ("browsing_two.pcap", TrafficClass.WEB),
    ],
)
def test_filename_labels(filename: str, expected: TrafficClass) -> None:
    assert iscx.label_for(filename) is expected


def test_skype_file_is_transfer_not_voip() -> None:
    """Pattern order is load-bearing. ``skype_file`` must not fall through to
    the VoIP rule that also matches ``skype``, or the file-transfer class picks
    up mislabelled VoIP and the confusion matrix hides it as a model failure."""
    assert iscx.label_for("skype_file1.pcap") is TrafficClass.FILE_TRANSFER
    assert iscx.label_for("skype_audio1a.pcap") is TrafficClass.VOIP


def test_unmappable_names_return_none_rather_than_a_guess() -> None:
    """ISCXVPN2016 carries applications with no home in PRD section 9.2's seven
    classes. Forcing them into the nearest bucket injects label noise into the
    one evaluation that exists to be trusted."""
    for name in ("tor_p2p.pcap", "capture_003.pcap", "unknown.pcap"):
        assert iscx.label_for(name) is None


def test_vpn_prefix_is_recognised() -> None:
    assert iscx.is_tunnelled("vpn_youtube.pcap") is True
    assert iscx.is_tunnelled("youtube.pcap") is False


# --- the substitutions, and their limits -----------------------------------


def test_ip_payload_length_substitutes_for_esp_payload_length(tmp_path: Path) -> None:
    """Without the substitution every external vector would be all-zero
    geometry, which reads as a perfectly padded tunnel rather than an
    unmeasured one -- a silent wrong answer of exactly the kind this project
    exists to avoid."""
    flows = iscx.adapt_capture(_external_capture(tmp_path / "vpn_browsing.pcap"))

    assert flows[0].vector["esp_len_mean"] > 0.0
    assert flows[0].vector["byte_count"] > 0.0


def test_geometry_features_are_declared_not_comparable() -> None:
    """The congruence and modality features measure ESP padding, which these
    captures do not have. Step 9.12 must not score on them."""
    assert "esp_len_mod16_0" in iscx.NOT_COMPARABLE
    assert "esp_len_modal" in iscx.NOT_COMPARABLE
    # The size *statistics* stay: payload size distribution is a real property
    # of the application in both corpora.
    assert "esp_len_mean" not in iscx.NOT_COMPARABLE
    assert "iat_mean" not in iscx.NOT_COMPARABLE


def test_comparable_names_drop_exactly_the_geometry_features(tmp_path: Path) -> None:
    flows = iscx.adapt_capture(_external_capture(tmp_path / "vpn_youtube.pcap"))
    names = set(flows[0].vector)

    comparable = iscx.comparable_feature_names(names)

    assert set(comparable) == names - iscx.NOT_COMPARABLE
    assert comparable == sorted(comparable), "column order must be stable"


def test_synthetic_spi_is_stable_across_calls() -> None:
    """``hash()`` is salted per process. A row identity that changed between
    runs would make a feature matrix impossible to trace back to its capture."""
    first = iscx._synthetic_spi("10.0.0.1", "10.0.0.2")
    assert first == iscx._synthetic_spi("10.0.0.1", "10.0.0.2")
    assert first != iscx._synthetic_spi("10.0.0.2", "10.0.0.1")
    assert 0 <= first <= 0xFFFFFFFF


def test_flows_pair_both_directions(tmp_path: Path) -> None:
    pairs = iscx.to_sa_pairs(read_packets(_external_capture(tmp_path / "vpn_youtube.pcap")).packets)

    assert len(pairs) == 1
    assert pairs[0].paired is True
    assert pairs[0].reverse is not None


def test_short_flows_are_dropped(tmp_path: Path) -> None:
    """Background chatter would otherwise enter the matrix as hundreds of
    two-packet rows whose timing statistics are pure noise."""
    path = tmp_path / "vpn_youtube.pcap"
    write_pcap(
        path,
        DLT_EN10MB,
        [
            eth_frame(
                ipv4_packet("1.1.1.1", "2.2.2.2", IP_PROTO_UDP, udp_packet(53, 53, b"Q" * 30))
            )
            for _ in range(3)
        ],
    )

    assert iscx.to_sa_pairs(read_packets(path).packets) == []


# --- batch reporting -------------------------------------------------------


def test_directory_adaptation_reports_its_gaps(tmp_path: Path) -> None:
    """A batch that silently dropped what it could not handle would overstate
    its own coverage, and the coverage is the point of an external set."""
    _external_capture(tmp_path / "vpn_youtube.pcap")
    _external_capture(tmp_path / "tor_p2p.pcap")
    (tmp_path / "broken.pcap").write_bytes(b"not a pcap at all")
    write_pcap(tmp_path / "vpn_email1a.pcap", DLT_EN10MB, [])

    batch = iscx.adapt_directory(tmp_path)

    assert [p.name for p in batch.unmapped] == ["tor_p2p.pcap"]
    assert [p.name for p, _ in batch.unreadable] == ["broken.pcap"]
    assert batch.unreadable[0][1], "the reason must be carried, not just the path"
    assert [p.name for p in batch.empty] == ["vpn_email1a.pcap"]
    assert {f.label for f in batch.labelled} == {TrafficClass.VIDEO}
    # The unmapped file's flows are still carried, just unlabelled -- they are
    # usable for unsupervised checks and their absence would be unexplained.
    assert any(f.label is None for f in batch.flows)


def test_tunnelled_flag_survives_into_the_batch(tmp_path: Path) -> None:
    """A classifier trained on IPsec should do better on the OpenVPN half than
    on the plaintext half. If it does not, that is a finding."""
    _external_capture(tmp_path / "vpn_youtube.pcap")
    _external_capture(tmp_path / "youtube.pcap")

    batch = iscx.adapt_directory(tmp_path)

    assert {f.tunnelled for f in batch.flows} == {True, False}


def test_adaptation_is_deterministic(tmp_path: Path) -> None:
    """NFR-4 reaches here too: the same capture must give the same matrix."""
    path = _external_capture(tmp_path / "vpn_youtube.pcap")

    assert [f.vector for f in iscx.adapt_capture(path)] == [
        f.vector for f in iscx.adapt_capture(path)
    ]
