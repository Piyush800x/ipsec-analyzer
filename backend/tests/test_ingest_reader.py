"""Steps 3.1-3.4: PacketRecord/FlowKey, the pcap reader, NAT-T, and IPv6.

No Docker is available for every environment this suite runs in, so these
build synthetic classic-pcap files byte-for-byte (see ``tests/_pcap.py``)
rather than depending on a real testbed capture. That covers the reader's
decoding logic; it does not substitute for step 3.2's actual Done-when
condition (packet count against ``tshark -r file | wc -l`` on a Phase 2
capture), which needs a real capture and is recorded as not verified in
CHANGELOG.md until one is available in CI.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from analyzer.ingest.reader import FlowKey, IngestError, PacketRecord, read_packets
from tests._pcap import (
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    DLT_RAW,
    ah_payload,
    esp_payload,
    eth_frame,
    ipv4_packet,
    ipv6_packet,
    isakmp_header,
    sll2_frame,
    sll_frame,
    udp_packet,
    write_pcap,
)


def test_packet_record_and_flow_key_are_typed() -> None:
    """Step 3.1: both types exist with the exact fields LLD section 5 gives."""
    record = PacketRecord(
        index=0,
        ts=1.0,
        ip_version=4,
        src="10.0.0.1",
        dst="10.0.0.2",
        proto="esp",
        spi=1,
        seq=1,
        ip_payload_len=40,
        esp_payload_len=32,
        captured_len=60,
        orig_len=60,
    )
    assert record.proto == "esp"
    key = FlowKey(src="10.0.0.1", dst="10.0.0.2", spi=1, proto="esp")
    assert key.spi == 1


def test_reader_yields_one_record_per_frame(tmp_path: Path) -> None:
    """Step 3.2 Done-when, in spirit: every frame in the file, classified or
    not, produces exactly one PacketRecord -- the invariant that makes the
    reader's count comparable to ``tshark -r file | wc -l``."""
    frames = [
        eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, 1))),
        eth_frame(ipv4_packet("10.0.0.2", "10.0.0.1", 50, esp_payload(2, 1))),
        eth_frame(b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x06" + b"not-ip", ethertype=0x0806),
    ]
    path = tmp_path / "cap.pcap"
    write_pcap(path, DLT_EN10MB, frames)

    result = read_packets(path)

    assert len(result.packets) == len(frames)
    assert [p.index for p in result.packets] == [0, 1, 2]
    assert result.packets[2].proto == "other"


def test_raw_esp_over_ipv4(tmp_path: Path) -> None:
    path = tmp_path / "cap.pcap"
    inner = ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(7, 42, b"X" * 24))
    write_pcap(path, DLT_EN10MB, [eth_frame(inner)])

    (record,) = read_packets(path).packets

    assert record.proto == "esp"
    assert record.ip_version == 4
    assert record.spi == 7
    assert record.seq == 42
    assert record.esp_payload_len == 24


def test_raw_ah_over_ipv4(tmp_path: Path) -> None:
    path = tmp_path / "cap.pcap"
    inner = ipv4_packet("10.0.0.1", "10.0.0.2", 51, ah_payload(6, 9, 3))
    write_pcap(path, DLT_EN10MB, [eth_frame(inner)])

    (record,) = read_packets(path).packets

    assert record.proto == "ah"
    assert record.spi == 9
    assert record.seq == 3
    assert record.esp_payload_len is None


def test_udp_500_is_always_isakmp(tmp_path: Path) -> None:
    path = tmp_path / "cap.pcap"
    inner = ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp_packet(500, 500, isakmp_header(0)))
    write_pcap(path, DLT_EN10MB, [eth_frame(inner)])

    (record,) = read_packets(path).packets

    assert record.proto == "isakmp"
    assert record.spi is None


def test_natt_zero_marker_is_isakmp_not_esp(tmp_path: Path) -> None:
    """Step 3.3: first four UDP/4500 bytes all zero -> IKE, not an ESP SPI."""
    path = tmp_path / "cap.pcap"
    payload = b"\x00\x00\x00\x00" + isakmp_header(3)
    inner = ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp_packet(4500, 4500, payload))
    write_pcap(path, DLT_EN10MB, [eth_frame(inner)])

    (record,) = read_packets(path).packets

    assert record.proto == "isakmp_natt"
    assert record.spi is None


def test_natt_nonzero_marker_is_esp(tmp_path: Path) -> None:
    """Step 3.3: anything else in those four bytes is an ESP SPI."""
    path = tmp_path / "cap.pcap"
    payload = esp_payload(99, 5, b"Y" * 16)
    inner = ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp_packet(4500, 4500, payload))
    write_pcap(path, DLT_EN10MB, [eth_frame(inner)])

    (record,) = read_packets(path).packets

    assert record.proto == "esp"
    assert record.spi == 99
    assert record.seq == 5
    assert record.esp_payload_len == 16


def test_natt_keepalive_too_short_is_neither(tmp_path: Path) -> None:
    """A one-byte NAT-T keepalive is neither a marker nor a full ESP header."""
    path = tmp_path / "cap.pcap"
    inner = ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp_packet(4500, 4500, b"\xff"))
    write_pcap(path, DLT_EN10MB, [eth_frame(inner)])

    (record,) = read_packets(path).packets

    assert record.proto == "other"


def test_ipv6_esp_via_extension_header(tmp_path: Path) -> None:
    """Step 3.4: walk the IPv6 extension header chain to find ESP."""
    path = tmp_path / "cap.pcap"
    inner = ipv6_packet("2001:db8::1", "2001:db8::2", 50, esp_payload(11, 1, b"Z" * 20))
    write_pcap(path, DLT_EN10MB, [eth_frame(inner, ethertype=0x86DD)])

    (record,) = read_packets(path).packets

    assert record.ip_version == 6
    assert record.proto == "esp"
    assert record.spi == 11
    assert record.esp_payload_len == 20
    assert record.src == "2001:db8::1"


def test_ipv6_ah_via_extension_header(tmp_path: Path) -> None:
    path = tmp_path / "cap.pcap"
    inner = ipv6_packet("2001:db8::1", "2001:db8::2", 51, ah_payload(59, 22, 1))
    write_pcap(path, DLT_EN10MB, [eth_frame(inner, ethertype=0x86DD)])

    (record,) = read_packets(path).packets

    assert record.ip_version == 6
    assert record.proto == "ah"
    assert record.spi == 22


@pytest.mark.parametrize(
    ("linktype", "frame_builder"),
    [(DLT_LINUX_SLL, sll_frame), (DLT_LINUX_SLL2, sll2_frame)],
)
def test_linux_cooked_capture_linktypes(
    tmp_path: Path, linktype: int, frame_builder: Callable[[bytes], bytes]
) -> None:
    path = tmp_path / "cap.pcap"
    inner = ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, 1))
    write_pcap(path, linktype, [frame_builder(inner)])

    (record,) = read_packets(path).packets

    assert record.proto == "esp"
    assert record.spi == 1


def test_raw_ip_linktype(tmp_path: Path) -> None:
    path = tmp_path / "cap.pcap"
    write_pcap(path, DLT_RAW, [ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, 1))])

    (record,) = read_packets(path).packets

    assert record.proto == "esp"


def test_truncated_packet_reports_both_lengths(tmp_path: Path) -> None:
    """Step 3.6 depends on this: ``captured_len < orig_len`` must be visible."""
    path = tmp_path / "cap.pcap"
    frame = eth_frame(ipv4_packet("10.0.0.1", "10.0.0.2", 50, esp_payload(1, 1, b"X" * 200)))
    write_pcap(path, DLT_EN10MB, [frame], snaplen=40)

    (record,) = read_packets(path).packets

    assert record.captured_len == 40
    assert record.orig_len == len(frame)
    assert record.captured_len < record.orig_len


def test_ike_sa_init_message_id_is_captured(tmp_path: Path) -> None:
    """Feeds step 3.6's ike_complete: message ID 0 marks IKE_SA_INIT."""
    path = tmp_path / "cap.pcap"
    inner = ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp_packet(500, 500, isakmp_header(0)))
    write_pcap(path, DLT_EN10MB, [eth_frame(inner)])

    result = read_packets(path)

    assert result.ike_message_ids == [0]


def test_unrecognisable_pcap_magic_raises(tmp_path: Path) -> None:
    path = tmp_path / "not-a-pcap.bin"
    path.write_bytes(b"\x00" * 24)

    with pytest.raises(IngestError):
        read_packets(path)
