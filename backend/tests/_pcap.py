"""Byte-level builders for synthetic classic-pcap files, used by the ingest tests.

A real testbed capture needs Docker (step 2.1), which is not available in every
environment this suite runs in. These builders construct the exact wire layout
LLD section 5 describes by hand, so the reader can be tested against
known-correct packets without one. Checksums are left as zero throughout --
dpkt does not validate them, and neither does this project's reader.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

DLT_EN10MB = 1
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
DLT_RAW = 101

_PCAP_MAGIC = 0xA1B2C3D4
_ETH_SRC = bytes.fromhex("aaaaaaaaaaaa")
_ETH_DST = bytes.fromhex("bbbbbbbbbbbb")


def write_pcap(
    path: Path,
    linktype: int,
    frames: list[bytes],
    *,
    snaplen: int = 65535,
    interval_s: float = 1.0,
) -> None:
    """Write *frames* as a classic pcap file, *interval_s* apart, starting at t=0.

    The one-second default is what most of these tests want: it makes a frame
    index and a timestamp the same number, which keeps assertions readable.

    Anything exercising Track B's windowing needs a smaller interval. LLD §7.6
    scores a 10-second window only above 20 packets, so at one second per frame
    no window in a synthetic capture can ever be scored -- a test written that
    way gets an empty result and reads as a broken windower rather than as a
    capture too sparse to window.
    """
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", _PCAP_MAGIC, 2, 4, 0, 0, snaplen, linktype))
        for i, frame in enumerate(frames):
            caplen = min(len(frame), snaplen)
            offset = i * interval_s
            fh.write(
                struct.pack("<IIII", int(offset), round(offset % 1 * 1_000_000), caplen, len(frame))
            )
            fh.write(frame[:caplen])


def eth_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return _ETH_DST + _ETH_SRC + struct.pack(">H", ethertype) + payload


def sll_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return struct.pack(">HHH8sH", 0, 1, 6, _ETH_SRC.ljust(8, b"\x00"), ethertype) + payload


def sll2_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return struct.pack(">HHiHBB8s", ethertype, 0, 1, 1, 0, 6, _ETH_SRC.ljust(8, b"\x00")) + payload


def ipv4_packet(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header + payload


def ipv6_packet(src: str, dst: str, nxt: int, payload: bytes) -> bytes:
    header = struct.pack(
        ">IHBB16s16s",
        0x60000000,
        len(payload),
        nxt,
        64,
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst),
    )
    return header + payload


def esp_payload(spi: int, seq: int, body: bytes = b"\x00" * 32) -> bytes:
    return struct.pack(">II", spi, seq) + body


def ah_payload(nxt: int, spi: int, seq: int, icv: bytes = b"\x00" * 12, tail: bytes = b"") -> bytes:
    """RFC 4302 layout. ``len`` is header words in 4-octet units, minus 2."""
    length_field = (12 + len(icv)) // 4 - 2
    return struct.pack(">BBHII", nxt, length_field, 0, spi, seq) + icv + tail


def udp_packet(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack(">HHHH", sport, dport, length, 0) + payload


def isakmp_header(message_id: int, exchange_type: int = 34, length: int = 28) -> bytes:
    """The 28-byte ISAKMP fixed header. Just enough for message-ID extraction."""
    init_spi = b"\x11" * 8
    resp_spi = b"\x22" * 8
    fixed = struct.pack(">BBBBII", 0, 0x20, exchange_type, 0, message_id, length)
    return init_spi + resp_spi + fixed
