"""PCAP reader producing PacketRecord values (LLD 5). Steps 3.1-3.4.

``dpkt`` over a buffered file handle, decoding only outer headers -- no deep
dissection. Every frame in the file becomes exactly one ``PacketRecord``,
including frames this reader cannot classify (``proto="other"``), so
``len(read_packets(path).packets)`` always equals the file's total frame
count. That is what step 3.2's Done-when condition checks against
``tshark -r file | wc -l``.

Only the classic pcap file format is supported, matching what
``testbed/capture.py``'s ``tcpdump -w`` invocation produces. pcapng is out of
scope: nothing in this project's pipeline writes it.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final, Literal, NamedTuple

from dpkt.ah import AH
from dpkt.esp import ESP
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.ip6 import IP6
from dpkt.sll import SLL
from dpkt.sll2 import SLL2
from dpkt.udp import UDP

IsakmpProto = Literal["esp", "ah", "isakmp", "isakmp_natt", "other"]


class PacketRecord(NamedTuple):
    """One packet's outer-header facts. LLD section 5."""

    index: int  # type: ignore[assignment] # LLD sec 5 field name; shadows tuple.index(), never called as a method
    ts: float
    ip_version: int
    src: str
    dst: str
    proto: IsakmpProto
    spi: int | None
    seq: int | None
    ip_payload_len: int
    """Bytes after the outer IP header (IPv6: after the fixed 40-byte header,
    extension headers included -- there is no equivalent of IPv4 options)."""
    esp_payload_len: int | None
    """``IV || ciphertext || ICV`` -- the bytes after ESP's own 8-byte SPI and
    sequence-number header, wherever that header sits (raw ESP, or inside a
    NAT-T UDP/4500 payload). ``None`` for every non-ESP packet."""
    captured_len: int
    orig_len: int


class FlowKey(NamedTuple):
    """Identity of one directional SA or IKE stream. LLD section 5."""

    src: str
    dst: str
    spi: int
    proto: str


@dataclass(frozen=True, slots=True)
class IngestResult:
    """Everything one pass over a capture produced.

    ``ike_message_ids`` is not part of LLD section 5's contract; it exists so
    step 3.6's ``ike_complete`` (was ``IKE_SA_INIT`` on the wire, rather than a
    join mid-stream) can be computed without a second parse of the ISAKMP
    header, which this reader already has in hand while classifying a packet
    as ``isakmp``/``isakmp_natt``.
    """

    packets: list[PacketRecord]
    ike_message_ids: list[int]


class IngestError(RuntimeError):
    """The file is not a pcap this reader can decode."""


IP_PROTO_ESP: Final = 50
IP_PROTO_AH: Final = 51
UDP_PORT_ISAKMP: Final = 500
UDP_PORT_ISAKMP_NATT: Final = 4500
NON_ESP_MARKER: Final = b"\x00\x00\x00\x00"
ESP_HEADER_LEN: Final = 8
"""RFC 4303: 4-byte SPI + 4-byte sequence number."""
ISAKMP_HEADER_LEN: Final = 28
"""RFC 7296 section 3.1: two 8-byte SPIs, 4 header bytes, 4-byte message ID,
4-byte length."""

_DLT_EN10MB: Final = 1
_DLT_LINUX_SLL: Final = 113
_DLT_LINUX_SLL2: Final = 276
_IP_VERSION_4: Final = 4
_IP_VERSION_6: Final = 6

_MAGIC_LE_MICRO: Final = 0xA1B2C3D4
_MAGIC_LE_NANO: Final = 0xA1B23C4D
_MAGIC_BE_MICRO: Final = 0xD4C3B2A1
_MAGIC_BE_NANO: Final = 0x4D3CB2A1
_FILE_HDR_LEN: Final = 24
_RECORD_HDR_LEN: Final = 16


def read_packets(path: Path) -> IngestResult:
    """Read *path* end to end, decoding only outer headers."""
    packets: list[PacketRecord] = []
    ike_message_ids: list[int] = []
    with path.open("rb") as fh:
        linktype, records = _iter_pcap_records(fh)
        for index, (ts, buf, caplen, orig_len) in enumerate(records):
            packets.append(_decode(index, ts, buf, caplen, orig_len, linktype, ike_message_ids))
    return IngestResult(packets=packets, ike_message_ids=ike_message_ids)


def _iter_pcap_records(fh: IO[bytes]) -> tuple[int, _RecordIter]:
    header = fh.read(_FILE_HDR_LEN)
    if len(header) < _FILE_HDR_LEN:
        msg = "truncated pcap global header"
        raise IngestError(msg)

    magic_probe = struct.unpack("<I", header[:4])[0]
    if magic_probe in (_MAGIC_LE_MICRO, _MAGIC_LE_NANO):
        order = "<"
    elif magic_probe in (_MAGIC_BE_MICRO, _MAGIC_BE_NANO):
        order = ">"
    else:
        msg = f"not a classic pcap file (magic {header[:4]!r})"
        raise IngestError(msg)
    nano = magic_probe in (_MAGIC_LE_NANO, _MAGIC_BE_NANO)

    _, _, _, _, _, _snaplen, linktype = struct.unpack(f"{order}IHHiIII", header)
    return linktype, _RecordIter(fh, order, nano)


class _RecordIter:
    """Yields ``(ts, buf, caplen, orig_len)`` for each record in a classic pcap body."""

    def __init__(self, fh: IO[bytes], order: str, nano: bool) -> None:
        self._fh = fh
        self._order = order
        self._divisor = 1e9 if nano else 1e6

    def __iter__(self) -> _RecordIter:
        return self

    def __next__(self) -> tuple[float, bytes, int, int]:
        header = self._fh.read(_RECORD_HDR_LEN)
        if not header:
            raise StopIteration
        if len(header) < _RECORD_HDR_LEN:
            msg = "truncated pcap record header"
            raise IngestError(msg)
        ts_sec, ts_frac, caplen, orig_len = struct.unpack(f"{self._order}IIII", header)
        buf = self._fh.read(caplen)
        if len(buf) < caplen:
            msg = "truncated packet body"
            raise IngestError(msg)
        return ts_sec + ts_frac / self._divisor, buf, caplen, orig_len


def _link_layer_payload(buf: bytes, linktype: int) -> IP | IP6 | None:
    if linktype == _DLT_EN10MB:
        payload = Ethernet(buf).data
    elif linktype == _DLT_LINUX_SLL:
        payload = SLL(buf).data
    elif linktype == _DLT_LINUX_SLL2:
        payload = SLL2(buf).data
    elif buf:
        version = buf[0] >> 4
        if version == _IP_VERSION_4:
            payload = IP(buf)
        elif version == _IP_VERSION_6:
            payload = IP6(buf)
        else:
            return None
    else:
        return None
    return payload if isinstance(payload, IP | IP6) else None


def _outer_ip_facts(ip_pkt: IP | IP6) -> tuple[int, str, str, int]:
    if isinstance(ip_pkt, IP):
        ip_payload_len = ip_pkt.len - ip_pkt.hl * 4
        return 4, socket.inet_ntoa(ip_pkt.src), socket.inet_ntoa(ip_pkt.dst), ip_payload_len
    return (
        6,
        socket.inet_ntop(socket.AF_INET6, ip_pkt.src),
        socket.inet_ntop(socket.AF_INET6, ip_pkt.dst),
        ip_pkt.plen,
    )


def _security_header(ip_pkt: IP | IP6) -> tuple[int, ESP | AH] | None:
    """The ESP or AH header carried directly by *ip_pkt*, if any.

    For IPv6, dpkt resolves ESP/AH as entries of ``extension_hdrs`` rather than
    as ``.data`` (dpkt's IPv6 unpacker treats every RFC 8200 extension header,
    ESP and AH included, as part of the same walk). ESP is checked first: this
    project's testbed never negotiates AH-then-ESP, and ESP is the case that
    matters for the length-lattice work in LLD section 7.2.
    """
    if isinstance(ip_pkt, IP):
        return (ip_pkt.p, ip_pkt.data) if isinstance(ip_pkt.data, ESP | AH) else None
    if IP_PROTO_ESP in ip_pkt.extension_hdrs:
        return IP_PROTO_ESP, ip_pkt.extension_hdrs[IP_PROTO_ESP]
    if IP_PROTO_AH in ip_pkt.extension_hdrs:
        return IP_PROTO_AH, ip_pkt.extension_hdrs[IP_PROTO_AH]
    return None


def _record_ike_message_id(data: bytes, sink: list[int]) -> None:
    if len(data) >= ISAKMP_HEADER_LEN:
        sink.append(struct.unpack_from(">I", data, 20)[0])


def _decode(
    index: int,
    ts: float,
    buf: bytes,
    caplen: int,
    orig_len: int,
    linktype: int,
    ike_message_ids: list[int],
) -> PacketRecord:
    ip_pkt = _link_layer_payload(buf, linktype)
    if ip_pkt is None:
        return PacketRecord(index, ts, 0, "", "", "other", None, None, 0, None, caplen, orig_len)

    ip_version, src, dst, ip_payload_len = _outer_ip_facts(ip_pkt)

    security = _security_header(ip_pkt)
    if security is not None:
        proto_num, hdr = security
        if proto_num == IP_PROTO_ESP:
            return PacketRecord(
                index, ts, ip_version, src, dst, "esp", hdr.spi, hdr.seq,
                ip_payload_len, len(hdr.data), caplen, orig_len,
            )  # fmt: skip
        return PacketRecord(
            index, ts, ip_version, src, dst, "ah", hdr.spi, hdr.seq,
            ip_payload_len, None, caplen, orig_len,
        )  # fmt: skip

    udp = ip_pkt.data if isinstance(ip_pkt.data, UDP) else None
    if udp is not None:
        if UDP_PORT_ISAKMP in (udp.sport, udp.dport):
            _record_ike_message_id(bytes(udp.data), ike_message_ids)
            return PacketRecord(
                index, ts, ip_version, src, dst, "isakmp", None, None,
                ip_payload_len, None, caplen, orig_len,
            )  # fmt: skip
        if UDP_PORT_ISAKMP_NATT in (udp.sport, udp.dport):
            payload = bytes(udp.data)
            if payload[:4] == NON_ESP_MARKER:
                _record_ike_message_id(payload[4:], ike_message_ids)
                return PacketRecord(
                    index, ts, ip_version, src, dst, "isakmp_natt", None, None,
                    ip_payload_len, None, caplen, orig_len,
                )  # fmt: skip
            if len(payload) >= ESP_HEADER_LEN:
                esp = ESP(payload)
                return PacketRecord(
                    index, ts, ip_version, src, dst, "esp", esp.spi, esp.seq,
                    ip_payload_len, len(esp.data), caplen, orig_len,
                )  # fmt: skip

    return PacketRecord(
        index, ts, ip_version, src, dst, "other", None, None,
        ip_payload_len, None, caplen, orig_len,
    )  # fmt: skip
