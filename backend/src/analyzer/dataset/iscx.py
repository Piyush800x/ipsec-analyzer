"""ISCXVPN2016 adapter. Step 8.5, feeding the cross-validation of step 9.12.

Maps the University of New Brunswick's ISCXVPN2016 captures into the feature
format ``track_b.features`` produces for testbed captures, so a traffic
classifier trained on our own tunnels can be evaluated on traffic nobody here
generated. An internal test set built by the same generator that built the
training set flatters a model; an external one does not.

**Read this before trusting a number that comes out of here.**

ISCXVPN2016 is not IPsec. Its "VPN" captures are OpenVPN over UDP, and its
non-VPN captures are plain application traffic. Neither carries an ESP header,
so there is no SPI to key a security association on and no
``esp_payload_len`` to measure. Two substitutions bridge that, and both change
what the numbers mean:

1. **Flows are keyed by address pair, not by SPI.** ``_synthetic_spi`` derives
   a stable integer from the address pair purely so the existing ``FlowKey``
   type can be filled in. It is not an SPI and must never be reported as one.
2. **``ip_payload_len`` stands in for ``esp_payload_len``.** These are not the
   same measurement. The ESP figure is ``IV || ciphertext || ICV`` and nothing
   else; the IP figure includes the transport header and carries no ESP
   overhead at all.

Substitution 2 is why the **geometry** features -- ``esp_len_mod16_*``,
``esp_len_modal``, ``esp_len_distinct`` -- are not comparable across the two
corpora. They measure ESP padding and ICV structure, and there is none here.
``NOT_COMPARABLE`` names them, and ``comparable_feature_names()`` is what step
9.12 should evaluate on. The timing, flow and directionality groups do
transfer: they describe the application's behaviour, which is what the traffic
classifier is supposed to be reading anyway.

Reporting a cross-corpus score over the geometry columns would produce a
number that looks like generalisation and is actually an artefact. Step 9.12
says to report the gap and not hide it; this is where the gap starts.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from analyzer.core.enums import TrafficClass
from analyzer.ingest.flow import Flow, SAPair
from analyzer.ingest.reader import FlowKey, PacketRecord, read_packets
from analyzer.track_b import features

MIN_PACKETS: Final = 8
"""Below this a flow's timing statistics are noise. ISCXVPN2016 captures carry
background chatter -- DNS, ARP-adjacent stray unicast -- that would otherwise
enter the matrix as hundreds of two-packet rows and swamp the real traffic."""

LABEL_PATTERNS: Final[tuple[tuple[str, TrafficClass], ...]] = (
    # Ordered: the first match wins, so the specific precedes the general.
    # "skype_file" is file transfer, not VoIP, and must be tested before "skype".
    (r"(?:^|[_-])(?:aim|icq|facebook|hangout|skype)[_-]?chat", TrafficClass.MESSAGING),
    (r"(?:^|[_-])(?:skype|ftps?|sftp|scp)[_-]?(?:file|transfer)", TrafficClass.FILE_TRANSFER),
    (r"(?:^|[_-])(?:voipbuzz|voip)", TrafficClass.VOIP),
    (r"(?:^|[_-])(?:skype|hangouts?|facebook)[_-]?(?:audio|voice|call)", TrafficClass.VOIP),
    (r"(?:^|[_-])(?:skype|hangouts?|facebook)[_-]?video", TrafficClass.VIDEO),
    (r"(?:^|[_-])(?:youtube|netflix|vimeo|spotify)", TrafficClass.VIDEO),
    (r"(?:^|[_-])(?:email|gmail|pop|imap|smtp)", TrafficClass.EMAIL),
    (r"(?:^|[_-])(?:ftps?|sftp|scp|torrent|bittorrent)", TrafficClass.FILE_TRANSFER),
    (r"(?:^|[_-])(?:icq|aim|hangouts?|chat)", TrafficClass.MESSAGING),
    (r"(?:^|[_-])(?:browsing|http|https|web)", TrafficClass.WEB),
    (r"(?:^|[_-])(?:icmp|ping)", TrafficClass.ICMP),
)
"""ISCXVPN2016 encodes its label in the filename -- ``vpn_youtube.pcap``,
``email1a.pcap``, ``skype_file1.pcap``.

The seven classes here are PRD section 9.2's, and the mapping is deliberately
**partial**. ISCXVPN2016 has no ICMP category worth speaking of, and it carries
applications with no home in our taxonomy (``tor_*``, ``p2p`` in some
distributions). Those return ``None`` and are reported as unmapped rather than
being forced into the nearest bucket, which would inject label noise into the
one evaluation whose whole purpose is to be trusted.
"""

NOT_COMPARABLE: Final[frozenset[str]] = frozenset(
    {"esp_len_distinct", "esp_len_modal", "esp_len_modal_share"}
    | {f"esp_len_mod16_{residue}" for residue in range(16)}
)
"""Features that measure ESP padding geometry, which these captures do not have.

The ``esp_len_*`` *statistics* -- mean, std, percentiles -- are deliberately
**not** in this set. They describe payload size distribution, which is a real
property of the application in both corpora even though the exact byte counts
are offset by the missing ESP overhead. The congruence and modality features
are different: they are measuring a padding rule that is simply absent here,
and their values would be structured noise.
"""

VPN_PREFIX: Final = re.compile(r"^vpn[_-]", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ExternalFlow:
    """One flow from an external capture, with its provenance kept attached."""

    source: Path
    label: TrafficClass | None
    tunnelled: bool
    """Whether the source file is one of ISCXVPN2016's VPN captures. Worth
    keeping separate: a classifier trained on IPsec should do better on the
    OpenVPN half than on the plaintext half, and if it does not, that is a
    finding rather than a detail."""
    vector: dict[str, float]


@dataclass(frozen=True, slots=True)
class AdaptedBatch:
    """What one directory of external captures produced, gaps included."""

    flows: tuple[ExternalFlow, ...]
    unmapped: tuple[Path, ...]
    """Files whose name matched no label pattern. Reported, never guessed."""
    empty: tuple[Path, ...]
    """Files that parsed but yielded no flow above ``MIN_PACKETS``."""
    unreadable: tuple[tuple[Path, str], ...]
    """Files the reader refused, with its reason. ISCXVPN2016 ships some
    captures in pcapng, which ``read_packets`` does not accept; a batch that
    silently dropped them would overstate its own coverage."""

    @property
    def labelled(self) -> tuple[ExternalFlow, ...]:
        return tuple(flow for flow in self.flows if flow.label is not None)


def label_for(name: str) -> TrafficClass | None:
    """The traffic class ISCXVPN2016's filename convention encodes, if any."""
    stem = Path(name).stem.lower()
    for pattern, traffic_class in LABEL_PATTERNS:
        if re.search(pattern, stem):
            return traffic_class
    return None


def is_tunnelled(name: str) -> bool:
    """ISCXVPN2016 prefixes its VPN captures ``vpn_``."""
    return bool(VPN_PREFIX.match(Path(name).stem))


def _synthetic_spi(src: str, dst: str) -> int:
    """A stable 32-bit integer standing in for an SPI these packets lack.

    Deterministic across runs and processes -- ``hash()`` is not, and a feature
    matrix whose row identity changed between runs would be untraceable. Only
    ever used to fill ``FlowKey.spi``; never reported.
    """
    digest = 0
    for char in f"{src}>{dst}":
        digest = (digest * 131 + ord(char)) & 0xFFFFFFFF
    return digest


def _as_esp_shaped(packet: PacketRecord) -> PacketRecord:
    """Move ``ip_payload_len`` into the ``esp_payload_len`` slot.

    ``features.extract`` reads ``esp_payload_len`` and treats ``None`` as zero,
    so without this every external vector would be all-zero geometry and would
    look like a well-padded tunnel rather than an unmeasured one. See the module
    docstring on what this substitution costs.
    """
    return packet._replace(esp_payload_len=packet.ip_payload_len)


def to_sa_pairs(packets: Sequence[PacketRecord], *, min_packets: int = MIN_PACKETS) -> list[SAPair]:
    """Group non-ESP packets into ``SAPair``s keyed on the address pair.

    Mirrors ``ingest.flow.assemble_flows`` in shape, but keys on addresses
    because there is no SPI. Direction is decided by which address pair was
    seen first, so the same capture always yields the same forward direction.
    """
    directional: dict[tuple[str, str], list[PacketRecord]] = {}
    for packet in packets:
        if not packet.src or not packet.dst:
            continue
        directional.setdefault((packet.src, packet.dst), []).append(_as_esp_shaped(packet))

    pairs: list[SAPair] = []
    consumed: set[tuple[str, str]] = set()
    for key in sorted(directional, key=lambda k: directional[k][0].index):
        if key in consumed:
            continue
        src, dst = key
        forward_packets = directional[key]
        reverse_packets = directional.get((dst, src))
        consumed.update({key, (dst, src)})

        total = len(forward_packets) + len(reverse_packets or [])
        if total < min_packets:
            continue

        forward = _flow(src, dst, forward_packets)
        reverse = _flow(dst, src, reverse_packets) if reverse_packets else None
        pairs.append(SAPair(forward=forward, reverse=reverse, paired=reverse is not None))
    return pairs


def _flow(src: str, dst: str, packets: list[PacketRecord]) -> Flow:
    ordered = sorted(packets, key=lambda p: (p.ts, p.index))
    return Flow(
        key=FlowKey(src=src, dst=dst, spi=_synthetic_spi(src, dst), proto="esp"),
        packets=tuple(ordered),
        start_ts=ordered[0].ts,
        end_ts=ordered[-1].ts,
    )


def adapt_capture(path: Path, *, min_packets: int = MIN_PACKETS) -> list[ExternalFlow]:
    """Feature vectors for one external capture, one per address-pair flow."""
    label = label_for(path.name)
    tunnelled = is_tunnelled(path.name)
    return [
        ExternalFlow(source=path, label=label, tunnelled=tunnelled, vector=features.extract(pair))
        for pair in to_sa_pairs(read_packets(path).packets, min_packets=min_packets)
    ]


def adapt_directory(root: Path, *, min_packets: int = MIN_PACKETS) -> AdaptedBatch:
    """Adapt every capture under *root*, keeping the failures visible."""
    flows: list[ExternalFlow] = []
    unmapped: list[Path] = []
    empty: list[Path] = []
    unreadable: list[tuple[Path, str]] = []

    for path in sorted(root.rglob("*.pcap")):
        try:
            produced = adapt_capture(path, min_packets=min_packets)
        except Exception as exc:
            unreadable.append((path, str(exc)))
            continue
        if not produced:
            empty.append(path)
            continue
        if produced[0].label is None:
            unmapped.append(path)
        flows.extend(produced)

    return AdaptedBatch(
        flows=tuple(flows),
        unmapped=tuple(unmapped),
        empty=tuple(empty),
        unreadable=tuple(unreadable),
    )


def comparable_feature_names(names: Iterable[str]) -> list[str]:
    """*names* minus the ESP-geometry features, sorted.

    What step 9.12 should evaluate on. Everything removed here is measuring a
    padding rule these captures do not have.
    """
    return sorted(set(names) - NOT_COMPARABLE)
