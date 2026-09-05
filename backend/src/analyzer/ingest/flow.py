"""Flow assembly and SA pairing (LLD 5). Step 3.5.

Group packets by ``FlowKey``, then pair directional SAs into ``SAPair`` by
matching ``(src, dst)`` against ``(dst, src)`` with overlapping time ranges.
Unpaired SAs are retained and flagged -- a one-directional capture is a
legitimate and common analyst situation, not an error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from analyzer.ingest.reader import FlowKey, PacketRecord

SA_FLOW_PROTOS: Final = ("esp", "ah")
"""Only these carry a real SPI and take part in flow assembly. ISAKMP and
unclassified packets do not form flows."""


@dataclass(frozen=True, slots=True)
class Flow:
    """Every packet sharing one ``FlowKey`` -- one direction of one SA."""

    key: FlowKey
    packets: tuple[PacketRecord, ...]
    start_ts: float
    end_ts: float


@dataclass(frozen=True, slots=True)
class SAPair:
    """A directional SA, and its reverse-direction counterpart if one exists.

    LLD section 5 names this type without giving it a schema. ``reverse`` is
    optional and ``paired`` records which case this is, rather than raising on
    a one-directional capture or fabricating a partner for it.
    """

    forward: Flow
    reverse: Flow | None
    paired: bool


def assemble_flows(packets: list[PacketRecord]) -> list[SAPair]:
    """Group *packets* into flows and pair directional SAs where they overlap."""
    by_key: dict[FlowKey, list[PacketRecord]] = {}
    order: list[FlowKey] = []
    for pkt in packets:
        if pkt.proto not in SA_FLOW_PROTOS or pkt.spi is None:
            continue
        key = FlowKey(src=pkt.src, dst=pkt.dst, spi=pkt.spi, proto=pkt.proto)
        if key not in by_key:
            by_key[key] = []
            order.append(key)
        by_key[key].append(pkt)

    flows = [_build_flow(key, by_key[key]) for key in order]
    return _pair_flows(flows)


def _build_flow(key: FlowKey, pkts: list[PacketRecord]) -> Flow:
    timestamps = [p.ts for p in pkts]
    return Flow(key=key, packets=tuple(pkts), start_ts=min(timestamps), end_ts=max(timestamps))


def _overlaps(a: Flow, b: Flow) -> bool:
    return a.start_ts <= b.end_ts and b.start_ts <= a.end_ts


def _is_reverse_of(candidate: Flow, flow: Flow) -> bool:
    return (
        candidate.key.src == flow.key.dst
        and candidate.key.dst == flow.key.src
        and candidate.key.proto == flow.key.proto
        and _overlaps(flow, candidate)
    )


def _pair_flows(flows: list[Flow]) -> list[SAPair]:
    unmatched = list(flows)
    pairs: list[SAPair] = []
    while unmatched:
        flow = unmatched.pop(0)
        partner_index = next(
            (i for i, other in enumerate(unmatched) if _is_reverse_of(other, flow)), None
        )
        if partner_index is None:
            pairs.append(SAPair(forward=flow, reverse=None, paired=False))
        else:
            partner = unmatched.pop(partner_index)
            pairs.append(SAPair(forward=flow, reverse=partner, paired=True))
    return pairs
