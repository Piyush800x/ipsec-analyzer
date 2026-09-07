"""Replay behaviour and observed rekey timing. Step 9.3, LLD 7.5.

LLD section 7.5 opens by saying that being imprecise here is the most common
way a project of this kind loses credibility, and it is right. The table it
gives is the specification for this module, and two of its rows are about what
this module must *refuse* to report:

============================  ==========  ===================================
Property                      Observable  Handled here as
============================  ==========  ===================================
Sequence monotonicity         yes         ``replay_sane``
Duplicate sequence numbers    yes         counted, feeds ``replay_sane``
Sequence gaps                 yes         counted, but never called an attack
ESN in use                    Track A     not touched here
Anti-replay window size       **never**   ``window_size`` is UNAVAILABLE, always
Observed rekey interval       yes         ``observed_rekey_s``
============================  ==========  ===================================

The distinction ``replay_sane`` encodes is the one that matters: it means
"sequence numbers behave correctly on the wire", **not** "anti-replay is
enabled". The window size is a receiver-side local setting that is never
transmitted, so no amount of traffic analysis can recover it, and the report
wording must preserve that difference.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import Final

from analyzer.core.schema import Attribute, Evidence
from analyzer.ingest.flow import SAPair
from analyzer.ingest.reader import PacketRecord

GAP_TOLERANCE: Final = 0.02
"""Fraction of missing sequence numbers tolerated before ``replay_sane`` turns
false. Capture drops are ordinary -- tcpdump drops packets under load and a
span port drops them silently -- so a handful of gaps says more about the
capture than the deployment."""

SEQUENCE_CONFIDENCE: Final = 0.95
"""High, because this is nearly a measurement: the only uncertainty is whether
the capture itself dropped what looks like a gap."""

MIN_PACKETS_FOR_SEQUENCE: Final = 20
"""Below this, one dropped packet dominates the gap ratio and the answer says
nothing about the deployment."""


@dataclass(frozen=True, slots=True)
class SequenceStats:
    packets: int
    duplicates: int
    out_of_order: int
    missing: int
    first_seq: int
    last_seq: int

    @property
    def gap_ratio(self) -> float:
        span = max(1, self.last_seq - self.first_seq + 1)
        return self.missing / span


def sequence_stats(packets: Sequence[PacketRecord]) -> SequenceStats | None:
    """Per-SA sequence behaviour. ``None`` when there is nothing to say."""
    sequences = [p.seq for p in packets if p.seq is not None]
    if len(sequences) < 2:
        return None

    seen: set[int] = set()
    duplicates = 0
    out_of_order = 0
    previous = sequences[0]
    for value in sequences:
        if value in seen:
            duplicates += 1
        seen.add(value)
        if value < previous:
            out_of_order += 1
        previous = value

    first, last = min(sequences), max(sequences)
    expected = last - first + 1
    return SequenceStats(
        packets=len(sequences),
        duplicates=duplicates,
        out_of_order=out_of_order,
        missing=max(0, expected - len(seen)),
        first_seq=first,
        last_seq=last,
    )


def replay_sane(packets: Sequence[PacketRecord]) -> Attribute[bool]:
    """Whether sequence numbers behave correctly on the wire.

    Not "anti-replay is enabled" -- that is a different claim this module is
    structurally unable to make (see ``anti_replay_window_size``).
    """
    stats = sequence_stats(packets)
    if stats is None or stats.packets < MIN_PACKETS_FOR_SEQUENCE:
        return Attribute.unavailable(
            f"fewer than {MIN_PACKETS_FOR_SEQUENCE} sequenced ESP packets on this SA; "
            "one dropped packet would dominate the result"
        )

    evidence = Evidence(
        method="esp_sequence_analysis",
        measured={
            "packets": stats.packets,
            "duplicates": stats.duplicates,
            "out_of_order": stats.out_of_order,
            "missing": stats.missing,
            "gap_ratio": round(stats.gap_ratio, 4),
        },
    )

    sane = stats.duplicates == 0 and stats.gap_ratio <= GAP_TOLERANCE
    note = (
        "sequence numbers are monotonic with no duplicates"
        if sane
        else (
            f"{stats.duplicates} duplicate and {stats.missing} missing sequence numbers. "
            "Gaps also arise from capture drops and reordering middleboxes, so this is "
            "not by itself evidence of a replay attack (LLD section 7.5)"
        )
    )
    return Attribute.inferred(sane, SEQUENCE_CONFIDENCE, evidence=evidence, note=note)


def anti_replay_window_size() -> Attribute[int]:
    """Always UNAVAILABLE. There is no other correct answer.

    The window size is a receiver-side local setting that is never transmitted
    (LLD section 7.5). A function rather than a constant so that the reason
    travels with the value wherever it is used.
    """
    return Attribute.unavailable(
        "the anti-replay window size is a receiver-side local setting and is never "
        "transmitted, so it cannot be determined from a capture by any means "
        "(LLD section 7.5)"
    )


def spi_series(sa_pairs: Sequence[SAPair]) -> dict[tuple[str, str], list[tuple[int, float]]]:
    """Each *directed* endpoint pair's SPIs, in the order they first appeared.

    This is the input ``observed_rekey_s`` needs, and computing it requires the
    whole capture rather than one SA -- which is the correction this function
    exists to make.

    A rekey replaces the Child SA, and a new Child SA means a new SPI, which
    ``ingest.assemble_flows`` groups into an entirely **separate** ``SAPair``.
    So the successive generations of one tunnel are never visible from inside a
    single ``SAPair``; what *is* inside one is its forward and reverse SPI, and
    those two belong to the same generation and appear at the same instant.

    Reading a rekey interval off one ``SAPair`` therefore measures the gap
    between the two directions of a single SA coming up -- which is
    approximately zero, every time, for every capture. Grouping by direction
    across pairs is what makes successive entries successive *generations*.

    Directed rather than unordered on purpose: an unordered key interleaves the
    two directions, and since both directions of a generation start together,
    every other interval in the merged series is a spurious zero.
    """
    series: dict[tuple[str, str], list[tuple[int, float]]] = {}
    for pair in sa_pairs:
        for flow in (pair.forward, pair.reverse):
            if flow is None:
                continue
            series.setdefault((flow.key.src, flow.key.dst), []).append(
                (flow.key.spi, flow.start_ts)
            )
    for entries in series.values():
        entries.sort(key=lambda entry: entry[1])
    return series


def observed_rekey_s(spi_first_seen: Sequence[tuple[int, float]]) -> Attribute[int]:
    """Time between successive SPIs appearing in **one direction**. FR-4.6.

    *spi_first_seen* is ``(spi, first timestamp)`` for a single directed
    endpoint pair, in appearance order -- see ``spi_series``, which is how a
    caller should build it. Two SPIs are one rekey; one SPI is not evidence
    that no rekey happens, only that none happened inside the capture window.

    Passing both directions of a tunnel here is a caller error that this
    function cannot detect: the two SPIs of one generation appear together, so
    the merged series is full of zero-length intervals and the median collapses
    to zero -- reported as an INFERRED rekey interval of 0 seconds at 0.95
    confidence, which is a confident falsehood of exactly the kind this project
    exists to avoid.
    """
    if len(spi_first_seen) < 2:
        return Attribute.unavailable(
            "only one ESP SPI appeared on this endpoint pair, so no rekey happened "
            "within the capture window. This is a fact about the capture's length, "
            "not evidence that the SA never rekeys"
        )

    ordered = sorted(spi_first_seen, key=lambda entry: entry[1])
    intervals = [round(later[1] - earlier[1]) for earlier, later in pairwise(ordered)]
    median = sorted(intervals)[len(intervals) // 2]

    return Attribute.inferred(
        median,
        SEQUENCE_CONFIDENCE,
        evidence=Evidence(
            method="spi_rotation_timing",
            measured={
                "spi_count": len(ordered),
                "intervals_s": ", ".join(str(value) for value in intervals),
                "median_interval_s": median,
            },
        ),
        note=(
            f"{len(intervals)} SPI rotation(s) observed; the median interval is the "
            "reported value. A rekey slightly early or late is normal -- most "
            "implementations jitter the interval deliberately"
        ),
    )
