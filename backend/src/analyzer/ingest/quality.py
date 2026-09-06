"""CaptureQuality computation (LLD 5). Step 3.6.

Every downstream analyser reads ``CaptureQuality`` and self-disables where its
preconditions fail. ``sufficient_for_lattice`` is the guard that stops the
cipher-family sieve (LLD section 7.2) producing a confident wrong answer on a
VoIP-only or truncated capture.
"""

from __future__ import annotations

from analyzer.core.schema import (
    MIN_DISTINCT_LENGTHS_FOR_LATTICE,
    MIN_ESP_PACKETS_FOR_LATTICE,
    CaptureQuality,
)
from analyzer.ingest.flow import SAPair
from analyzer.ingest.reader import IngestResult


def compute_quality(result: IngestResult, sa_pairs: list[SAPair]) -> CaptureQuality:
    """Build a ``CaptureQuality`` from one reader pass and its assembled flows."""
    packets = result.packets
    warnings: list[str] = []

    packet_count = len(packets)
    timestamps = [p.ts for p in packets]
    duration_s = max(timestamps) - min(timestamps) if packets else 0.0

    truncated = any(p.captured_len < p.orig_len for p in packets)
    if truncated:
        warnings.append(
            "capture is truncated: some packets were cut short by the capture's snaplen"
        )

    has_ike = any(p.proto in ("isakmp", "isakmp_natt") for p in packets)
    ike_complete = has_ike and 0 in result.ike_message_ids
    if has_ike and not ike_complete:
        warnings.append(
            "IKE traffic is present but IKE_SA_INIT was not captured; "
            "the negotiation was joined mid-stream"
        )

    esp_lengths = [
        p.esp_payload_len for p in packets if p.proto == "esp" and p.esp_payload_len is not None
    ]
    esp_sa_count = _flow_count(sa_pairs, "esp")

    sufficient_for_lattice = (
        not truncated
        and len(esp_lengths) >= MIN_ESP_PACKETS_FOR_LATTICE
        and len(set(esp_lengths)) >= MIN_DISTINCT_LENGTHS_FOR_LATTICE
    )
    if not sufficient_for_lattice and esp_lengths and not truncated:
        warnings.append(
            "insufficient ESP length diversity for the cipher-family sieve "
            f"(need >= {MIN_ESP_PACKETS_FOR_LATTICE} packets and "
            f"{MIN_DISTINCT_LENGTHS_FOR_LATTICE} distinct lengths, "
            f"have {len(esp_lengths)} and {len(set(esp_lengths))})"
        )

    return CaptureQuality(
        packet_count=packet_count,
        duration_s=duration_s,
        truncated=truncated,
        has_ike=has_ike,
        ike_complete=ike_complete,
        esp_sa_count=esp_sa_count,
        sufficient_for_lattice=sufficient_for_lattice,
        warnings=warnings,
    )


def _flow_count(sa_pairs: list[SAPair], proto: str) -> int:
    count = 0
    for pair in sa_pairs:
        if pair.forward.key.proto == proto:
            count += 1
            if pair.reverse is not None:
                count += 1
    return count
