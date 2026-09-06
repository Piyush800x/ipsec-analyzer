"""Feature extraction over ESP flows. Step 9.1, LLD 7.1.

Polars over one row per packet, grouped per SA. The feature groups are LLD
section 7.1's table; the names are stable because they become column headers
in the training matrices (step 9.5) and SHAP labels in the reports (9.10), and
renaming one silently invalidates a trained model.

Two properties are load-bearing and tested:

- **No NaNs, ever.** A feature that cannot be computed for a short flow gets an
  explicit zero, not a NaN that propagates through training and turns up as a
  model that refuses to score half the captures.
- **Deterministic ordering.** Same input, same vector, same order -- this feeds
  NFR-4 as much as the assessment engine does.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

import polars as pl

from analyzer.ingest.flow import SAPair
from analyzer.ingest.reader import PacketRecord

BURST_GAP_S: Final = 0.2
"""LLD section 7.1: a gap longer than 200 ms starts a new burst."""

SEQUENCE_FEATURE_LENGTH: Final = 128
"""The CNN input from LLD section 7.1: the first 128 signed sizes, zero-padded.
Signed by direction, so the model sees the conversation's shape rather than
just its volume."""

PERCENTILES: Final[tuple[int, ...]] = (10, 25, 50, 75, 90, 99)


def _frame(packets: Sequence[PacketRecord], *, forward_src: str) -> pl.DataFrame:
    return pl.DataFrame(
        {
            "ts": [p.ts for p in packets],
            "length": [p.esp_payload_len or 0 for p in packets],
            "upstream": [p.src == forward_src for p in packets],
        }
    )


def _as_float(value: object) -> float:
    """Polars aggregations are typed as a broad union and return None on an
    empty or single-element series. Zero is the honest answer for both -- a
    NaN here would propagate into a training matrix and turn up much later as
    a model that silently refuses half the captures."""
    return float(value) if isinstance(value, int | float) else 0.0


def _stats(values: pl.Series, prefix: str) -> dict[str, float]:
    """Mean/std/min/max plus percentiles, with zeros rather than NaNs."""
    if values.len() == 0:
        base = {f"{prefix}_{name}": 0.0 for name in ("mean", "std", "min", "max")}
        base.update({f"{prefix}_p{p}": 0.0 for p in PERCENTILES})
        return base

    out = {
        f"{prefix}_mean": _as_float(values.mean()),
        # std is null for a single sample; zero is the honest answer there.
        f"{prefix}_std": _as_float(values.std()),
        f"{prefix}_min": _as_float(values.min()),
        f"{prefix}_max": _as_float(values.max()),
    }
    for percentile in PERCENTILES:
        out[f"{prefix}_p{percentile}"] = _as_float(values.quantile(percentile / 100))
    return out


def extract(pair: SAPair) -> dict[str, float]:
    """One feature vector for one SA pair. LLD section 7.1's groups."""
    forward = pair.forward
    packets = list(forward.packets) + list(pair.reverse.packets if pair.reverse else ())
    packets.sort(key=lambda p: (p.ts, p.index))

    features: dict[str, float] = {}
    if not packets:
        return features

    frame = _frame(packets, forward_src=forward.key.src)
    lengths = frame["length"]

    # --- geometry ---------------------------------------------------------
    features.update(_stats(lengths, "esp_len"))
    residues = (lengths % 16).value_counts().sort("length")
    for residue in range(16):
        match = residues.filter(pl.col("length") == residue)
        features[f"esp_len_mod16_{residue}"] = (
            float(match["count"][0]) / len(packets) if match.height else 0.0
        )
    distinct = lengths.n_unique()
    features["esp_len_distinct"] = float(distinct)
    # `mode()` returns ties in arbitrary order, and when every length is
    # distinct *every* value is a mode -- so an unsorted pick makes this
    # feature differ between two runs over identical input. Sorting is what
    # keeps this deterministic (NFR-4) and keeps a training column stable.
    modal_values = lengths.mode().sort()
    modal = _as_float(modal_values[0]) if modal_values.len() else 0.0
    features["esp_len_modal"] = modal
    features["esp_len_modal_share"] = (
        float((lengths == modal).sum()) / len(packets) if modal_values.len() else 0.0
    )

    # --- flow -------------------------------------------------------------
    duration = max(1e-6, _as_float(frame["ts"].max()) - _as_float(frame["ts"].min()))
    total_bytes = _as_float(lengths.sum())
    features["packet_count"] = float(len(packets))
    features["byte_count"] = total_bytes
    features["duration_s"] = duration
    features["packets_per_s"] = len(packets) / duration
    features["bytes_per_s"] = total_bytes / duration

    # --- timing -----------------------------------------------------------
    inter_arrival = frame["ts"].diff().drop_nulls()
    features.update(_stats(inter_arrival, "iat"))
    mean_iat = features["iat_mean"]
    features["iat_cv"] = features["iat_std"] / mean_iat if mean_iat > 0 else 0.0
    bursts = int((inter_arrival > BURST_GAP_S).sum()) if inter_arrival.len() else 0
    features["burst_count"] = float(bursts)
    idle = inter_arrival.filter(inter_arrival > BURST_GAP_S)
    features["idle_total_s"] = _as_float(idle.sum())
    features["idle_mean_s"] = _as_float(idle.mean()) if idle.len() else 0.0

    # --- directionality ---------------------------------------------------
    up = frame.filter(pl.col("upstream"))
    down = frame.filter(~pl.col("upstream"))
    up_bytes = _as_float(up["length"].sum())
    down_bytes = _as_float(down["length"].sum())
    features["up_packets"] = float(up.height)
    features["down_packets"] = float(down.height)
    # Ratios against a zero denominator are 0.0, not infinity: a one-directional
    # capture is legitimate (LLD section 5) and must not produce a NaN.
    features["up_down_byte_ratio"] = up_bytes / down_bytes if down_bytes else 0.0
    features["up_down_packet_ratio"] = up.height / down.height if down.height else 0.0
    features.update(_stats(up["length"], "up_len"))
    features.update(_stats(down["length"], "down_len"))

    # --- SA behaviour -----------------------------------------------------
    features["sa_spi_count"] = 2.0 if pair.reverse else 1.0
    features["sa_paired"] = 1.0 if pair.paired else 0.0

    return features


def sequence_features(pair: SAPair) -> list[float]:
    """The first 128 signed packet sizes, zero-padded. CNN input (LLD 7.1)."""
    packets = list(pair.forward.packets) + list(pair.reverse.packets if pair.reverse else ())
    packets.sort(key=lambda p: (p.ts, p.index))
    signed = [
        float(p.esp_payload_len or 0) * (1.0 if p.src == pair.forward.key.src else -1.0)
        for p in packets[:SEQUENCE_FEATURE_LENGTH]
    ]
    return signed + [0.0] * (SEQUENCE_FEATURE_LENGTH - len(signed))


def feature_names(pair: SAPair) -> list[str]:
    """Stable column order for the training matrices of step 9.5."""
    return sorted(extract(pair))
