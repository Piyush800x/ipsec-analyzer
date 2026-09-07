"""Tunnel vs transport classifier, ML-2 (LLD 7.3). Step 9.9.

**Ordering dependency, which step 9.9 requires be documented here.** LLD section
7.3's fourth feature -- the modal payload length compared against what that
length should be for a given inner traffic class -- depends on knowing the inner
traffic class, which is ML-1's output. That is a cycle, and LLD section 7.3
breaks it in one direction only: **the traffic classifier runs first and its
output is a feature of this model. Never the reverse.** ``predict`` therefore
takes a traffic-class distribution as an argument rather than computing one, so
the dependency is in the signature and cannot be satisfied backwards by
accident.

Why it has to be that direction and not the other: the traffic classifier reads
rates, burst structure and inter-arrival timing, none of which change when a
20-byte inner IP header is added to every packet. Mode, by contrast, is
*primarily* a statement about packet length, which is exactly what the inner
traffic class determines. One direction of the cycle is a small correction; the
other is the whole signal.

The other three features are LLD section 7.3's, in its order of usefulness:
maximum ESP length against the path MTU, endpoint role from distinct SPI counts
per address, and correlated cleartext in the same capture. Feature 3 is the one
that reads outside the SA, which is why ``extract_mode_features`` takes the
whole capture and not just the pair.

LightGBM rather than the CNN: this is four features and a binary label, and a
tree over four features is both sufficient and legible in a way that matters
when a report has to say *why* it called a tunnel a tunnel.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import numpy as np

from analyzer.ingest.flow import SAPair
from analyzer.ingest.reader import PacketRecord
from analyzer.track_b.traffic_clf import RANDOM_SEED, Evaluation, evaluate

log = logging.getLogger(__name__)

PATH_MTU: Final = 1500
"""The reference the maximum-length feature is expressed against. Ethernet's
MTU, which is what both the testbed bridge and most real paths present."""

IPV4_HEADER_BYTES: Final = 20
IPV6_HEADER_BYTES: Final = 40
"""The inner header tunnel mode adds and transport mode does not (LLD 7.3,
feature 1). Named because the whole model is trying to detect their presence."""

MODE_LABELS: Final[tuple[str, ...]] = ("transport", "tunnel")
"""Index order is fixed and saved with the model. ``tunnel`` is index 1, so a
probability from ``predict_proba``'s second column reads as P(tunnel)."""

CLEARTEXT_PROTOS: Final = frozenset({"other"})
"""What the ingest reader calls a packet that is neither ESP, AH nor ISAKMP.
LLD section 7.3's feature 3: in transport mode the outer addresses are the real
endpoints and tend to also emit ARP, DNS or NTP; in tunnel mode the gateway
addresses show little else."""


@dataclass(frozen=True, slots=True)
class ModeFeatures:
    """LLD section 7.3's four features, named as that section names them."""

    max_len_over_mtu: float
    spi_pairs_per_endpoint: float
    cleartext_ratio: float
    modal_len_offset: float

    def vector(self) -> list[float]:
        return [
            self.max_len_over_mtu,
            self.spi_pairs_per_endpoint,
            self.cleartext_ratio,
            self.modal_len_offset,
        ]

    @staticmethod
    def names() -> list[str]:
        return [
            "max_len_over_mtu",
            "spi_pairs_per_endpoint",
            "cleartext_ratio",
            "modal_len_offset",
        ]


EXPECTED_MODAL_LEN: Final[dict[str, int]] = {
    "icmp": 128,
    "voip": 200,
    "video": 1240,
    "web": 800,
    "email": 1200,
    "file_transfer": 1300,
    "messaging": 140,
}
"""Rough per-class expected outer payload length in *transport* mode.

Deliberately coarse. This is feature 4's baseline, and its job is to make the
~20-40 byte inner-header offset visible relative to what the class would look
like without one -- not to predict the length. A table tuned tighter than the
class-to-class spread would be fitting the testbed's specific generators, which
is exactly what the external validation of step 9.12 exists to catch."""


def extract_mode_features(
    pair: SAPair,
    all_packets: Sequence[PacketRecord],
    traffic_class_probabilities: dict[str, float],
) -> ModeFeatures:
    """LLD section 7.3's features for one SA.

    *traffic_class_probabilities* is ML-1's output and is required, not
    optional: see the module docstring for why this argument exists rather than
    being computed here.
    """
    packets = pair.forward.packets + (pair.reverse.packets if pair.reverse else ())
    lengths = [p.esp_payload_len for p in packets if p.esp_payload_len is not None]
    max_len = max(lengths) if lengths else 0

    endpoints = {p.src for p in packets} | {p.dst for p in packets}
    spi_pairs = {(p.src, p.spi) for p in all_packets if p.spi is not None}
    per_endpoint = len(spi_pairs) / max(len(endpoints), 1)

    cleartext = sum(1 for p in all_packets if p.proto in CLEARTEXT_PROTOS)
    cleartext_ratio = cleartext / len(all_packets) if all_packets else 0.0

    # Feature 4: the offset of the observed modal length from what this traffic
    # class looks like without an inner header. Weighted by ML-1's distribution
    # rather than taking its argmax, so a genuinely uncertain classification
    # contributes a blurred baseline instead of a confidently wrong one.
    modal = _modal(lengths)
    baseline = sum(
        EXPECTED_MODAL_LEN.get(label, 0) * probability
        for label, probability in traffic_class_probabilities.items()
    )
    offset = float(modal - baseline) if baseline else 0.0

    return ModeFeatures(
        max_len_over_mtu=float(max_len) / PATH_MTU,
        spi_pairs_per_endpoint=float(per_endpoint),
        cleartext_ratio=float(cleartext_ratio),
        modal_len_offset=offset,
    )


def _modal(lengths: Sequence[int]) -> int:
    """The most common length, ties broken by taking the smallest.

    Tie-breaking is explicit because ``statistics.mode`` and Polars' ``mode``
    both return ties in an order that is not guaranteed -- the same
    non-determinism that broke ``esp_len_modal`` in step 9.1 (CHANGELOG.md,
    Phase 9). A feature that changes between two runs over one capture would
    break NFR-4 and, worse, put a shifting column into a training matrix.
    """
    if not lengths:
        return 0
    counts: dict[int, int] = {}
    for length in lengths:
        counts[length] = counts.get(length, 0) + 1
    best = max(counts.values())
    return min(length for length, count in counts.items() if count == best)


@dataclass
class ModeModel:
    """A trained mode classifier and the label order it was trained with."""

    booster: Any
    labels: tuple[str, ...] = MODE_LABELS

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        raw = np.asarray(self.booster.predict(features), dtype=np.float64)
        # LightGBM's binary objective returns P(class 1) as a 1-D vector.
        if raw.ndim == 1:
            return np.column_stack([1.0 - raw, raw])
        return raw

    def predict(self, features: ModeFeatures) -> tuple[str, float]:
        """The predicted mode and its probability, for one SA."""
        probabilities = self.predict_proba(np.array([features.vector()], dtype=np.float32))[0]
        index = int(probabilities.argmax())
        return self.labels[index], float(probabilities[index])

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.booster.save_model(str(path))
        path.with_suffix(".meta.json").write_text(
            json.dumps(
                {"labels": list(self.labels), "feature_names": ModeFeatures.names()}, indent=2
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: Path) -> ModeModel:
        import lightgbm as lgb

        meta = json.loads(path.with_suffix(".meta.json").read_text(encoding="utf-8"))
        return cls(booster=lgb.Booster(model_file=str(path)), labels=tuple(meta["labels"]))


def train_mode(
    features: np.ndarray,
    y: np.ndarray,
    *,
    num_boost_round: int = 200,
) -> ModeModel:
    """Train ML-2 over LLD section 7.3's four features."""
    import lightgbm as lgb

    params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "learning_rate": 0.05,
        "num_leaves": 15,
        "min_data_in_leaf": 10,
        "seed": RANDOM_SEED,
        "deterministic": True,
        "force_row_wise": True,
        "verbosity": -1,
    }
    dataset = lgb.Dataset(features, label=y, feature_name=ModeFeatures.names())
    booster = lgb.train(params, dataset, num_boost_round=num_boost_round)
    return ModeModel(booster=booster)


def evaluate_mode(model: ModeModel, features: np.ndarray, y: np.ndarray) -> Evaluation:
    """Accuracy and macro-F1 on held-out SAs. Step 9.9 targets accuracy >= 0.90."""
    predictions = model.predict_proba(features).argmax(axis=1)
    return evaluate(y, predictions, MODE_LABELS)
