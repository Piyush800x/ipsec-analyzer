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

**Why the maximum length is the wrong length to look at.** The first version of
this model scored 0.7273 against step 9.9's 0.90 target, and measuring its four
features across the whole corpus said why. Two of them are *constant*: on a
two-container testbed with one SA pair there are always two SPIs over two
endpoints, so ``spi_pairs_per_endpoint`` is 1.0 in all 216 sessions, and there
is no correlated cleartext on a private bridge, so ``cleartext_ratio`` is 0.0 in
all 216. They are kept because they are LLD section 7.3's and would carry signal
on a real capture with several SAs and side traffic; here they carry none, and
saying so is more useful than quietly dropping them.

That leaves the length features, and the maximum is precisely the length the
inner header cannot move. Tunnel mode adds 20 bytes (IPv4) or 40 (IPv6) to
every packet, but the path MTU caps the packet, so for any class that saturates
the MTU the header *displaces* payload instead of adding to it. Measured per
class as the median tunnel-minus-transport difference in modal ESP length:

    icmp v4  +8    voip v4  +30    video v4  +18    web v4   -4
    icmp v6 +40    voip v6  +40    video v6  +60    web v6    0
                                   file_transfer v4/v6   0 / 0

Three of the six classes -- ``web``, ``file_transfer`` and ``email``, which is
most of the bulk traffic in the world -- show no signal at all, and a
classifier cannot do better than chance on them. That is what 0.73 was.

**The minimum length is the one that carries it.** The smallest packets in any
flow are pure acknowledgements, keepalives and control: nowhere near the MTU, so
the inner header adds to them rather than displacing anything. The same
measurement on ``min(esp_payload_len)`` is positive for *every* class in both IP
versions -- +8 to +60, tracking the 20 and 40 byte headers -- including the three
where the modal length is flat. Hence ``min_len_offset``, and
``inner_header_bytes`` alongside it so the model knows whether it is looking for
a 20-byte or a 40-byte shift rather than having to infer the IP version from the
offsets themselves.

With those two added and ``ModeBaseline`` fitted rather than hardcoded, held-out
accuracy goes from 0.75 to 0.92 on the same split.

LightGBM rather than the CNN: this is six features and a binary label, and a
tree over six features is both sufficient and legible in a way that matters
when a report has to say *why* it called a tunnel a tunnel.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import median
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
    """LLD section 7.3's four features, plus the two that make feature 1 work.

    The first four are LLD section 7.3's, named as that section names them.
    ``min_len_offset`` and ``inner_header_bytes`` are additions, and the
    module docstring explains why the section's own feature 1 does not carry
    the signal it was expected to.
    """

    max_len_over_mtu: float
    spi_pairs_per_endpoint: float
    cleartext_ratio: float
    modal_len_offset: float
    min_len_offset: float
    inner_header_bytes: float

    def vector(self) -> list[float]:
        return [
            self.max_len_over_mtu,
            self.spi_pairs_per_endpoint,
            self.cleartext_ratio,
            self.modal_len_offset,
            self.min_len_offset,
            self.inner_header_bytes,
        ]

    @staticmethod
    def names() -> list[str]:
        return [
            "max_len_over_mtu",
            "spi_pairs_per_endpoint",
            "cleartext_ratio",
            "modal_len_offset",
            "min_len_offset",
            "inner_header_bytes",
        ]


@dataclass(frozen=True, slots=True)
class ModeBaseline:
    """What each traffic class's ESP geometry looks like *without* an inner
    header, learned from transport-mode training sessions.

    LLD section 7.3's feature 4 is "the modal payload length compared against
    what that length should be for a given inner traffic class". The first
    implementation supplied that comparison from a hand-written table of round
    numbers, and measured against the real corpus the table was wrong by up to
    672 bytes -- `web` was written as 800 and observed at 1472. The effect the
    feature exists to detect is 20 or 40 bytes. A baseline whose error is
    thirty times the signal does not blur the feature, it replaces it.

    So the baseline is fitted instead of guessed: the median geometry of the
    *transport* sessions in the training fold, per traffic class and IP
    version. Transport because transport is by definition the case with no
    inner header; per IP version because the header being detected is 20 bytes
    for IPv4 and 40 for IPv6, so the two cannot share a baseline.

    **This is fitted to this testbed's generators and should be read that
    way.** It is the same exposure the traffic classifier already has, and the
    same measurement would answer it -- step 9.12's external validation. What
    it is not is a number invented in an editor.
    """

    min_len: dict[str, float]
    modal_len: dict[str, float]
    """Keyed ``"<traffic_class>/<ip_version>"``, e.g. ``"voip/4"``. A flat
    string key rather than a tuple because this is serialised to JSON beside
    the model and has to survive the round trip."""

    @staticmethod
    def key(traffic_class: str, ip_version: int) -> str:
        return f"{traffic_class}/{ip_version}"

    def expected(self, probabilities: dict[str, float], ip_version: int) -> tuple[float, float]:
        """The baseline geometry for a traffic-class *distribution*.

        Weighted by ML-1's distribution rather than taking its argmax, so a
        genuinely uncertain classification contributes a blurred baseline
        instead of a confidently wrong one.

        A class with no fitted baseline contributes nothing and its
        probability mass is renormalised away, rather than contributing a zero
        that would drag the baseline toward the origin and manufacture a large
        spurious offset.
        """
        known = {
            label: p
            for label, p in probabilities.items()
            if self.key(label, ip_version) in self.min_len
        }
        total = sum(known.values())
        if not total:
            return 0.0, 0.0
        min_len = sum(self.min_len[self.key(k, ip_version)] * p for k, p in known.items()) / total
        modal = sum(self.modal_len[self.key(k, ip_version)] * p for k, p in known.items()) / total
        return min_len, modal

    @classmethod
    def fit(cls, samples: Sequence[tuple[str, int, int, int]]) -> ModeBaseline:
        """Fit from ``(traffic_class, ip_version, min_len, modal_len)`` rows.

        The caller passes *transport-mode training sessions only*; this cannot
        check that for itself, and a tunnel session leaking in would move the
        baseline toward the very offset it is supposed to measure against.

        Median rather than mean: one session whose generator stalled and
        produced a handful of keepalives would drag a mean and cannot move a
        median.
        """
        by_key_min: dict[str, list[int]] = {}
        by_key_modal: dict[str, list[int]] = {}
        for traffic_class, ip_version, min_len, modal_len in samples:
            key = cls.key(traffic_class, ip_version)
            by_key_min.setdefault(key, []).append(min_len)
            by_key_modal.setdefault(key, []).append(modal_len)
        return cls(
            min_len={k: float(median(v)) for k, v in sorted(by_key_min.items())},
            modal_len={k: float(median(v)) for k, v in sorted(by_key_modal.items())},
        )

    def to_dict(self) -> dict[str, dict[str, float]]:
        return {"min_len": self.min_len, "modal_len": self.modal_len}

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ModeBaseline:
        data = data or {}
        return cls(
            min_len=dict(data.get("min_len") or {}), modal_len=dict(data.get("modal_len") or {})
        )

    def __bool__(self) -> bool:
        return bool(self.min_len)


EMPTY_BASELINE: Final = ModeBaseline(min_len={}, modal_len={})
"""What a model trained before baselines existed, or loaded without its meta
file, carries. Both offsets then come out 0.0 for every session, which is
uninformative rather than wrong -- the tree simply cannot split on them."""


def _inner_header_bytes(ip_version: int) -> float:
    return float(IPV6_HEADER_BYTES if ip_version == 6 else IPV4_HEADER_BYTES)


def extract_mode_features(
    pair: SAPair,
    all_packets: Sequence[PacketRecord],
    traffic_class_probabilities: dict[str, float],
    baseline: ModeBaseline = EMPTY_BASELINE,
) -> ModeFeatures:
    """LLD section 7.3's features for one SA.

    *traffic_class_probabilities* is ML-1's output and is required, not
    optional: see the module docstring for why this argument exists rather than
    being computed here.
    """
    packets = pair.forward.packets + (pair.reverse.packets if pair.reverse else ())
    lengths = [p.esp_payload_len for p in packets if p.esp_payload_len is not None]
    max_len = max(lengths) if lengths else 0
    min_len = min(lengths) if lengths else 0

    ip_version = packets[0].ip_version if packets else 4

    endpoints = {p.src for p in packets} | {p.dst for p in packets}
    spi_pairs = {(p.src, p.spi) for p in all_packets if p.spi is not None}
    per_endpoint = len(spi_pairs) / max(len(endpoints), 1)

    cleartext = sum(1 for p in all_packets if p.proto in CLEARTEXT_PROTOS)
    cleartext_ratio = cleartext / len(all_packets) if all_packets else 0.0

    expected_min, expected_modal = baseline.expected(traffic_class_probabilities, ip_version)
    modal = _modal(lengths)

    return ModeFeatures(
        max_len_over_mtu=float(max_len) / PATH_MTU,
        spi_pairs_per_endpoint=float(per_endpoint),
        cleartext_ratio=float(cleartext_ratio),
        modal_len_offset=float(modal - expected_modal) if expected_modal else 0.0,
        min_len_offset=float(min_len - expected_min) if expected_min else 0.0,
        inner_header_bytes=_inner_header_bytes(ip_version),
    )


def session_geometry(pair: SAPair) -> tuple[int, int, int]:
    """``(ip_version, min_len, modal_len)`` for one SA, for fitting a baseline.

    Shares ``_modal`` with the feature extractor deliberately: a baseline
    fitted with a different definition of "modal" than the feature it is
    subtracted from would be a constant offset applied to every session, which
    is invisible on the training fold and wrong everywhere else.
    """
    packets = pair.forward.packets + (pair.reverse.packets if pair.reverse else ())
    lengths = [p.esp_payload_len for p in packets if p.esp_payload_len is not None]
    ip_version = packets[0].ip_version if packets else 4
    return ip_version, (min(lengths) if lengths else 0), _modal(lengths)


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
    """A trained mode classifier, its label order, and its fitted baseline.

    The baseline travels *with* the booster rather than beside it because two
    of the six features are expressed relative to it. A model loaded without
    its baseline would compute both offsets as 0.0, split on neither, and
    quietly fall back to the accuracy of the four features that were already
    there -- with nothing raised and no way to tell from the output.
    """

    booster: Any
    labels: tuple[str, ...] = MODE_LABELS
    baseline: ModeBaseline = EMPTY_BASELINE

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
                {
                    "labels": list(self.labels),
                    "feature_names": ModeFeatures.names(),
                    "baseline": self.baseline.to_dict(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: Path) -> ModeModel:
        import lightgbm as lgb

        meta = json.loads(path.with_suffix(".meta.json").read_text(encoding="utf-8"))
        return cls(
            booster=lgb.Booster(model_file=str(path)),
            labels=tuple(meta["labels"]),
            baseline=ModeBaseline.from_dict(meta.get("baseline")),
        )


def train_mode(
    features: np.ndarray,
    y: np.ndarray,
    *,
    num_boost_round: int = 200,
    baseline: ModeBaseline = EMPTY_BASELINE,
) -> ModeModel:
    """Train ML-2 over LLD section 7.3's features and the two additions.

    *baseline* is stored on the returned model, not used here: the features
    have already been computed against it by the caller. It is threaded
    through so that a trained model cannot be saved without the baseline its
    offsets were measured from.
    """
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
    return ModeModel(booster=booster, baseline=baseline)


def evaluate_mode(model: ModeModel, features: np.ndarray, y: np.ndarray) -> Evaluation:
    """Accuracy and macro-F1 on held-out SAs. Step 9.9 targets accuracy >= 0.90."""
    predictions = model.predict_proba(features).argmax(axis=1)
    return evaluate(y, predictions, MODE_LABELS)
