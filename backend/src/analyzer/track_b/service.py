"""Track B inference service. Step 9.11.

The seam the pipeline calls. It runs the deterministic analyses that exist --
the cipher-family sieve (9.2), sequence and rekey behaviour (9.3), PFS (9.4)
-- and, for the parts that need a trained model, **reports UNAVAILABLE with the
reason** rather than pretending.

**Both states are supported, and neither is a special case.** When
``model_dir`` holds trained artefacts they are loaded and used; when it is
empty every model-backed field comes back UNAVAILABLE with ``NO_MODEL_NOTE``
explaining that no classifier is installed. The empty case is not a stub
awaiting removal -- an air-gapped deployment that was handed the code and not
the artefacts runs in it permanently, and it has to produce a correct
assessment that is honest about what it could not determine, rather than an
error or a guess.

Loading is lazy and failure-tolerant for the same reason. LightGBM and torch
live in the ``ml`` dependency group and are absent from the offline image
(step 11.4), so importing them at module scope would make this module -- which
the API imports on every request -- unimportable in the deployment that needs
it most. An artefact that is present but unreadable is logged and treated as
absent, because a model that will not load is exactly as informative as no
model, and crashing the pipeline over it would lose the Track A analysis too.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from analyzer.core.enums import (
    EncryptionAlg,
    IntegrityAlg,
    OperatingMode,
    Provenance,
    TrafficClass,
)
from analyzer.core.schema import (
    Attribute,
    CaptureQuality,
    Evidence,
    SecurityAssociation,
    TrafficPrediction,
)
from analyzer.ingest.flow import SAPair
from analyzer.ingest.reader import PacketRecord
from analyzer.track_b import cipher_family, replay
from analyzer.track_b.pfs import infer_pfs

log = logging.getLogger(__name__)

NO_MODEL_NOTE: Final = (
    "no trained model is available for this deployment. The classifier "
    "(implementation-plan steps 9.6-9.9) requires the labelled dataset from "
    "Phase 8, which has not been generated. This is an absence of a model, not "
    "a measurement of zero leakage"
)


TRAFFIC_MODEL_NAME: Final = "traffic_lightgbm.txt"
MODE_MODEL_NAME: Final = "mode_lightgbm.txt"
CALIBRATION_NAME: Final = "calibration.json"
"""Artefact filenames, as ``track_b/train.py`` writes them.

The LightGBM traffic classifier is what inference loads rather than the CNN,
even though the CNN is the stronger model. Loading the CNN would make torch a
runtime dependency of the API and of the offline image, for a model whose
advantage is measured in the metrics file; LightGBM also gives exact TreeSHAP
attributions (step 9.10) that the CNN can only approximate. ``metrics.json``
records both models' scores so the trade is visible rather than implicit."""

MIN_SPAN_CONFIDENCE: Final = 0.0
"""No confidence floor. A low-confidence prediction is reported *with* its low
confidence, because the assessment policy's own confidence guards decide what
is actionable -- suppressing it here would hide the uncertainty rather than
communicate it, and the guard would never see the row it was written for."""


def _artefact_version(path: Path) -> str:
    """A short content hash of an artefact, as its version string.

    Derived from the bytes rather than read from a sidecar, so it cannot fall
    out of step with the file it names -- which is the whole purpose of
    ``Assessment.model_versions``: tracing an inference back to the exact model
    that produced it.
    """
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256:{digest[:16]}"


def _feature_vector(pair: SAPair, feature_names: list[str]) -> Any:
    """One window's tabular features, ordered as the model was trained.

    Ordered by the *model's* stored feature names, never by whatever order the
    extractor happens to return. A feature vector assembled in a different order
    than training would be silently wrong -- every value present, every value in
    the wrong column, and no error anywhere.
    """
    import numpy as np

    from analyzer.track_b.features import extract

    features = extract(pair)
    missing = [name for name in feature_names if name not in features]
    if missing:
        msg = (
            f"the loaded model expects features this build does not produce: {missing[:5]}. "
            "The extractor and the artefact are from different versions."
        )
        raise ValueError(msg)
    return np.array([features[name] for name in feature_names], dtype=np.float32)


def _merge_spans(
    scored: list[tuple[float, float, int, float, list[Any]]],
    *,
    labels: tuple[str, ...],
) -> list[TrafficPrediction]:
    """Merge adjacent windows sharing an argmax label into one span. LLD 7.6.

    The span's confidence is the *minimum* over its windows, not the mean. A
    span is a claim about the whole stretch, and it is only as good as its
    weakest window -- averaging would let one uncertain window disappear into
    its confident neighbours, which is precisely the window an analyst should
    see.
    """
    merged: list[TrafficPrediction] = []
    for start_ts, end_ts, index, confidence, attributions in scored:
        label = labels[index]
        if label not in _TRAFFIC_CLASS_VALUES:
            # An artefact trained against a different vocabulary. Dropped with a
            # warning rather than coerced: there is no correct mapping from an
            # unknown label onto this contract's seven classes, and picking the
            # nearest one would put a fabricated class into a security report.
            log.warning("model predicted %r, which is not a TrafficClass; window dropped", label)
            continue
        if merged and merged[-1].label == label and merged[-1].window_end >= _utc(start_ts):
            previous = merged[-1]
            merged[-1] = previous.model_copy(
                update={
                    "window_end": _utc(end_ts),
                    "probability": min(previous.probability, confidence),
                }
            )
            continue
        merged.append(
            TrafficPrediction(
                label=TrafficClass(label),
                probability=confidence,
                window_start=_utc(start_ts),
                window_end=_utc(end_ts),
                top_features=attributions,
            )
        )
    return merged


_TRAFFIC_CLASS_VALUES: Final = frozenset(member.value for member in TrafficClass)


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=UTC)


@dataclass(frozen=True, slots=True)
class TrackBResult:
    """Everything Track B contributes to one SA."""

    encryption_alg: Attribute[EncryptionAlg]
    integrity_alg: Attribute[IntegrityAlg]
    operating_mode: Attribute[OperatingMode]
    pfs_enabled: Attribute[bool]
    replay_sane: Attribute[bool]
    observed_rekey_s: Attribute[int]
    inner_traffic: list[TrafficPrediction]


class InferenceService:
    """Loads what models exist and applies them. Step 9.11.

    ``model_dir`` is scanned rather than assumed: a deployment with no models
    is a supported state, not an error.
    """

    def __init__(self, model_dir: Path | None = None) -> None:
        self._model_dir = model_dir
        self._traffic: object | None = None
        self._mode: object | None = None
        self._temperature: float = 1.0
        self._isotonic: list[dict[str, list[float]]] = []
        self._versions: dict[str, str] = {}
        if model_dir is not None and model_dir.is_dir():
            self._load(model_dir)

    def _load(self, model_dir: Path) -> None:
        """Load whatever artefacts are present, tolerating each one's absence.

        Each model is loaded independently: a deployment shipped the traffic
        classifier but not the mode classifier should use the one it has rather
        than neither.
        """
        traffic_path = model_dir / TRAFFIC_MODEL_NAME
        if traffic_path.exists():
            try:
                from analyzer.track_b.traffic_clf import LightGbmModel

                self._traffic = LightGbmModel.load(traffic_path)
                self._versions["traffic_classifier"] = _artefact_version(traffic_path)
            except Exception as exc:
                log.warning("traffic classifier at %s could not be loaded: %s", traffic_path, exc)

        mode_path = model_dir / MODE_MODEL_NAME
        if mode_path.exists():
            try:
                from analyzer.track_b.mode import ModeModel

                self._mode = ModeModel.load(mode_path)
                self._versions["mode_classifier"] = _artefact_version(mode_path)
            except Exception as exc:
                log.warning("mode classifier at %s could not be loaded: %s", mode_path, exc)

        calibration_path = model_dir / CALIBRATION_NAME
        if calibration_path.exists():
            try:
                document = json.loads(calibration_path.read_text(encoding="utf-8"))
                self._temperature = float(document.get("cnn_temperature", 1.0)) or 1.0
                self._isotonic = list(document.get("lightgbm_isotonic_knots", []))
                self._versions["calibration"] = _artefact_version(calibration_path)
            except Exception as exc:
                log.warning("calibration at %s could not be read: %s", calibration_path, exc)

    @property
    def model_versions(self) -> dict[str, str]:
        """What went into an assessment, for its ``model_versions`` field.

        Empty is the correct state for a Track A-only assessment, and the
        contract says so. A populated one is how an assessment is traced back to
        the exact artefact that produced its inferences, so the version is
        derived from the file's own content rather than from a string a training
        run wrote next to it -- a hash cannot get out of step with the bytes it
        describes.
        """
        return dict(self._versions)

    def analyse(
        self,
        pair: SAPair,
        quality: CaptureQuality,
        *,
        dh_group: int | None = None,
        create_child_sizes: Sequence[int] = (),
        baseline_sizes: Sequence[int] = (),
        spi_first_seen: Sequence[tuple[int, float]] = (),
    ) -> TrackBResult:
        packets = list(pair.forward.packets) + list(pair.reverse.packets if pair.reverse else ())
        esp_lengths = [
            p.esp_payload_len for p in packets if p.proto == "esp" and p.esp_payload_len is not None
        ]

        # ML-1 first, then ML-2 with ML-1's output as a feature. LLD section 7.3
        # breaks the circularity in this direction only, and the ordering here
        # is the enforcement of it: `operating_mode` cannot be computed before
        # `inner_traffic` exists to be passed to it.
        inner_traffic = self.predict_traffic(pair)
        operating_mode = self.predict_mode(pair, packets, inner_traffic)

        return TrackBResult(
            encryption_alg=cipher_family.detect_encryption(esp_lengths, quality),
            integrity_alg=cipher_family.detect_integrity(esp_lengths, quality),
            operating_mode=operating_mode,
            pfs_enabled=infer_pfs(create_child_sizes, baseline_sizes, dh_group),
            replay_sane=replay.replay_sane(packets),
            observed_rekey_s=replay.observed_rekey_s(spi_first_seen),
            inner_traffic=inner_traffic,
        )

    def predict_traffic(self, pair: SAPair) -> list[TrafficPrediction]:
        """ML-1 over 10-second windows, merged into spans. FR-4.1, LLD 7.6.

        Returns an empty list when no model is installed. Empty is the correct
        answer there and is *not* the same claim as "no classifiable traffic
        was found": the report's capability matrix distinguishes the two, and
        ``model_versions`` being empty is what tells it which case this is.
        """
        if self._traffic is None:
            return []

        from analyzer.track_b.attribution import lightgbm_attribution
        from analyzer.track_b.calibration import apply_knots
        from analyzer.track_b.windows import MIN_WINDOW_PACKETS, WINDOW_S, window_pair

        model = self._traffic
        scored: list[tuple[float, float, int, float, list[object]]] = []
        for start_ts, windowed in window_pair(pair):
            total = len(windowed.forward.packets) + (
                len(windowed.reverse.packets) if windowed.reverse else 0
            )
            if total < MIN_WINDOW_PACKETS:
                continue

            vector = _feature_vector(windowed, model.feature_names)  # type: ignore[attr-defined] # loaded LightGbmModel
            raw = model.predict_proba(vector.reshape(1, -1))  # type: ignore[attr-defined]
            # TrafficPrediction.probability is specified as *calibrated*, and it
            # is also the metadata-exposure measurement the score is computed
            # from -- so the isotonic mapping is applied here rather than being
            # left to the caller, where forgetting it would silently overstate
            # what a passive observer learns.
            probabilities = apply_knots(raw, self._isotonic)[0]
            index = int(probabilities.argmax())
            attributions = lightgbm_attribution(model, vector, class_index=index)
            scored.append(
                (
                    start_ts,
                    start_ts + WINDOW_S,
                    index,
                    float(probabilities[index]),
                    list(attributions),
                )
            )

        return _merge_spans(scored, labels=model.labels)  # type: ignore[attr-defined]

    def predict_mode(
        self,
        pair: SAPair,
        packets: list[PacketRecord],
        inner_traffic: list[TrafficPrediction],
    ) -> Attribute[OperatingMode]:
        """ML-2 (step 9.9), taking ML-1's output as an input feature.

        *inner_traffic* is a parameter rather than something recomputed here so
        that the ordering LLD section 7.3 mandates is visible at the call site
        and cannot be inverted by a later edit.
        """
        if self._mode is None:
            return Attribute.unavailable(NO_MODEL_NOTE)

        from analyzer.track_b.mode import extract_mode_features

        distribution: dict[str, float] = {}
        for prediction in inner_traffic:
            label = str(prediction.label.value)
            distribution[label] = max(distribution.get(label, 0.0), prediction.probability)

        features = extract_mode_features(pair, packets, distribution)
        label, confidence = self._mode.predict(features)  # type: ignore[attr-defined] # loaded ModeModel
        try:
            mode = OperatingMode(label)
        except ValueError:
            log.warning("mode classifier returned an unknown label %r", label)
            return Attribute.unavailable(
                f"the mode classifier returned {label!r}, which is not an OperatingMode"
            )
        return Attribute.inferred(
            mode,
            confidence,
            evidence=Evidence(
                method="mode_classifier",
                measured=dict(zip(features.names(), features.vector(), strict=True)),
            ),
            note=(
                "inferred from encapsulation overhead and endpoint role (LLD section 7.3); "
                "the inner traffic class was classified first and used as an input feature"
            ),
        )

    def apply(self, sa: SecurityAssociation, result: TrackBResult) -> SecurityAssociation:
        """Fold Track B's findings into a Track A ``SecurityAssociation``.

        Track A's values win where it observed something: an inference must
        never overwrite a parsed fact. Track B only fills what Track A left
        unavailable, plus the fields that are its own by definition.
        """
        updates: dict[str, object] = {
            "operating_mode": result.operating_mode,
            "pfs_enabled": result.pfs_enabled,
            "replay_sane": result.replay_sane,
            "observed_rekey_s": result.observed_rekey_s,
            "inner_traffic": result.inner_traffic,
        }

        # The cipher sieve is a *fallback*: it only speaks where Track A could
        # not, which is the ESP-only capture case (PRD section 7, FR-4.4). Both
        # fields are filled independently, because the sieve routinely
        # determines one and not the other.
        for field, inferred in (
            ("encryption_alg", result.encryption_alg),
            ("integrity_alg", result.integrity_alg),
        ):
            existing: Attribute[object] = getattr(sa, field)
            if existing.provenance is Provenance.UNAVAILABLE and inferred.value is not None:
                updates[field] = inferred

        return sa.model_copy(update=updates)
