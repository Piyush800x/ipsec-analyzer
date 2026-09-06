"""Track B inference service. Step 9.11.

The seam the pipeline calls. It runs the deterministic analyses that exist --
the cipher-family sieve (9.2), sequence and rekey behaviour (9.3), PFS (9.4)
-- and, for the parts that need a trained model, **reports UNAVAILABLE with the
reason** rather than pretending.

That last part is the whole design of this module. Steps 9.6 through 9.10 need
the labelled dataset from Phase 8, which needs Docker, which was not available
(see CHANGELOG). The choices were to fake a classifier, to leave the pipeline
stage out, or to wire the seam properly and have it say what it does not know.
Only the third produces a system whose behaviour will not change shape when the
models arrive: ``predict_traffic`` already returns the right type, the
assessment already renders the right cell, and the policy's confidence guards
already refuse to fire on it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from analyzer.core.enums import EncryptionAlg, IntegrityAlg, OperatingMode, Provenance
from analyzer.core.schema import (
    Attribute,
    CaptureQuality,
    SecurityAssociation,
    TrafficPrediction,
)
from analyzer.ingest.flow import SAPair
from analyzer.track_b import cipher_family, replay
from analyzer.track_b.pfs import infer_pfs

log = logging.getLogger(__name__)

NO_MODEL_NOTE: Final = (
    "no trained model is available for this deployment. The classifier "
    "(implementation-plan steps 9.6-9.9) requires the labelled dataset from "
    "Phase 8, which has not been generated. This is an absence of a model, not "
    "a measurement of zero leakage"
)


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
    is a supported state, not an error, and it is the state this project is in
    today.
    """

    def __init__(self, model_dir: Path | None = None) -> None:
        self._model_dir = model_dir
        self._models: dict[str, object] = {}
        if model_dir is not None and model_dir.is_dir():
            found = sorted(p.name for p in model_dir.glob("*.txt")) + sorted(
                p.name for p in model_dir.glob("*.pt")
            )
            if found:
                log.info("model artefacts present but no loader is implemented yet: %s", found)

    @property
    def model_versions(self) -> dict[str, str]:
        """What went into an assessment, for its ``model_versions`` field.

        Empty is the correct state for a Track A-only assessment, and the
        contract says so.
        """
        return {}

    def analyse(
        self, pair: SAPair, quality: CaptureQuality, *, dh_group: int | None = None
    ) -> TrackBResult:
        packets = list(pair.forward.packets) + list(pair.reverse.packets if pair.reverse else ())
        esp_lengths = [
            p.esp_payload_len for p in packets if p.proto == "esp" and p.esp_payload_len is not None
        ]

        spi_first_seen: list[tuple[int, float]] = [(pair.forward.key.spi, pair.forward.start_ts)]
        if pair.reverse:
            spi_first_seen.append((pair.reverse.key.spi, pair.reverse.start_ts))

        return TrackBResult(
            encryption_alg=cipher_family.detect_encryption(esp_lengths, quality),
            integrity_alg=cipher_family.detect_integrity(esp_lengths, quality),
            # ML-2 (step 9.9). Honest until a model exists.
            operating_mode=Attribute.unavailable(NO_MODEL_NOTE),
            pfs_enabled=infer_pfs([], [], dh_group),
            replay_sane=replay.replay_sane(packets),
            observed_rekey_s=replay.observed_rekey_s(spi_first_seen),
            inner_traffic=[],
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
