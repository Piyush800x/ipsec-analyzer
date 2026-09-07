"""Training entry point for Track B's models. Steps 9.5-9.10, 9.12.

``python -m analyzer.track_b.train <sessions-dir>`` assembles the dataset,
trains both traffic classifiers and the mode classifier, calibrates them, and
writes everything to ``backend/models/`` alongside a ``metrics.json`` recording
what was scored on what.

Everything reported here is measured on the *test* fold, which
``windows.split_configs`` fills with whole configurations never seen in
training or calibration. That is the number PRD section 8.4's targets are
about, and it is lower than a window-level split would produce -- which is the
point of splitting this way rather than the easier way.

The metrics file is written whatever the numbers are. A run that misses
PRD section 8.4's macro-F1 >= 0.85 records the miss; nothing here reruns with
different hyperparameters until a threshold is cleared, because a threshold
cleared that way is a description of the search, not of the model.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from analyzer.track_b import calibration as calib
from analyzer.track_b.mode import MODE_LABELS, ModeFeatures, evaluate_mode, train_mode
from analyzer.track_b.traffic_clf import (
    Evaluation,
    evaluate,
    label_vocabulary,
    matrices_for,
    train_cnn,
    train_lightgbm,
)
from analyzer.track_b.windows import (
    Window,
    feature_columns,
    load_dataset,
    sequence_columns,
    split_configs,
    to_frame,
)

log = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parents[3] / "models"


def _absent_classes(windows: list[Window]) -> dict[str, str]:
    """PRD section 9.2 classes that produced no scorable window, with the reason.

    Recorded rather than inferred from a short label list, because the two
    situations a reader must tell apart -- "this dataset has no messaging
    sessions" and "messaging sessions exist and every window was discarded" --
    look identical from the outside.
    """
    from analyzer.core.enums import TrafficClass

    present = {window.traffic_class for window in windows}
    return {
        member.value: (
            "sessions were generated but every window fell below LLD section "
            "7.6's 20-packet floor, so the class contributes no training rows. "
            "See CHANGELOG.md, 'LLD section 7.6's window floor makes PRD section "
            "9.2's sparsest class unlearnable'"
        )
        for member in TrafficClass
        if member.value not in present
    }


def _evaluation_dict(evaluation: Evaluation) -> dict[str, Any]:
    data = asdict(evaluation)
    data["labels"] = list(evaluation.labels)
    return data


def build_frame(sessions_dir: Path) -> tuple[pl.DataFrame, list[Window]]:
    windows = load_dataset(sessions_dir)
    if not windows:
        msg = f"no scorable windows under {sessions_dir}"
        raise SystemExit(msg)
    split = split_configs(windows)
    log.info(
        "split: %d train / %d calibration / %d test configurations",
        len(split.train),
        len(split.calibration),
        len(split.test),
    )
    return to_frame(windows, split), windows


def train_all(sessions_dir: Path, models_dir: Path, *, epochs: int = 60) -> dict[str, Any]:
    """Train, calibrate and evaluate everything. Returns the metrics document."""
    frame, windows = build_frame(sessions_dir)
    labels = label_vocabulary(frame)
    features = feature_columns(frame)
    sequences = sequence_columns(frame)

    folds = {
        name: matrices_for(
            frame, name, feature_names=features, sequence_names=sequences, labels=labels
        )
        for name in ("train", "calibration", "test")
    }
    train, calibration, test = folds["train"], folds["calibration"], folds["test"]

    metrics: dict[str, Any] = {
        "labels": list(labels),
        "n_features": len(features),
        "windows": {name: len(matrix.y) for name, matrix in folds.items()},
        "configurations": {name: len(set(matrix.config_names)) for name, matrix in folds.items()},
        "sessions_total": len({window.session_name for window in windows}),
        # Which of PRD section 9.2's classes never reached the model, and why.
        # A macro-F1 is an average over a class list, so a reader who does not
        # know the list cannot interpret the number: six classes perfectly
        # classified scores 6/7 = 0.857 against a seven-class target, which
        # would sit just above PRD section 8.4's 0.85 threshold while the model
        # had never seen a seventh of the problem.
        "classes_absent": _absent_classes(windows),
        # Kept so step 9.12 can hold the ESP-geometry features at the training
        # mean when scoring external captures that have no ESP geometry. Zero
        # would be a measurement there, and the wrong one.
        "training_feature_means": {
            name: float(value)
            for name, value in zip(features, train.tabular.mean(axis=0), strict=True)
        },
    }

    # --- step 9.6: LightGBM baseline ---------------------------------------
    log.info("step 9.6: LightGBM baseline over %d tabular features", len(features))
    gbm = train_lightgbm(train, calibration, feature_names=features, labels=labels)
    gbm_test_proba = gbm.predict_proba(test.tabular)
    gbm_eval = evaluate(test.y, gbm_test_proba.argmax(axis=1), labels)
    log.info("LightGBM test:\n%s", gbm_eval.summary())

    # --- step 9.8, LightGBM half: isotonic ---------------------------------
    isotonic = calib.fit_isotonic(
        gbm.predict_proba(calibration.tabular), calibration.y, len(labels)
    )
    gbm_calibrated = isotonic.apply(gbm_test_proba)
    metrics["lightgbm"] = {
        "test": _evaluation_dict(gbm_eval),
        "ece_uncalibrated": calib.expected_calibration_error(gbm_test_proba, test.y),
        "ece_calibrated": calib.expected_calibration_error(gbm_calibrated, test.y),
        "calibration_fold_ece_before": isotonic.ece_before,
        "calibration_fold_ece_after": isotonic.ece_after,
    }

    # --- step 9.7: the CNN --------------------------------------------------
    log.info("step 9.7: 1D-CNN over the %d-length sequence plus tabular", len(sequences))
    cnn = train_cnn(train, calibration, feature_names=features, labels=labels, epochs=epochs)
    cnn_test_logits = cnn.logits(test.tabular, test.sequence)
    cnn_eval = evaluate(test.y, cnn_test_logits.argmax(axis=1), labels)
    log.info("CNN test:\n%s", cnn_eval.summary())

    # --- step 9.8, CNN half: temperature scaling ---------------------------
    temperature = calib.fit_temperature(
        cnn.logits(calibration.tabular, calibration.sequence), calibration.y
    )
    cnn_calibrated = temperature.apply(cnn_test_logits)
    metrics["cnn"] = {
        "test": _evaluation_dict(cnn_eval),
        "temperature": temperature.value,
        "ece_uncalibrated": calib.expected_calibration_error(
            cnn.predict_proba(test.tabular, test.sequence), test.y
        ),
        "ece_calibrated": calib.expected_calibration_error(cnn_calibrated, test.y),
        "calibration_fold_ece_before": temperature.ece_before,
        "calibration_fold_ece_after": temperature.ece_after,
    }
    metrics["reliability"] = calib.reliability_bins(cnn_calibrated, test.y)

    # --- step 9.9: the mode classifier -------------------------------------
    metrics["mode"] = _train_mode_classifier(sessions_dir, models_dir, frame, gbm, features, labels)

    # --- artefacts ----------------------------------------------------------
    models_dir.mkdir(parents=True, exist_ok=True)
    gbm.save(models_dir / "traffic_lightgbm.txt")
    cnn.save(models_dir / "traffic_cnn.pt")
    # The isotonic mapping is exported as knots rather than a pickled
    # estimator: `service.apply_knots` reproduces it with `np.interp`, so
    # inference needs no scikit-learn, and a JSON table can be read by a person
    # asking why a confidence came out where it did.
    (models_dir / "calibration.json").write_text(
        json.dumps(
            {
                "cnn_temperature": temperature.value,
                "lightgbm_isotonic_knots": isotonic.knots(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    calib.write_reliability(
        models_dir / "reliability_cnn.json",
        metrics["reliability"],
        title="CNN, temperature-scaled, test fold",
    )
    return metrics


def _train_mode_classifier(
    sessions_dir: Path,
    models_dir: Path,
    frame: pl.DataFrame,
    traffic_model: Any,
    features: list[str],
    labels: tuple[str, ...],
) -> dict[str, Any]:
    """Step 9.9, with ML-1 running first and feeding it (LLD section 7.3).

    Built from whole sessions rather than windows: operating mode is a property
    of the SA, not of a ten-second slice of it, and scoring per window would
    count one tunnel's 30 windows as 30 independent correct answers.
    """
    import json as _json

    from analyzer.ingest.flow import assemble_flows
    from analyzer.ingest.reader import read_packets
    from analyzer.track_b.mode import ModeBaseline, extract_mode_features, session_geometry

    fold_of = dict(
        zip(
            frame["config_name"].to_list(),
            frame["fold"].to_list(),
            strict=True,
        )
    )

    # Collected in one pass, then turned into vectors in a second: two of the
    # six features are offsets against a baseline that is itself fitted from
    # the training fold, so no feature vector can be built until every session
    # has been seen. Re-reading 248 captures to do it would cost a second seven
    # minutes for data already in hand.
    collected: list[dict[str, Any]] = []
    for session_dir in sorted(p for p in sessions_dir.iterdir() if p.is_dir()):
        labels_path = session_dir / "labels.json"
        pcap_path = session_dir / "capture.pcap"
        if not labels_path.exists() or not pcap_path.exists():
            continue
        ground_truth = _json.loads(labels_path.read_text(encoding="utf-8"))
        mode = ground_truth.get("expected", {}).get("operating_mode")
        if mode not in MODE_LABELS:
            continue

        from analyzer.track_b.windows import config_name_of

        fold = fold_of.get(config_name_of(session_dir.name))
        if fold is None:
            continue

        packets = read_packets(pcap_path).packets
        pairs = assemble_flows(packets)
        if not pairs:
            continue

        # ML-1 first, then its output as a feature. Never the reverse.
        #
        # Scored over *windows* and averaged, not over the whole session in one
        # shot: the classifier was trained on 10-second windows, and a
        # whole-session feature vector is a different distribution than anything
        # it has seen. It would still return a confident answer, which is the
        # failure mode worth avoiding -- the wrongness would be invisible.
        distribution = _class_distribution(traffic_model, pairs[0], features, labels)
        if distribution is None:
            continue

        ip_version, min_len, modal_len = session_geometry(pairs[0])
        collected.append(
            {
                "pair": pairs[0],
                "packets": packets,
                "distribution": distribution,
                "traffic_class": ground_truth["expected"]["traffic_class"],
                "ip_version": ip_version,
                "min_len": min_len,
                "modal_len": modal_len,
                "mode": mode,
                "fold": fold,
            }
        )

    if not collected:
        return {"trained": False, "reason": "no sessions carried an operating_mode label"}

    # The baseline is what a class looks like with *no* inner header, so it is
    # fitted from transport sessions only -- and from the training fold only,
    # because a baseline that had seen the test fold's geometry would be
    # leakage of exactly the kind the configuration split exists to prevent.
    baseline = ModeBaseline.fit(
        [
            (row["traffic_class"], row["ip_version"], row["min_len"], row["modal_len"])
            for row in collected
            if row["fold"] != "test" and row["mode"] == "transport"
        ]
    )
    log.info(
        "mode baseline fitted from %d transport training sessions, %d (class, ip) cells",
        sum(1 for r in collected if r["fold"] != "test" and r["mode"] == "transport"),
        len(baseline.min_len),
    )

    rows = [
        extract_mode_features(row["pair"], row["packets"], row["distribution"], baseline).vector()
        for row in collected
    ]
    matrix = np.array(rows, dtype=np.float32)
    targets = np.array([MODE_LABELS.index(row["mode"]) for row in collected], dtype=np.int64)
    fold_array = np.array([row["fold"] for row in collected])

    train_mask = fold_array != "test"
    test_mask = fold_array == "test"
    if not train_mask.any() or not test_mask.any():
        return {
            "trained": False,
            "reason": "the split left the mode classifier a fold with no rows",
        }

    model = train_mode(matrix[train_mask], targets[train_mask], baseline=baseline)
    evaluation = evaluate_mode(model, matrix[test_mask], targets[test_mask])
    model.save(models_dir / "mode_lightgbm.txt")
    log.info("mode classifier test:\n%s", evaluation.summary())

    return {
        "trained": True,
        "sessions": len(rows),
        "test_sessions": int(test_mask.sum()),
        "feature_names": ModeFeatures.names(),
        "baseline_cells": len(baseline.min_len),
        "test": _evaluation_dict(evaluation),
    }


def _class_distribution(
    traffic_model: Any,
    pair: Any,
    features: list[str],
    labels: tuple[str, ...],
) -> dict[str, float] | None:
    """ML-1's mean predicted distribution over a session's scorable windows.

    ``None`` when the session has no window long enough to score, which leaves
    the mode classifier without its fourth feature -- so the session is skipped
    rather than fed a fabricated uniform distribution.
    """
    from analyzer.track_b.features import extract
    from analyzer.track_b.windows import MIN_WINDOW_PACKETS, window_pair

    vectors = []
    for _start, windowed in window_pair(pair):
        total = len(windowed.forward.packets) + (
            len(windowed.reverse.packets) if windowed.reverse else 0
        )
        if total < MIN_WINDOW_PACKETS:
            continue
        window_features = extract(windowed)
        vectors.append([window_features.get(name, 0.0) for name in features])

    if not vectors:
        return None
    mean = traffic_model.predict_proba(np.array(vectors, dtype=np.float32)).mean(axis=0)
    return {label: float(mean[i]) for i, label in enumerate(labels)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sessions_dir", type=Path)
    parser.add_argument("--models-dir", type=Path, default=MODELS_DIR)
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    metrics = train_all(args.sessions_dir, args.models_dir, epochs=args.epochs)
    metrics_path = args.models_dir / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    sys.stdout.write(f"metrics written to {metrics_path}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
