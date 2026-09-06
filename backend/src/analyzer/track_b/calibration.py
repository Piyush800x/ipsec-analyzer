"""Confidence calibration (LLD 7.6, PRD 8.3). Step 9.8.

PRD section 8.3 is the reason this module exists, and it is not about accuracy.
A model that is 90% accurate while reporting 0.99 on everything it says is a
model whose confidences cannot be used for anything -- and this project puts
those confidences in a security report next to the word INFERRED, where an
analyst is entitled to read 0.9 as "wrong about one in ten". Calibration is
what makes that reading true.

Two methods, per LLD section 7.6:

* **Temperature scaling** for the CNN. One scalar dividing the logits, fitted
  by minimising NLL on the calibration fold. It cannot change any prediction --
  dividing every logit by the same positive number leaves the argmax alone --
  so it costs no accuracy and only moves the confidences. That property is why
  it is the right tool: a calibration step that also changed answers would make
  the accuracy figure conditional on it.
* **Isotonic regression** for LightGBM, via ``CalibratedClassifierCV``'s
  underlying fit. Trees produce piecewise-constant, badly-shaped probabilities
  that a single scalar cannot fix.

Both are fitted on the *calibration* fold, which ``windows.split_configs``
keeps disjoint from train and test. Fitting on train inherits the training
fold's overconfidence and measures nothing; fitting on test makes ECE a
training metric and the number stops being held out.

**ECE** here is the standard equal-width binned estimator over the predicted
top-class probability. Reported alongside accuracy in every evaluation, per
LLD section 7.6.
"""

from __future__ import annotations

import itertools
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import numpy as np

log = logging.getLogger(__name__)

ECE_BINS: Final = 10
"""Equal-width bins over [0, 1]. Ten is the convention the ECE numbers in the
literature use, and PRD section 8.4's 0.10 threshold is stated against it."""

MAX_TEMPERATURE_STEPS: Final = 200


def expected_calibration_error(
    probabilities: np.ndarray, y_true: np.ndarray, *, bins: int = ECE_BINS
) -> float:
    """Weighted mean gap between confidence and accuracy, per confidence bin.

    Only the top-class probability is binned. That is the quantity a reader
    acts on -- "the model says video, 0.82" -- and it is what PRD section 8.4's
    threshold is about.
    """
    if not len(y_true):
        return 0.0
    confidence = probabilities.max(axis=1)
    predicted = probabilities.argmax(axis=1)
    correct = (predicted == y_true).astype(np.float64)

    edges = np.linspace(0.0, 1.0, bins + 1)
    total = 0.0
    for lower, upper in itertools.pairwise(edges):
        # Upper-inclusive on the last bin only, so a confidence of exactly 1.0
        # lands somewhere rather than being dropped from the average.
        in_bin = (
            (confidence > lower) & (confidence <= upper)
            if upper < 1.0
            else ((confidence > lower) & (confidence <= 1.0))
        )
        count = int(in_bin.sum())
        if not count:
            continue
        total += (count / len(y_true)) * abs(correct[in_bin].mean() - confidence[in_bin].mean())
    return float(total)


def reliability_bins(
    probabilities: np.ndarray, y_true: np.ndarray, *, bins: int = ECE_BINS
) -> list[dict[str, float]]:
    """The reliability diagram's data, as rows.

    Returned as data rather than drawn as an image: step 9.8 wants a diagram in
    the docs, and a table of (confidence, accuracy, count) can be rendered into
    one and also read directly, which a PNG cannot.
    """
    if not len(y_true):
        return []
    confidence = probabilities.max(axis=1)
    correct = (probabilities.argmax(axis=1) == y_true).astype(np.float64)
    edges = np.linspace(0.0, 1.0, bins + 1)

    rows = []
    for lower, upper in itertools.pairwise(edges):
        in_bin = (
            (confidence > lower) & (confidence <= upper)
            if upper < 1.0
            else ((confidence > lower) & (confidence <= 1.0))
        )
        count = int(in_bin.sum())
        rows.append(
            {
                "bin_lower": float(lower),
                "bin_upper": float(upper),
                "count": count,
                "mean_confidence": float(confidence[in_bin].mean()) if count else 0.0,
                "accuracy": float(correct[in_bin].mean()) if count else 0.0,
            }
        )
    return rows


# ===========================================================================
# Temperature scaling, for the CNN
# ===========================================================================


@dataclass(frozen=True, slots=True)
class Temperature:
    """One scalar, and what it did to the calibration fold's ECE."""

    value: float
    ece_before: float
    ece_after: float

    def apply(self, logits: np.ndarray) -> np.ndarray:
        scaled = logits / self.value
        shifted = scaled - scaled.max(axis=1, keepdims=True)
        exp = np.exp(shifted)
        return np.asarray(exp / exp.sum(axis=1, keepdims=True), dtype=np.float64)


def fit_temperature(logits: np.ndarray, y_true: np.ndarray) -> Temperature:
    """Fit one temperature by minimising NLL with LBFGS on the calibration fold.

    ``log_temperature`` is the free parameter rather than the temperature
    itself, so the optimiser cannot walk into a zero or negative value --
    which would flip the logits' order and turn calibration into a different
    classifier.
    """
    import torch

    if not len(y_true):
        log.warning("the calibration fold is empty; leaving the CNN uncalibrated (T=1.0)")
        return Temperature(value=1.0, ece_before=0.0, ece_after=0.0)

    def softmax(values: np.ndarray) -> np.ndarray:
        shifted = values - values.max(axis=1, keepdims=True)
        exp = np.exp(shifted)
        return np.asarray(exp / exp.sum(axis=1, keepdims=True), dtype=np.float64)

    before = expected_calibration_error(softmax(logits), y_true)

    logits_t = torch.from_numpy(logits.astype(np.float32))
    y_t = torch.from_numpy(y_true.astype(np.int64))
    log_temperature = torch.zeros(1, requires_grad=True)
    optimiser = torch.optim.LBFGS([log_temperature], lr=0.1, max_iter=MAX_TEMPERATURE_STEPS)
    criterion = torch.nn.CrossEntropyLoss()

    def closure() -> Any:
        optimiser.zero_grad()
        loss = criterion(logits_t / log_temperature.exp(), y_t)
        loss.backward()
        return loss

    optimiser.step(closure)  # type: ignore[no-untyped-call] # torch ships LBFGS.step untyped; the closure form is its documented API

    value = float(log_temperature.exp().item())
    after = expected_calibration_error(softmax(logits / value), y_true)
    log.info("temperature %.4f: ECE %.4f -> %.4f", value, before, after)
    return Temperature(value=value, ece_before=before, ece_after=after)


# ===========================================================================
# Isotonic regression, for LightGBM
# ===========================================================================


@dataclass
class IsotonicCalibrator:
    """One isotonic regressor per class, renormalised to a distribution.

    One-vs-rest is what ``CalibratedClassifierCV`` does internally for a
    multiclass estimator, done explicitly here because the LightGBM model is a
    raw ``Booster`` rather than a scikit-learn estimator and wrapping it just to
    unwrap it again would obscure what is fitted on what.

    Isotonic regression is monotonic per class but not jointly normalised, so
    the outputs are divided by their sum. Rows where every class calibrates to
    zero fall back to the uncalibrated distribution rather than to a uniform
    one, because a uniform row would be a *fabricated* "no idea" replacing a
    real, if badly scaled, opinion.
    """

    regressors: list[Any]
    ece_before: float
    ece_after: float

    def knots(self) -> list[dict[str, list[float]]]:
        """The fitted step functions as (x, y) breakpoints, one set per class.

        Exported so inference can apply the calibration without scikit-learn.
        ``IsotonicRegression.predict`` is linear interpolation between these
        points with the ends clipped, which ``apply_knots`` reproduces in a few
        lines of numpy -- and that keeps a 40 MB dependency out of the offline
        image for what is, once fitted, a lookup table.
        """
        return [
            {
                "x": [float(v) for v in regressor.X_thresholds_],
                "y": [float(v) for v in regressor.y_thresholds_],
            }
            for regressor in self.regressors
        ]

    def apply(self, probabilities: np.ndarray) -> np.ndarray:
        if not self.regressors or not len(probabilities):
            return np.asarray(probabilities, dtype=np.float64)
        calibrated = np.column_stack(
            [regressor.predict(probabilities[:, i]) for i, regressor in enumerate(self.regressors)]
        )
        totals = calibrated.sum(axis=1, keepdims=True)
        safe = totals.squeeze(-1) > 0
        result = probabilities.astype(np.float64).copy()
        result[safe] = calibrated[safe] / totals[safe]
        return result


def fit_isotonic(
    probabilities: np.ndarray, y_true: np.ndarray, n_classes: int
) -> IsotonicCalibrator:
    """Fit one isotonic regressor per class on the calibration fold.

    An empty calibration fold returns an identity calibrator rather than
    raising. A dataset small enough for the stratified split to leave that fold
    empty is a real state -- a pilot batch, or a class with two configurations
    -- and the right response is an uncalibrated model whose metrics say it is
    uncalibrated, not a crashed training run.
    """
    if not len(y_true):
        log.warning("the calibration fold is empty; leaving LightGBM uncalibrated")
        return IsotonicCalibrator(regressors=[], ece_before=0.0, ece_after=0.0)
    from sklearn.isotonic import (  # type: ignore[import-untyped] # sklearn ships no py.typed marker
        IsotonicRegression,
    )

    before = expected_calibration_error(probabilities, y_true)
    regressors = []
    for index in range(n_classes):
        regressor = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        target = (y_true == index).astype(np.float64)
        if len(np.unique(target)) < 2:
            # A class absent from the calibration fold: fit the identity rather
            # than a constant, so this class's probabilities pass through
            # untouched instead of being flattened to whatever single value the
            # regressor saw.
            regressor.fit(np.array([0.0, 1.0]), np.array([0.0, 1.0]))
        else:
            regressor.fit(probabilities[:, index], target)
        regressors.append(regressor)

    calibrator = IsotonicCalibrator(regressors=regressors, ece_before=before, ece_after=before)
    after = expected_calibration_error(calibrator.apply(probabilities), y_true)
    log.info("isotonic: ECE %.4f -> %.4f", before, after)
    return IsotonicCalibrator(regressors=regressors, ece_before=before, ece_after=after)


def write_reliability(path: Path, rows: list[dict[str, float]], *, title: str) -> None:
    """Write a reliability diagram's data next to the model that produced it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"title": title, "bins": rows}, indent=2), encoding="utf-8")


def apply_knots(probabilities: np.ndarray, knots: list[dict[str, list[float]]]) -> np.ndarray:
    """Apply exported isotonic knots without scikit-learn.

    ``np.interp`` clamps outside the fitted range, which is what
    ``IsotonicRegression(out_of_bounds="clip")`` does, so this reproduces
    ``IsotonicCalibrator.apply`` exactly rather than approximating it --
    asserted in ``tests/test_track_b_dataset.py``.
    """
    if not knots:
        return probabilities
    calibrated = np.column_stack(
        [
            np.interp(probabilities[:, i], knot["x"], knot["y"])
            for i, knot in enumerate(knots[: probabilities.shape[1]])
        ]
    )
    totals = calibrated.sum(axis=1, keepdims=True)
    safe = totals.squeeze(-1) > 0
    result = probabilities.astype(np.float64).copy()
    result[safe] = calibrated[safe] / totals[safe]
    return result
