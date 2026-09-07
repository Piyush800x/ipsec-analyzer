"""SHAP feature attribution for a prediction. Step 9.10, FR-4.10.

An inferred traffic class costs the deployment points on the metadata-exposure
component of the score (PRD section 10), so it has to be arguable rather than
oracular: an analyst who disagrees needs to see which measurements produced the
answer. This module turns one prediction into the five features that moved it
most, as ``FeatureAttribution`` objects the report renders directly.

**Exact TreeSHAP, from LightGBM itself.** ``Booster.predict(pred_contrib=True)``
returns the Shapley values for a tree ensemble exactly, by the TreeSHAP
algorithm -- the same computation the ``shap`` package performs for this model
family, without the dependency. That matters practically here: ``shap`` pulls
numba and llvmlite, which do not resolve against this project's numpy on Python
3.11, and it would have been a large dependency added to get a number LightGBM
already computes.

The CNN gets attribution over its *tabular* half only, by occlusion: each
feature is set to the training mean in turn and the change in the predicted
class's logit is the contribution. This is an approximation of a Shapley value
rather than the exact thing, and ``cnn_attribution`` says so in its return --
LLD makes no claim about attributing the convolutional half, and pretending a
single-feature occlusion is TreeSHAP would be dressing up a weaker method with
a stronger method's name.
"""

from __future__ import annotations

from typing import Any, Final

import numpy as np

from analyzer.core.schema import FeatureAttribution

TOP_FEATURES: Final = 5
"""Step 9.10: "a prediction returns its top five contributing features"."""


def _attributions(
    contributions: np.ndarray,
    values: np.ndarray,
    feature_names: list[str],
    *,
    top: int,
) -> list[FeatureAttribution]:
    """The *top* features by absolute contribution, largest first.

    Ranked on absolute value but reported with the sign intact: "this feature
    pushed hard *against* the predicted label" is as much of an explanation as
    the reverse, and dropping the sign would leave a reader unable to tell the
    two apart.
    """
    order = np.argsort(-np.abs(contributions))[:top]
    return [
        FeatureAttribution(
            feature=feature_names[i],
            contribution=float(contributions[i]),
            observed_value=float(values[i]),
        )
        for i in order
    ]


def lightgbm_attribution(
    model: Any,
    tabular: np.ndarray,
    *,
    class_index: int,
    top: int = TOP_FEATURES,
) -> list[FeatureAttribution]:
    """Exact TreeSHAP values for one row, for the predicted class.

    ``pred_contrib=True`` returns ``n_features + 1`` columns per class, the last
    being the expected-value base term. That base is dropped: it is the model's
    prior, identical for every prediction, and including it as a "feature" would
    put a constant at the top of most explanations.
    """
    contributions = np.asarray(
        model.booster.predict(tabular.reshape(1, -1), pred_contrib=True), dtype=np.float64
    )
    n_features = len(model.feature_names)
    n_classes = len(model.labels)

    if contributions.shape[1] == (n_features + 1) * n_classes:
        start = class_index * (n_features + 1)
        row = contributions[0, start : start + n_features]
    else:
        # Binary objective: one block of contributions towards class 1. Class 0
        # is the same evidence read the other way, so the sign is flipped rather
        # than the row being reported as if it argued for the predicted class.
        row = contributions[0, :n_features]
        if class_index == 0:
            row = -row

    return _attributions(row, tabular, model.feature_names, top=top)


def cnn_attribution(
    model: Any,
    tabular: np.ndarray,
    sequence: np.ndarray,
    *,
    class_index: int,
    top: int = TOP_FEATURES,
) -> list[FeatureAttribution]:
    """Occlusion attribution over the CNN's tabular inputs. An approximation.

    Each feature is replaced by the training-set mean -- the model's own notion
    of "uninformative", which it was normalised against -- and the drop in the
    predicted class's logit is that feature's contribution. Single-feature
    occlusion ignores interactions, so it is not a Shapley value and is not
    claimed as one; it is the honest thing available without adding a dependency
    that will not install.

    The sequence half is not attributed. A per-timestep saliency over 128
    packet sizes is not something a report can render usefully, and LLD asks for
    named features.
    """
    baseline_logit = model.logits(tabular.reshape(1, -1), sequence.reshape(1, -1))[0, class_index]

    contributions = np.zeros(len(model.feature_names), dtype=np.float64)
    for index in range(len(model.feature_names)):
        occluded = tabular.copy()
        occluded[index] = model.tabular_mean[index]
        logit = model.logits(occluded.reshape(1, -1), sequence.reshape(1, -1))[0, class_index]
        contributions[index] = float(baseline_logit - logit)

    return _attributions(contributions, tabular, model.feature_names, top=top)
