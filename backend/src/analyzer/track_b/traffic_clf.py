"""Inner traffic classifier, ML-1 (LLD 7.6). Steps 9.6-9.7.

Two models over the same windows, because LLD section 7.6 asks for both and
they answer different questions:

* **LightGBM** over the tabular features (step 9.6). The baseline whose job is
  to be honest about how much of this task is just "count the packets" -- if
  the CNN cannot beat a gradient-boosted tree on rate and size statistics, the
  CNN is not earning its complexity.
* **A 1D-CNN** over the 128-length signed-size sequence, concatenated with the
  tabular features at the dense layer (step 9.7). The architecture is LLD
  section 7.6's, laid out there as a diagram and transcribed here without
  changes.

Both are trained on *windows*, and both are evaluated on folds split by
*configuration* (``windows.split_configs``). That split is the reason the
numbers here are lower than a window-level split would report, and it is the
only reason they mean anything.

Importing this module needs LightGBM and torch, which are the ``ml``
dependency group and not runtime dependencies. ``track_b/service.py`` -- what
the API actually calls -- imports neither: it reads a saved artefact. Training
is an offline activity and the offline image should not carry a tensor library
to do inference it does not do.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import numpy as np
import polars as pl

log = logging.getLogger(__name__)

RANDOM_SEED: Final = 20260906
"""Fixed everywhere a model touches randomness. A reported macro-F1 that moves
between runs is not a measurement of the model, and NFR-4 applies to the
training pipeline as much as to the engine."""

SEQUENCE_LENGTH: Final = 128
"""Matches ``features.SEQUENCE_FEATURE_LENGTH``; the CNN's input width."""


@dataclass(frozen=True, slots=True)
class Evaluation:
    """What a trained model scored, and on what.

    ``support`` is carried per class because a macro-F1 over seven classes with
    one of them holding four windows is a different claim from one where every
    class has hundreds, and the average alone hides which it is.
    """

    macro_f1: float
    accuracy: float
    per_class_f1: dict[str, float]
    support: dict[str, int]
    confusion: list[list[int]]
    labels: tuple[str, ...]

    def summary(self) -> str:
        lines = [f"macro-F1 {self.macro_f1:.4f}   accuracy {self.accuracy:.4f}"]
        for label in self.labels:
            lines.append(
                f"  {label:<14} F1 {self.per_class_f1.get(label, 0.0):.4f}"
                f"   support {self.support.get(label, 0)}"
            )
        return "\n".join(lines)


def evaluate(y_true: np.ndarray, y_pred: np.ndarray, labels: tuple[str, ...]) -> Evaluation:
    """Macro-F1, accuracy and a confusion matrix over label *indices*."""
    from sklearn.metrics import (  # type: ignore[import-untyped] # sklearn ships no py.typed marker
        confusion_matrix,
        f1_score,
    )

    indices = list(range(len(labels)))
    per_class = f1_score(y_true, y_pred, labels=indices, average=None, zero_division=0)
    return Evaluation(
        macro_f1=float(f1_score(y_true, y_pred, labels=indices, average="macro", zero_division=0)),
        accuracy=float((y_true == y_pred).mean()) if len(y_true) else 0.0,
        per_class_f1={labels[i]: float(per_class[i]) for i in indices},
        support={labels[i]: int((y_true == i).sum()) for i in indices},
        confusion=confusion_matrix(y_true, y_pred, labels=indices).tolist(),
        labels=labels,
    )


# ===========================================================================
# Matrix preparation, shared by both models
# ===========================================================================


@dataclass(frozen=True, slots=True)
class Matrices:
    """One fold's inputs, in the two shapes the two models need."""

    tabular: np.ndarray
    sequence: np.ndarray
    y: np.ndarray
    config_names: tuple[str, ...]


def label_vocabulary(frame: pl.DataFrame) -> tuple[str, ...]:
    """Class labels in a fixed order.

    Sorted rather than first-seen: the index a class gets ends up baked into a
    saved model, and an order that depended on row order would silently remap
    the classes of a model retrained on a reordered dataset.
    """
    return tuple(sorted(frame["traffic_class"].unique().to_list()))


def matrices_for(
    frame: pl.DataFrame,
    fold: str,
    *,
    feature_names: list[str],
    sequence_names: list[str],
    labels: tuple[str, ...],
) -> Matrices:
    subset = frame.filter(pl.col("fold") == fold)
    index = {label: i for i, label in enumerate(labels)}
    return Matrices(
        tabular=subset.select(feature_names).to_numpy().astype(np.float32),
        sequence=subset.select(sequence_names).to_numpy().astype(np.float32),
        y=np.array([index[value] for value in subset["traffic_class"].to_list()], dtype=np.int64),
        config_names=tuple(subset["config_name"].to_list()),
    )


# ===========================================================================
# Step 9.6: the LightGBM baseline
# ===========================================================================


@dataclass
class LightGbmModel:
    """A trained LightGBM classifier plus everything needed to reuse it."""

    booster: Any
    feature_names: list[str]
    labels: tuple[str, ...]
    params: dict[str, Any] = field(default_factory=dict)

    def predict_proba(self, tabular: np.ndarray) -> np.ndarray:
        """Class probabilities, always ``(n_rows, n_classes)``.

        LightGBM collapses a zero-row input to a 1-D array, which every caller
        then indexes as if it were 2-D. Reshaping here rather than guarding at
        each call site means an empty fold -- which a small dataset really does
        produce -- flows through the pipeline as an empty result instead of an
        IndexError several layers away.
        """
        raw = np.asarray(self.booster.predict(tabular), dtype=np.float64)
        if raw.ndim == 1:
            return raw.reshape(len(tabular), len(self.labels))
        return raw

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.booster.save_model(str(path))
        path.with_suffix(".meta.json").write_text(
            json.dumps(
                {"feature_names": self.feature_names, "labels": list(self.labels), **self.params},
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: Path) -> LightGbmModel:
        import lightgbm as lgb

        meta = json.loads(path.with_suffix(".meta.json").read_text(encoding="utf-8"))
        return cls(
            booster=lgb.Booster(model_file=str(path)),
            feature_names=list(meta["feature_names"]),
            labels=tuple(meta["labels"]),
        )


def train_lightgbm(
    train: Matrices,
    validation: Matrices | None,
    *,
    feature_names: list[str],
    labels: tuple[str, ...],
    num_boost_round: int = 400,
) -> LightGbmModel:
    """Step 9.6's baseline: LightGBM over the tabular features, 7 classes.

    ``deterministic`` and a fixed seed because two training runs over one
    dataset must produce one model. LightGBM is otherwise free to vary with
    thread scheduling, which would make a committed score unreproducible for
    the most boring possible reason.
    """
    import lightgbm as lgb

    params: dict[str, Any] = {
        "objective": "multiclass",
        "num_class": len(labels),
        "metric": "multi_logloss",
        "learning_rate": 0.05,
        "num_leaves": 31,
        "min_data_in_leaf": 20,
        "feature_fraction": 0.9,
        "bagging_fraction": 0.9,
        "bagging_freq": 1,
        "seed": RANDOM_SEED,
        "deterministic": True,
        "force_row_wise": True,
        "verbosity": -1,
    }

    train_set = lgb.Dataset(train.tabular, label=train.y, feature_name=feature_names)
    valid_sets = []
    callbacks: list[Any] = []
    if validation is not None and len(validation.y):
        valid_sets.append(lgb.Dataset(validation.tabular, label=validation.y, reference=train_set))
        callbacks.append(lgb.early_stopping(50, verbose=False))

    booster = lgb.train(
        params,
        train_set,
        num_boost_round=num_boost_round,
        valid_sets=valid_sets or None,
        callbacks=callbacks or None,
    )
    return LightGbmModel(
        booster=booster,
        feature_names=feature_names,
        labels=labels,
        params={"num_boost_round": num_boost_round, "seed": RANDOM_SEED},
    )


# ===========================================================================
# Step 9.7: the 1D-CNN of LLD section 7.6
# ===========================================================================


def build_cnn(n_tabular: int, n_classes: int) -> Any:
    """LLD section 7.6's architecture, transcribed.

    Conv1D(64,5) -> BN -> ReLU -> Conv1D(64,5) -> BN -> ReLU -> MaxPool(2) ->
    Conv1D(128,3) -> BN -> ReLU -> GlobalMaxPool, concatenated with the tabular
    features into Dense(128) -> Dropout(0.3) -> Dense(n_classes).

    The softmax is *not* in the module: it returns logits, because both the
    training loss (``CrossEntropyLoss``) and the temperature scaling of step 9.8
    are defined on logits, and a model that softmaxed internally would have to
    have it undone in both places.
    """
    import torch
    from torch import nn

    class TrafficCnn(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.conv = nn.Sequential(
                nn.Conv1d(1, 64, kernel_size=5, padding=2),
                nn.BatchNorm1d(64),
                nn.ReLU(),
                nn.Conv1d(64, 64, kernel_size=5, padding=2),
                nn.BatchNorm1d(64),
                nn.ReLU(),
                nn.MaxPool1d(2),
                nn.Conv1d(64, 128, kernel_size=3, padding=1),
                nn.BatchNorm1d(128),
                nn.ReLU(),
                nn.AdaptiveMaxPool1d(1),
            )
            self.head = nn.Sequential(
                nn.Linear(128 + n_tabular, 128),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(128, n_classes),
            )

        def forward(self, sequence: Any, tabular: Any) -> Any:
            conv = self.conv(sequence.unsqueeze(1)).squeeze(-1)
            return self.head(torch.cat([conv, tabular], dim=1))

    return TrafficCnn()


@dataclass
class CnnModel:
    """A trained CNN plus the normalisation its inputs were fitted with."""

    module: Any
    feature_names: list[str]
    labels: tuple[str, ...]
    tabular_mean: np.ndarray
    tabular_std: np.ndarray
    sequence_scale: float

    def _prepare(self, tabular: np.ndarray, sequence: np.ndarray) -> tuple[Any, Any]:
        import torch

        normalised = (tabular - self.tabular_mean) / self.tabular_std
        return (
            torch.from_numpy((sequence / self.sequence_scale).astype(np.float32)),
            torch.from_numpy(normalised.astype(np.float32)),
        )

    def logits(self, tabular: np.ndarray, sequence: np.ndarray) -> np.ndarray:
        import torch

        self.module.eval()
        with torch.no_grad():
            seq_t, tab_t = self._prepare(tabular, sequence)
            return np.asarray(self.module(seq_t, tab_t).numpy(), dtype=np.float64)

    def predict_proba(self, tabular: np.ndarray, sequence: np.ndarray) -> np.ndarray:
        logits = self.logits(tabular, sequence)
        shifted = logits - logits.max(axis=1, keepdims=True)
        exp = np.exp(shifted)
        return np.asarray(exp / exp.sum(axis=1, keepdims=True), dtype=np.float64)

    def save(self, path: Path) -> None:
        import torch

        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "state_dict": self.module.state_dict(),
                "feature_names": self.feature_names,
                "labels": list(self.labels),
                "tabular_mean": self.tabular_mean,
                "tabular_std": self.tabular_std,
                "sequence_scale": self.sequence_scale,
            },
            path,
        )


def train_cnn(
    train: Matrices,
    validation: Matrices | None,
    *,
    feature_names: list[str],
    labels: tuple[str, ...],
    epochs: int = 60,
    batch_size: int = 64,
    learning_rate: float = 1e-3,
) -> CnnModel:
    """Train the CNN, keeping the epoch that scored best on *validation*.

    Best-epoch selection uses the calibration fold rather than the test fold.
    Choosing an epoch by test macro-F1 is model selection on the test set: the
    reported number stops being held out at the moment it decides something.
    """
    import torch
    from torch import nn

    torch.manual_seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)
    torch.use_deterministic_algorithms(True)

    mean = train.tabular.mean(axis=0)
    std = train.tabular.std(axis=0)
    std[std == 0] = 1.0
    scale = float(np.abs(train.sequence).max()) or 1.0

    module = build_cnn(n_tabular=train.tabular.shape[1], n_classes=len(labels))
    model = CnnModel(
        module=module,
        feature_names=feature_names,
        labels=labels,
        tabular_mean=mean,
        tabular_std=std,
        sequence_scale=scale,
    )

    seq_t, tab_t = model._prepare(train.tabular, train.sequence)
    y_t = torch.from_numpy(train.y)

    # Class weights, because the window count per class follows the traffic
    # rate: one file-transfer session produces far more packets, and therefore
    # far more scorable windows, than one messaging session of equal length.
    # Unweighted, the loss would treat that accident of bitrate as a prior.
    counts = np.bincount(train.y, minlength=len(labels)).astype(np.float64)
    weights = np.divide(
        counts.sum(), counts * len(labels), out=np.ones_like(counts), where=counts > 0
    )
    criterion = nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float32))
    optimiser = torch.optim.Adam(module.parameters(), lr=learning_rate)

    generator = torch.Generator().manual_seed(RANDOM_SEED)
    dataset = torch.utils.data.TensorDataset(seq_t, tab_t, y_t)
    loader = torch.utils.data.DataLoader(
        dataset, batch_size=batch_size, shuffle=True, generator=generator
    )

    best_score = -1.0
    best_state: dict[str, Any] | None = None
    for epoch in range(1, epochs + 1):
        module.train()
        total = 0.0
        for seq_b, tab_b, y_b in loader:
            optimiser.zero_grad()
            loss = criterion(module(seq_b, tab_b), y_b)
            loss.backward()
            optimiser.step()
            total += float(loss.item()) * len(y_b)

        if validation is None or not len(validation.y):
            best_state = {k: v.clone() for k, v in module.state_dict().items()}
            continue

        predictions = model.predict_proba(validation.tabular, validation.sequence).argmax(axis=1)
        score = evaluate(validation.y, predictions, labels).macro_f1
        if score > best_score:
            best_score = score
            best_state = {k: v.clone() for k, v in module.state_dict().items()}
        log.info("epoch %d: loss %.4f, validation macro-F1 %.4f", epoch, total / len(y_t), score)

    if best_state is not None:
        module.load_state_dict(best_state)
    return model
