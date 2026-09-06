"""External validation on ISCXVPN2016. Step 9.12.

``python -m analyzer.track_b.external_eval <iscx-dir>`` scores the trained
traffic classifier on captures this project did not generate, and writes the
result next to the model.

**Step 9.12's instruction is "report the gap; do not hide it", and the design
here follows from that.** The internal test score and the external score are
reported side by side with their difference computed, so a reader cannot see
one without the other. A model that scores 0.9 on the testbed and 0.4 on
ISCXVPN2016 has learned the testbed, and that sentence should be readable off
the output rather than reconstructable from it.

**What this measurement can and cannot mean.** ISCXVPN2016 is not IPsec -- its
"VPN" captures are OpenVPN over UDP and the rest is plaintext (see
``dataset/iscx.py``, which explains the two substitutions that make the schemas
line up at all). Two consequences, both of which shape what is scored:

1. The 19 ESP-geometry features measure a padding rule these captures do not
   have. Scoring over them would compare a model's reading of real ESP
   geometry against zeros, and the resulting drop would say nothing about
   generalisation. ``comparable_feature_names`` removes them and this
   evaluation runs on the 55 that transfer, with the removed columns held at
   the *training mean* rather than zero -- zero is a measurement here, and a
   meaningful one, so feeding it would be asserting "perfectly padded" for
   every external flow.
2. Whole flows are scored, not 10-second windows. The adapter produces one
   feature vector per flow, and re-windowing captures whose timing has already
   been reshaped by a different tunnel would add a second approximation on top
   of the first.

Both are recorded in the output document. An external number without them is
not interpretable.
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

from analyzer.core.enums import TrafficClass
from analyzer.dataset.iscx import ExternalFlow, adapt_directory, comparable_feature_names
from analyzer.track_b.traffic_clf import LightGbmModel, evaluate

log = logging.getLogger(__name__)


def evaluate_external(
    model: LightGbmModel,
    iscx_dir: Path,
    *,
    training_means: dict[str, float] | None = None,
    tunnelled_only: bool = False,
) -> dict[str, Any]:
    """Score *model* on the adapted ISCXVPN2016 captures under *iscx_dir*."""
    batch = adapt_directory(iscx_dir)
    comparable = set(comparable_feature_names(model.feature_names))
    substituted = [name for name in model.feature_names if name not in comparable]
    means = training_means or {}

    # ``batch.labelled`` is already the subset whose filenames mapped to a
    # class, so ``label`` is not None here -- narrowed explicitly rather than
    # asserted, because an unmapped flow scored against an arbitrary class
    # would be label noise in the one evaluation whose purpose is to be trusted.
    #
    # A corpus can hold a class this model was never trained to predict. Those
    # flows are counted and set aside rather than scored: a class with no output
    # neuron cannot be got right, and leaving them in would charge the model for
    # failing a question it was never asked. Reported, because a large count
    # means the external score covers less of the corpus than it appears to.
    vocabulary = set(model.labels)
    labelled: list[tuple[ExternalFlow, TrafficClass]] = []
    untrained: dict[str, int] = {}
    for flow in batch.labelled:
        if flow.label is None or (tunnelled_only and not flow.tunnelled):
            continue
        if flow.label.value not in vocabulary:
            untrained[flow.label.value] = untrained.get(flow.label.value, 0) + 1
            continue
        labelled.append((flow, flow.label))
    flows = [flow for flow, _ in labelled]
    if not flows:
        return {
            "scored": False,
            "reason": (
                "no captures in this directory mapped to a traffic class this model "
                "was trained to predict"
            ),
            "labels_not_in_model": untrained,
            "unmapped": len(batch.unmapped),
            "unreadable": len(batch.unreadable),
            "empty": len(batch.empty),
        }

    rows = []
    for flow in flows:
        rows.append(
            [
                flow.vector.get(name, 0.0) if name in comparable else means.get(name, 0.0)
                for name in model.feature_names
            ]
        )
    matrix = np.array(rows, dtype=np.float32)

    index = {label: i for i, label in enumerate(model.labels)}
    y = np.array([index[label.value] for _, label in labelled], dtype=np.int64)
    predictions = model.predict_proba(matrix).argmax(axis=1)
    evaluation = evaluate(y, predictions, model.labels)

    document = asdict(evaluation)
    document["labels"] = list(evaluation.labels)
    return {
        "scored": True,
        "flows": len(flows),
        "tunnelled_only": tunnelled_only,
        "comparable_features": len(comparable),
        "substituted_features": substituted,
        "substitution": (
            "ESP-geometry features are held at the training mean, not zero: zero "
            "is a real and meaningful measurement for these columns and feeding "
            "it would assert a perfectly padded tunnel for every external flow"
        ),
        "labels_not_in_model": untrained,
        "unmapped": len(batch.unmapped),
        "unreadable": len(batch.unreadable),
        "empty": len(batch.empty),
        "evaluation": document,
    }


def report(internal_macro_f1: float, external: dict[str, Any]) -> dict[str, Any]:
    """Put the internal and external scores next to each other, with the gap.

    Step 9.12: "report the gap; do not hide it". Computing the difference here
    rather than leaving it to the reader means a regression in generalisation
    shows up as a number that got bigger, not as two numbers someone has to
    think about.
    """
    if not external.get("scored"):
        return {"internal_macro_f1": internal_macro_f1, "external": external, "gap": None}

    external_macro_f1 = float(external["evaluation"]["macro_f1"])
    return {
        "internal_macro_f1": internal_macro_f1,
        "external_macro_f1": external_macro_f1,
        "gap": internal_macro_f1 - external_macro_f1,
        "interpretation": (
            "The gap is the drop from this project's own testbed to captures it "
            "did not generate. A large gap means the model has learned the "
            "testbed's generators rather than the traffic classes; a small one "
            "is weak evidence of generalisation, weak because ISCXVPN2016 is "
            "OpenVPN and plaintext rather than IPsec and only 55 of the "
            "features transfer at all."
        ),
        "external": external,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("iscx_dir", type=Path)
    parser.add_argument("--models-dir", type=Path, default=Path("models"))
    parser.add_argument(
        "--tunnelled-only",
        action="store_true",
        help="score only the vpn_* captures, which are the nearest analogue to a tunnel",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    model_path = args.models_dir / "traffic_lightgbm.txt"
    if not model_path.exists():
        sys.stderr.write(f"no trained model at {model_path}; run track_b.train first\n")
        return 1
    model = LightGbmModel.load(model_path)

    metrics_path = args.models_dir / "metrics.json"
    internal = 0.0
    training_means: dict[str, float] = {}
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        internal = float(metrics.get("lightgbm", {}).get("test", {}).get("macro_f1", 0.0))
        training_means = dict(metrics.get("training_feature_means", {}))

    external = evaluate_external(
        model, args.iscx_dir, training_means=training_means, tunnelled_only=args.tunnelled_only
    )
    document = report(internal, external)

    out_path = args.models_dir / "external_validation.json"
    out_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    sys.stdout.write(json.dumps(document, indent=2) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
