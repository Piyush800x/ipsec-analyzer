# Trained model artefacts

**Committed to git, not DVC.** All 3.3 MB of what inference loads is in the
repository, so a clone works immediately: `uv sync && uv run uvicorn ...` gives
you a running analyser with Track B's classifiers live, no training and no
14 GB dataset required.

DVC is the right home for model weights and this project's docs describe it as
such, but no DVC remote is configured. Ignoring the artefacts on that basis
would mean every teammate's checkout silently loses Track B to `UNAVAILABLE`
with no way to recover it short of regenerating the dataset. A few megabytes in
git beats a broken checkout.

`traffic_cnn.pt` is the exception and stays out: inference loads LightGBM, not
the CNN (see below), so the checkpoint is a training artefact no deployment
reads. Retrain to reproduce it.

Each artefact ships with the version string reported in
`Assessment.model_versions`, so an assessment can always be traced back to the
exact model that produced its inferences. That string is a SHA-256 of the file's
own bytes rather than a label written beside it — a hash cannot fall out of step
with the thing it names.

## What lives here

| File | What it is |
|---|---|
| `traffic_lightgbm.txt` | ML-1, the LightGBM traffic classifier (step 9.6). **This is what inference loads.** |
| `traffic_lightgbm.meta.json` | its feature order and label order — both part of the artefact's contract |
| `traffic_cnn.pt` | ML-1, the 1D-CNN of LLD §7.6 (step 9.7) |
| `mode_lightgbm.txt` | ML-2, tunnel vs transport (step 9.9) |
| `calibration.json` | the CNN's temperature and the LightGBM isotonic knots (step 9.8) |
| `reliability_cnn.json` | the reliability diagram's data |
| `metrics.json` | everything the training run measured, on the held-out fold |
| `external_validation.json` | ISCXVPN2016 results, when that corpus is available |

## Why inference loads the tree model and not the CNN

The CNN is the stronger model on paper, and `metrics.json` records both scores
so the comparison is visible rather than asserted. Inference still loads
LightGBM, for two reasons that matter more than the gap between them:

- Loading the CNN would make **torch a runtime dependency** of the API and of
  the offline image (step 11.4). Two hundred megabytes of tensor library, in an
  air-gapped image, to do inference that a 2 MB tree ensemble does.
- LightGBM gives **exact TreeSHAP** attributions through `pred_contrib=True`.
  The CNN can only be attributed by occlusion, which is an approximation. FR-4.10
  asks for the explanation, and one of these two can actually give it.

## Regenerating

```bash
cd backend
uv sync --group ml                                   # LightGBM, torch, scikit-learn
uv run python -m analyzer.track_b.train ../dataset/sessions
uv run python -m analyzer.track_b.model_card         # writes docs/model-card.md
uv run python -m analyzer.track_b.external_eval <iscx-dir>   # step 9.12, needs the corpus
```

Training is deterministic: fixed seeds throughout and `deterministic: true` in
the LightGBM parameters, because a reported macro-F1 that moves between runs is
not a measurement of the model. NFR-4 applies to the training pipeline as much
as it does to the assessment engine.

## An empty directory is a supported state, not a broken one

`analyzer.track_b.service.InferenceService` loads whatever is here and, finding
nothing, returns `UNAVAILABLE` with `NO_MODEL_NOTE` explaining that no classifier
is installed — rather than a stub value, a random guess, or a silently absent
stage. `Assessment.model_versions` is correspondingly empty, and the technical
report's capability matrix shows those rows as unavailable.

That is not a placeholder awaiting removal. A deployment handed the code and not
the artefacts runs in it permanently, and it has to produce a complete, correct
assessment that is honest about what it could not determine. The deterministic
half of Track B — the cipher-family sieve, replay and rekey analysis, PFS
inference — is rule-based and runs either way.
