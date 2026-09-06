# Trained model artefacts

DVC-tracked, not git-tracked.

Each artefact ships with the version string reported in
`Assessment.model_versions`, so an assessment can always be traced back to the
exact model that produced its inferences.

## Status: empty, on purpose

**No model has been trained.** Phase 9's learned components (traffic classifier,
mode classifier, calibration) depend on Phase 8's dataset, which needs a Docker
daemon with kernel ESP to generate.

The seam is nevertheless wired end to end.
`analyzer.track_b.service.InferenceService` loads whatever is in this directory
and, finding nothing, returns `UNAVAILABLE` with `NO_MODEL_NOTE` explaining
that no classifier is installed — rather than a stub value, a random guess, or
a silently absent stage. `Assessment.model_versions` is correspondingly empty,
and the technical report's capability matrix shows those rows as unavailable.

The deterministic parts of Track B do run and do report: the cipher-family
congruence sieve (`cipher_family.py`), replay and rekey analysis
(`replay.py`), and PFS inference (`pfs.py`) are all rule-based and need no
artefact here.

Dropping trained artefacts into this directory is all that is required to light
the remaining rows up; nothing else has to change.
