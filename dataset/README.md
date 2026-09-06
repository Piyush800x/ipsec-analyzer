# Dataset

Labelled IPsec sessions produced by the testbed. Each session ships as
`capture.pcap` plus `labels.json` recording the full ground-truth configuration
and traffic label (PRD §9.3). PCAPs are DVC-tracked, not git-tracked.

[dataset.md](dataset.md) is the reference: schema, generation method, splitting
rules, and licence. Read it before training anything — in particular the rule
that splits go **by configuration and session, never by window**, which is the
one mistake that produces a beautiful held-out score and a worthless model.

## Generating it

```bash
cd backend
docker build -f testbed/Dockerfile.peer -t ipsec-testbed-peer:0.1.0 testbed/
uv run python -m testbed.batch ../dataset/sessions
```

See [backend/testbed/README.md](../backend/testbed/README.md) for the kernel
XFRM requirements and the resume behaviour.

## Verifying it

Every batch must pass the label-verification harness before it is used for
training. It replays Track A over each capture and compares against
`labels.json`:

```bash
uv run python -m testbed.verify ../dataset/sessions
```

It classifies each field into six outcomes rather than a pass/fail, because
several of them are correct answers that a two-state harness would score as
failures — `honest_gap` (the parser reported `UNAVAILABLE` for a field
`labels.json` lists under `not_observable_from_ike`) and `inferred` (the parser
reported a value with `INFERRED` provenance, which is unscored). Only
`mismatch` and `fabricated` are defects.

## The external set

`analyzer.dataset.iscx` (step 8.5) adapts ISCXVPN2016 into the same feature
schema, for the cross-validation of step 9.12:

```python
from pathlib import Path
from analyzer.dataset import iscx

batch = iscx.adapt_directory(Path("dataset/iscxvpn2016"))
print(len(batch.labelled), "labelled flows")
print(batch.unmapped, batch.unreadable, batch.empty)   # always look at these
```

**Do not score on all 74 columns.** ISCXVPN2016 is OpenVPN and plaintext, not
IPsec, so the 19 ESP-geometry features measure a padding rule those captures do
not have. `iscx.comparable_feature_names()` returns the 55 that transfer. The
module docstring explains both substitutions the adapter makes and what each
costs; read it before quoting a number from it.

## Status

**Not yet generated.** Sessions require a Docker daemon with kernel ESP; see
the Phase 8 entry in [CHANGELOG.md](../CHANGELOG.md) for what has and has not
been demonstrated. The ISCXVPN2016 adapter is written and tested against
synthetic captures, but no capture from the real corpus has been through it.
