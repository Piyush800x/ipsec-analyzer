# Testbed

Generates the labelled IPsec dataset: real tunnels between two containers, real
kernel ESP on the wire, and a ground-truth label file beside every capture.

Implementation-plan Phase 2. The matrix is [LLD §10.1](../../docs/LLD.md); the
session lifecycle is §10.2.

## Why kernel ESP, and not the easy way

strongSwan ships a `kernel-libipsec` plugin that processes ESP in userspace. It
makes IPsec work in any container, on any kernel, with no capabilities. It is
deleted from the peer image, and [LLD §10.3](../../docs/LLD.md) explains why:
Track B's entire feature set is packet geometry — padding behaviour, IV
placement, MTU handling — and a userspace ESP implementation may differ from the
kernel path in exactly those details. Models trained on it would learn artefacts
that do not exist in the deployments this tool analyses.

If containers ever prove intractable on a given host, move to VMs. Do not move
to userspace ESP.

## Requirements

- A Docker daemon.
- A kernel with XFRM and ESP available. Most Linux hosts already have them; if
  not, load them once:

  ```bash
  sudo modprobe esp4 esp6 ah4 ah6 xfrm_user af_key
  ```

  Under Docker Desktop the modules belong to the VM, not to your machine:

  ```bash
  docker run --rm --privileged --pid=host alpine \
    nsenter -t 1 -m -u -n -i modprobe esp4 esp6 ah4 ah6 xfrm_user af_key
  ```

`testbed.peers.preflight()` checks this and fails with these instructions
rather than letting every tunnel time out in negotiation, which looks like a
configuration bug and costs a day.

## Build the peer image

```bash
docker build -f testbed/Dockerfile.peer -t ipsec-testbed-peer:0.1.0 testbed/
```

Both ends of every tunnel run this image. It carries strongSwan, tcpdump, and
every traffic generator the seven PRD §9.2 classes need. strongSwan and tcpdump
are version-pinned, because between them they decide the cryptography and the
packet geometry the models learn from; the pins are recorded in
`pyproject.toml` under `[tool.ipsec-analyzer.external-tools]` and baked into
`/etc/testbed-versions.json`, which every session copies into its labels.

## Run

One session:

```python
from pathlib import Path
from testbed.config import WEAK_REFERENCE
from testbed.orchestrator import run_session

result = await run_session(WEAK_REFERENCE, Path("dataset/sessions"))
```

The sampled matrix, with resume:

```bash
uv run python -m testbed.batch dataset/sessions
uv run python -m testbed.batch dataset/sessions --limit 10 --duration 30
```

Interrupt it and run it again: completed sessions are skipped. A session counts
as complete only when the manifest records it **and** its `capture.pcap` and
`labels.json` are still on disk.

## What a session produces

```
dataset/sessions/
├── manifest.json                # which sessions ran, and how they went
└── <session-name>/
    ├── capture.pcap             # IKE negotiation, ESP traffic, IKE DELETE
    └── labels.json              # ground truth
```

`labels.json` keeps three things apart on purpose:

| Key | What it holds |
|---|---|
| `dimensions` | What the matrix chose, in matrix vocabulary |
| `expected` | What a correct parser should report, keyed by `SecurityAssociation` field |
| `not_observable_from_ike` | The fields no parser can recover from this capture, and why |

That third block is the one that matters. Without it, step 8.2 would flag a
parser correctly reporting `UNAVAILABLE` for an IKEv2 lifetime as a mismatch,
and the obvious way to turn the harness green would be to teach the parser to
guess.

## Verifying a batch

```bash
uv run python -m testbed.verify ../dataset/sessions
```

`verify.py` replays Track A over every capture in the batch and compares the
result against `labels.json`, field by field. It exits non-zero if anything is
a `mismatch` or a `fabricated`.

It reports six outcomes, not two:

| Outcome | Meaning | Counts as a defect |
|---|---|---|
| `match` | Parser observed the ground-truth value | no |
| `honest_gap` | Reported `UNAVAILABLE`, and the label agrees it is not observable | no |
| `inferred` | Reported with `INFERRED` provenance — unscored either way | no |
| `not_reported` | The parser produced no attribute at all | no, but investigate |
| `mismatch` | Reported a different value than the ground truth | **yes** |
| `fabricated` | Reported `OBSERVED` for a field the label says is unobservable | **yes** |

`inferred` is unscored for a specific reason: the testbed configures IKE on CBC
while ESP carries AEAD, so Track A's same-family inference is *expected* to
diverge on GCM rows. Scoring those as mismatches would push whoever is chasing
a green harness toward deleting a correct, honestly-labelled inference.

## Tests

The Docker-backed tests skip when there is no daemon, no XFRM, or no peer image:

```bash
uv run pytest tests/test_testbed_docker.py            # ~1 minute
TESTBED_SLOW=1 uv run pytest tests/test_testbed_docker.py   # ~5 minutes
REQUIRE_TESTBED=1 uv run pytest                       # a skip becomes a failure
```

`TESTBED_SLOW=1` adds the twenty-iteration container-leak check, all seven
traffic generators, and the batch resume cycle.

## Things that cost time once

- **strongSwan parses one setting per line.** `auth = psk  id = x` is accepted
  by the tokeniser and then rejected as `invalid value for: auth`, which reads
  like a value problem rather than a layout one.
- **Aggressive mode with a PSK is refused by default**, with good reason. The
  image enables it because generating that weakness is the job of the testbed —
  see the comment in `image/strongswan-testbed.conf`.
- **tcpdump needs time to drain.** It reads the kernel ring buffer on a
  roughly one-second poll even with `-U`, so stopping the capture immediately
  after the teardown discards the DELETE exchange the teardown existed to
  produce. `orchestrator.TEARDOWN_DRAIN_S` is that wait.
- **Nothing reaps children in the peer container.** charon is PID 1 and does not
  act as an init, so an exited tcpdump lingers as a zombie and `kill -0` keeps
  succeeding. Process state `Z` counts as finished.
- **Reverse-path filtering drops decrypted tunnel-mode packets.** The tunnel
  establishes and then passes nothing. `rp_filter` is set to 0 both as a
  container sysctl and in the entrypoint.
