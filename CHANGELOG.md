# Changelog

What has actually landed, in the order it landed. Structured by the phases and
steps of [docs/implementation-plan.md](docs/implementation-plan.md), because
that is the unit of work this project moves in.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/); the project stays on
`0.x` until the demo build.

**Update this file in the same commit as the change it describes.** An entry
added later is an entry written from memory. Record what a step *delivers*, not
which files moved — and when a step's **Done when** could not be demonstrated,
say so under Not verified rather than leaving it implied.

---

## [Unreleased]

### Fixed — clicking an uploaded capture 404'd; `/captures/[id]` did not exist

Found by hand: uploading a PCAP through the dashboard and clicking its row
produced a plain `GET /captures/{id} 404` from Next.js itself, before the
request ever reached the API.

Step 7.5/7.6's pieces were all built and individually correct —
`AnalyzeButton` posts to `/captures/{id}/analyze`, `RunProgress` consumes the
SSE stream and hands off to the resulting assessment — but no page mounted
them. The capture list on `/` has linked to `/captures/${capture.id}` since
7.5 landed; that route was never created, so every capture was a dead end
after upload, and the analyze flow — the demo's actual entry point — could not
be reached from the UI at all despite being fully wired underneath.

Added `app/captures/[id]/page.tsx` (summary card plus `AnalyzeButton`) and
`getCapture()` in `lib/api.ts`, the one API-client function step 7.5 was
missing (`GET /captures/{id}` already existed on the backend, per 6.4).

Verified against the running stack, not just a render: uploaded capture →
detail page (200, was 404) → `POST .../analyze` → run reaches `succeeded` →
returned `assessmentId` renders at `/assessments/{id}` (200). `tsc --noEmit`
and `eslint` both clean.

`_Peer.__init__` disabled Nagle unconditionally. `test_messaging_peer.py`'s
`test_a_periodic_stanza_reschedules_itself` drives the class through
`socket.socketpair()`, which returns an **AF_UNIX** pair on Linux — where an
`IPPROTO_TCP` option is not redundant but rejected, `OSError: [Errno 95]
Operation not supported`. Windows emulates `socketpair()` over loopback TCP and
accepts the call, so the suite was green on the development machine and red in
GitHub Actions, on a line that had nothing to do with what the test asserts.

The `setsockopt` is now guarded on `sock.family in (AF_INET, AF_INET6)`, which
is the real precondition: Nagle is a TCP algorithm and there is nothing to
disable on a Unix socket. `serve()` and `send()` both build `AF_INET`/`AF_INET6`
sockets, so generated traffic keeps one stanza per segment — the property the
guard had to preserve, since coalescing a burst would flatten the shape the
`messaging` class exists to produce.

Verified in both directions against stub sockets: an AF_UNIX-family socket whose
`setsockopt` raises `OSError(95)` now constructs, and an `AF_INET` one still
receives exactly `(IPPROTO_TCP, TCP_NODELAY, 1)`.

### Added — Phase 11 finished: 11.5 and 11.6 land, and MT-08/09 are all that is left

**11.5 Demo captures** — `testbed/demo_captures.py`, `dataset/demo/`

The two PRD §16 tunnels, frozen and committed: `demo-tunnel-a` (IKEv1
aggressive, 3DES-CBC, HMAC-SHA1-96, DH-2, PFS off, 24-hour lifetime, transport,
VoIP) and `demo-tunnel-b` (IKEv2, AES-256-GCM, DH-19, PFS on, 1-hour lifetime,
tunnel, the same call). 13117 and 13248 packets; 3.1 and 3.5 MB.

**Done when — both committed, and neither appears in any training split.**

The second half needed care, because the matrix *already* contains both tunnels
as `weak-reference` and `hardened-reference`, and the sampler generates them
regardless of what pairwise picks. Measured on the real split, `weak-reference`
is in the **test** fold and `hardened-reference` is in the **calibration** fold
— so demoing on the matrix fixtures would have meant demonstrating the
classifier's confidence on the capture that fitted its calibrator.

So the demo tunnels are their own configurations, in their own directory, with
their own seed, and `tests/test_demo_captures.py` asserts the property against
`split_configs` rather than trusting it. It carries a control —
`test_the_reference_fixtures_do_land_in_a_fold` — because otherwise the
assertion would pass just as well against a splitter that placed nothing at all.

What is *not* claimed: the tunnel parameters are PRD §16's and therefore
identical to those two dataset configurations. The demo is a tool being
demonstrated, not a held-out evaluation, and the module docstring says so.

**11.6 Demo rehearsal** — `scripts/demo_rehearsal.py`, and it passes

**3/3 clean runs, 21.1–21.2 s each** against PRD §16's two-minute target.

The harness drives PRD §16's sequence over HTTP and **asserts on each step**
rather than timing it. A rehearsal that only reports a number tells you the
stack was fast, not that the demo works — so it checks that tunnel A's findings
are not empty and B's list is shorter, that B scores *higher*, that the
classifier actually returned a class, that the report really begins `%PDF`.

| step | result | |
|---|---|---|
| 1. tunnel A (weak) | score **25**, 7 findings, 1 critical | 8.4 s |
| 2. traffic classifier | **voip at confidence 1.0, exposure 100** | 0.0 s |
| 3. tunnel B (hardened) | score **80** (+55), 2 findings | 8.4 s |
| 3b. comparison | delta 55, 5 findings only in A | 2.1 s |
| 4. executive report | 17 KB PDF | 2.4 s |

The three runs agreeing to the finding is NFR-4 visible from outside.

**Still needs a person, and MT-19 says so:** this drives the API, not the
browser. It does not prove the threat matrix lights up, or that the progress bar
moves rather than jumping from 0 to 100.

**11.8 was not done.** It is a screen recording with narration and needs someone
to record it. `docs/demo-script.md` is the shot list and narration it would be
recorded from, with PRD §4.1's metadata-exposure line written out, but the video
does not exist.

### Fixed — `MODEL_DIR` had never worked, on any deployment

Found by running the rehearsal against the offline stack, which is the first
time this project has run its own API with models on disk.

`Settings.model_dir` existed. `docker-compose.offline.yml` set it. And
`JobRunner` never passed it to `analyse_capture`, so the pipeline defaulted it
to `None` — and `None` means *no models*.

**Nothing raised, and nothing could.** `track_b/service.py` is deliberately
built to degrade: no model directory means every model-backed attribute comes
back UNAVAILABLE **with a reason**, and the run succeeds. So the symptom was a
complete, internally consistent, entirely plausible assessment saying

> no trained model is available for this deployment. The classifier
> (implementation-plan steps 9.6-9.9) requires the labelled dataset from
> Phase 8, which has not been generated.

on a deployment where the dataset *had* been generated and the models were
sitting in `backend/models/`. The note read as correct, because it is exactly
what a model-free build should say. `model_versions` was `{}` and the
metadata-exposure score was 0 — which the schema documents as "an absence of
evidence, not evidence that the tunnel leaks nothing", and which is precisely
the sentence that made it look handled.

This is the failure mode this project's whole design is arranged against, and it
survived because the design worked: the degradation was so graceful that nothing
distinguished a misconfiguration from an honest gap.

`tests/test_api_jobs.py::test_the_configured_model_dir_reaches_the_pipeline` now
holds that path open. It asserts at the wiring rather than through a real model,
because a test needing trained artefacts would be skipped in exactly the build
where those artefacts are missing.

### Fixed — an assessment that ran models recorded that it had not

The same run that found `MODEL_DIR` unwired found its twin one layer up. The
pipeline builds the inference service and uses it, and then calls
`engine.evaluate` **without** `model_versions`, so every assessment ever
produced carried `{}`.

`{}` is not an unset field. `core/schema.py` documents it as meaning *no
inference ran*, and the technical report acts on that: it prints
`Models: none loaded` and renders a whole section explaining that the
model-backed fields were unavailable in this build. So on the demo capture the
report stated, in print, that no model had run — on the same page as a
classifier result of VoIP at confidence 1.0.

Fixed by passing `service.model_versions`, which hashes the artefacts on disk
rather than trusting a string a training run wrote beside them. The technical
report now reads:

```
Models: traffic_classifier=sha256:6c474eea866e01d1
        mode_classifier=sha256:3a7e7519bd3b8fcd
        calibration=sha256:d8ad6131a24133b9
```

`test_an_assessment_records_the_models_that_produced_it` asserts **both**
directions — empty for a build with no artefacts, populated for one with them —
because it was the threading that broke, and a one-sided test passes against a
pipeline that hardcodes `{}`.

### Fixed — the offline stack had never been started, and four things were wrong

Step 11.4 shipped a compose file, two Dockerfiles and a claim. MT-18 says
"compose topology is the kind of claim that is either true or quietly false, and
only a run tells you which". The run says: false, four times over — and every
one of them produced a stack that came up and looked right.

1. **`frontend/` had no `.dockerignore` at all.** npm on Windows materialises
   its cache under the reserved name `NUL`; the Docker daemon cannot read that
   path, so the image would not build (`error from sender: open frontend\NUL:
   Incorrect function`). Because `NUL/` is gitignored it does not appear in
   `git status`. The same missing file also meant the build stage's `COPY . .`
   was overwriting the `node_modules` the deps stage had just installed with
   whatever the host had — a Linux image carrying a Windows install of anything
   with a native binding.
2. **The compose `command:` ran `uv run`.** `uv run` re-resolves the project
   environment before executing, which needs an index, which needs DNS — on an
   `internal: true` network with no route anywhere. It failed with "Could not
   connect, are you offline?", the right answer to the wrong question. The image
   already puts `/app/.venv/bin` on `PATH`; `alembic` and `uvicorn` are there
   without it.
3. **That `command:` was a YAML `>` folded block, and folding does not fold
   everything.** A line indented further than the first keeps its newline, so
   `sh` received two commands and the second began `--host`. Symptom:
   `sh: 4: --host: not found`.
4. **`libgomp1` was missing from the backend image.** It is LightGBM's OpenMP
   runtime and both trained models are LightGBM boosters, so `import lightgbm`
   raised `libgomp.so.1: cannot open shared object file` — caught, logged, and
   degraded to UNAVAILABLE, exactly as in the defect above.

One more turned up on the way: **`backend/Dockerfile` never copied `models/`
at all**, so `MODEL_DIR` pointed at a directory that did not exist. It was
written before the artefacts were committed — correct when written, silently
wrong afterwards. **MT-26** now opens the image and looks.

`backend/.dockerignore` also excluded `models/*.pt`, and that one turned out
*not* to be a defect: `traffic_cnn.pt` is the CNN, inference deliberately loads
the LightGBM booster so that torch is not a runtime dependency, and the file is
gitignored for the same reason — a clean clone does not have it either. The
exclusion is kept, now with the reasoning written next to it rather than left
to be rediscovered.

### Added — the `messaging` class is learnable, by making the generator honest

Resolves the open spec question recorded below, by its first option: enrich the
generator rather than lower the floor.

`messaging` contributed **zero training rows**. At roughly one packet per second
a 10-second window held 7–10 packets against LLD §7.6's floor of 20, so every
window was discarded and the traffic classifier was silently a six-class model.

**It was not fixed by making messaging faster.** Raising the rate until the
windows cleared the floor would be meeting a target by changing the data. It was
fixed by modelling what a real messaging connection actually carries — all of it
genuinely messaging traffic, and none of it in the generator:

* chat states (XEP-0085) — the "typing…" indicator, around each message;
* delivery receipts (XEP-0184) and read markers (XEP-0333) — the two ticks and
  the blue tick, one of each **per message**;
* message bursts, because people send "hey", then "you there", then the point;
* keepalive pings, because the connection is long-lived and NAT bindings are not;
* roster presence, because the connection is client-to-server and carries every
  contact's state changes, not only the open conversation.

The 1–12 second idle gap between conversational turns is **unchanged**. The
enrichment clusters small packets around each turn; it does not fill the
silences that define the class.

```
before:   61 packets ->  0 windows
after:   678 packets -> 17 windows, 28-116 packets each
```

32 messaging sessions regenerated, 0 failures. All seven of PRD §9.2's classes
now reach the model, `metrics.json`'s `classes_absent` is empty, and the model
card no longer opens with a class-count banner because there is nothing left to
warn about.

**The first draft of the enrichment was worse than the original**, and it is
worth recording because it looked fine. It replied per *message* rather than per
*turn*, so a three-message burst drew three replies, each opening a turn of up to
three more. Measured on loopback: 28 packets in the first 10-second window, 1565
in the ninth — an exponential ramp that still looked like ordinary chat traffic
from the outside, and that would have destroyed the class's signature in the
opposite direction. `tests/test_messaging_peer.py` asserts both bounds: every
window clears the floor, *and* the rate does not compound.

### Fixed — ML-2 was reading the one length the inner header cannot move

Step 9.9's mode classifier scored **0.7273** against its 0.90 target. Measuring
its four features across all 216 sessions said why, and none of it was the
model's fault.

**Two of the four features are constant.** `spi_pairs_per_endpoint` takes exactly
one distinct value across every session (two SPIs over two endpoints — always
1.0), and `cleartext_ratio` takes exactly one (0.0; there is no correlated
cleartext on a private bridge). They are LLD §7.3's, and would carry signal on a
real capture with several SAs and side traffic. Here they carry none. Kept, and
now documented as carrying none, which is more useful than dropping them.

**The remaining length feature measures the wrong length.** Tunnel mode adds 20
bytes (IPv4) or 40 (IPv6) to every packet — but the path MTU caps the packet, so
for any class that saturates the MTU the header *displaces* payload instead of
adding to it. Median tunnel-minus-transport difference in modal ESP length:

```
icmp v4  +8    voip v4 +30    video v4 +18    web v4  -4    file_transfer v4  0
icmp v6 +40    voip v6 +40    video v6 +60    web v6   0    file_transfer v6  0
```

Three of the six classes — `web`, `file_transfer` and `email`, which is most of
the bulk traffic there is — show no signal at all. A classifier cannot beat
chance on them, and 0.73 is what that looks like.

**The minimum length carries what the maximum hides.** The smallest packets in
any flow are pure acknowledgements, keepalives and control: far enough below the
MTU that the inner header adds to them rather than displacing anything. The same
measurement on `min(esp_payload_len)` is positive for **every** class in both IP
versions — +8 to +60, tracking the 20- and 40-byte headers — including all three
where the modal length is flat.

**And the baseline those offsets are measured against was invented.**
`EXPECTED_MODAL_LEN` was a hand-written table of round numbers. Measured against
the corpus it is wrong by up to **672 bytes** (`web` written as 800, observed at
1472) on an effect that is 20. A baseline whose error is thirty times the signal
does not blur a feature, it replaces it. `ModeBaseline` is now *fitted*: the
median transport-mode geometry per (traffic class, IP version), from the training
fold only, stored in `mode_lightgbm.meta.json` and loaded with the model so the
offsets cannot silently be computed against nothing at inference time.

| | accuracy |
|---|---|
| four features, hardcoded table | 0.7500 |
| plus `min_len_offset` and `inner_header_bytes`, fitted baseline | 0.9231 |
| final, retrained on all 248 sessions with ML-1 in the loop | **1.0000** |

Step 9.9's target is met. **1.0000 over 52 held-out sessions is reported with the
same caveat as ML-1's**, and the model card carries it: `min_len_offset` is close
to a *direct measurement* of the thing being classified rather than a learned
proxy for it, and this testbed presents one clean SA pair at a fixed MTU. Real
traffic has several SAs, varying path MTUs and fragmentation, and the baseline is
fitted to these generators. Step 9.12 is still the only measurement that would
say by how much.

### Verified — MT-15 and MT-24, which had never been run

- **MT-15** (step 3.2): the reader's packet count against tshark on *real*
  captures, rather than the synthetic pcaps the automated suite builds. Run
  against the pinned tshark 4.4.18 inside the backend image rather than a host
  binary, which is stricter — that is the version Track A parses. Four captures
  spanning both IP versions, both IKE versions and three cipher suites:
  7120/7120, 7123/7123, 678/678, 684/684. Exact.
- **MT-24** (step 9.8): `docs/model-card.md` regenerates byte-identically from
  `models/metrics.json`. This also fixed a defect of exactly the kind MT-24
  exists to catch — the Limitations section read "Seven classes, closed set"
  while the model had six. The count is now taken from the artefact.

### Not verified — what is still open

- **Step 9.12, external validation, remains unmeasured.** ISCXVPN2016 has not
  been downloaded. Every internal score in this release measures how distinct
  this testbed's generators are; none of them is evidence of generalisation. The
  model card says so in its own section rather than in a footnote.
- **MT-08 and MT-09** still need a Neon connection string, which was not
  available here. They are the only two rows in `manualtesting.md` still marked
  **Not run**.
- **Step 11.8, the demonstration video, does not exist.** `docs/demo-script.md`
  is what it would be recorded from.
- **The dashboard has not been walked by eye on the offline stack.** The
  rehearsal drives the API; MT-19 records what that leaves unproven.

### Fixed — PFS inference reported the *opposite* of the truth for every ECP group

Found by running step 9.4 against the one capture in existence that contains
real `CREATE_CHILD_SA` exchanges — the 700-second rekey probe, DH-19, PFS on.
It reported `pfs_enabled: false`, INFERRED, at 0.65 confidence. PFS being off
is a security weakness; this is a false positive in a security report.

The cause is a baseline this project chose wrongly when wiring step 9.4.
LLD §7.4 measures how much larger a `CREATE_CHILD_SA` carrying a KE payload is
than one that does not, so the baseline must be **a `CREATE_CHILD_SA` without a
KE payload**. `exchange_sizes` supplied INFORMATIONAL exchanges instead, on the
reasoning that they are the one IKEv2 exchange that never carries a KE and are
routinely present.

They also never carry the SA proposal, the nonce, or either traffic-selector
payload. Measured on the real capture that difference is **88 bytes** — larger
than the entire 72-byte KE payload of an ECP-256 group. So the delta being
compared was the KE payload plus 88 bytes of structure that has nothing to do
with PFS:

| Group | Expected delta | Accepted range | PFS on → | PFS off → | Confidence |
|---|---|---|---|---|---|
| 19 (ECP-256) | 72 | 43–101 | delta 160 → **False** ✗ | delta 88 → **True** ✗ | 0.65 |
| 14 (MODP-2048) | 264 | 158–370 | delta 352 → True ✓ | delta 88 → False ✓ | 0.90 |

**For ECP groups the answer is inverted, not merely noisy.** For MODP it is
right by accident: the 264-byte KE payload dominates the unmodelled 88, and the
40% tolerance is wide enough to swallow the remainder.

Two things kept this from reaching a score. `policies/baseline.yaml`'s PFS rule
carries `confidence_gte: 0.7` and the ECP confidence is 0.65, so the false
finding never fired — the confidence guard doing precisely the job it was
written for. And no dataset session rekeys at all (90-second sessions, 3600-second
lifetimes), so `create_child` is empty for all 248 and PFS was already
UNAVAILABLE there. The wrong value was reachable only on a capture long enough
to rekey, which is the case a real deployment presents.

**The fix is to stop supplying a baseline that is not one.**
`ExchangeSizes.informational` is now named for what it is and documented as not
a PFS baseline; `ExchangeSizes.ke_free_create_child` is the correct input and
is always empty, because distinguishing a rekey that carried a fresh key
exchange from one that did not *is the question `infer_pfs` is asked* — an
implementation that answered it while assembling the input would be assuming
its own conclusion. A capture of a uniformly configured tunnel contains only
one kind of rekey and nothing in it says which.

So PFS is now UNAVAILABLE with its reason rather than backwards:

```
create_child=14 exchanges, informational=17, ke_free=()
infer_pfs -> unavailable
note: no exchange without a key-exchange payload was captured, so there is
      no baseline to measure the CREATE_CHILD_SA against
```

`infer_pfs` itself was never wrong and is unchanged — given genuine KE-free
sizes it separates DH-14 PFS-on from PFS-off correctly and returns a lower
confidence for ECP, which is step 9.4's **Done when** and is now tested on the
inputs the method actually calls for.

**Step 9.4 is therefore implemented and correct, and undemonstrable end to end
on a single capture.** Measuring PFS this way needs a KE-free `CREATE_CHILD_SA`
in the same capture, which a uniformly configured tunnel never produces. Either
the analyser needs a reference for what a KE-free rekey costs on that tunnel, or
LLD §7.4's method needs a second signal. That is a decision about the
specification, and it is recorded here rather than papered over with a value
that is right 50% of the time by construction.

### Fixed — four UNAVAILABLE notes claimed Track B was unimplemented

`operating_mode`, `pfs_enabled`, `observed_rekey_s` and `replay_sane` each
carried a Track A note ending "which Track B does not yet implement". Track B
implements all four. The notes are what a reader sees in the report when a
value is missing, so a stale one is a wrong explanation for a real gap — the
same defect class as a wrong value, in the field whose entire job is to say why
there isn't one. They now describe the division of labour instead.

### Added — Phase 8 generated, Phase 9 trained: the measured results

> **Superseded in part.** Two numbers here are no longer this build's: ML-2's
> 0.7273 (now 1.0000 — the mode classifier was reading the wrong length) and the
> six-class traffic classifier (now seven — messaging contributes rows). Both are
> at the top of this file. The rest of this entry, including why a macro-F1 of
> 1.0000 is a reason to investigate rather than to celebrate, still stands.

**The dataset.** 248 sessions, 0 failures, 14 GB, generated by six concurrent
shards in about 27 minutes of wall clock. 62 configurations x 4 traffic runs,
which is how PRD §9.3's "at least 200" is met. Balanced by construction: v4
124 / v6 124, transport 124 / tunnel 124, ikev1-aggressive 84 / ikev1-main 80 /
ikev2 84.

**The models.** Trained on 216 of those sessions — `messaging` contributes
none, for the reason recorded above — giving 2546 train / 584 calibration / 797
test windows over 35 / 8 / 11 disjoint configurations.

| Model | Metric | Result | Target | |
|---|---|---|---|---|
| ML-1 LightGBM | macro-F1 | 1.0000 | — | baseline |
| ML-1 CNN | macro-F1 | 0.9988 | ≥0.85 (PRD §8.4) | met |
| ML-1 CNN | ECE | 0.0021 | ≤0.10 (PRD §8.4) | met |
| ML-2 mode | accuracy | **0.7273** | ≥0.90 (step 9.9) | **NOT MET** |

**The traffic-classifier scores do not mean what they look like, and the model
card says so in its own section rather than in a footnote.** A macro-F1 of
1.0000 is a reason to investigate, and two things were checked before it was
published.

*It is not leakage.* Train, calibration and test hold disjoint sets of
configurations — verified directly on the real split, not assumed: no
configuration in two folds, no session whose windows span a boundary.

*It is a nearly separable task.* The seven classes are produced by different
tools at rates differing by orders of magnitude, and they separate on single
features. Mean `packet_count` per 10-second test window: icmp 105, email 307,
voip 902, video 1824, web 4627, file_transfer 18071. `up_down_byte_ratio`: web
0.03, icmp and voip 1.0, email 31, file_transfer 812, video 3833. A one-feature
decision stump separates most of them.

So the figure measures **how distinct this testbed's generators are**, not how
the model would classify real traffic. The only measurement that answers the
second question is step 9.12's external validation, which is unmeasured. The
scores are a lower bound on the difficulty of the task as posed, and are
labelled as such.

**ML-2 misses its target and is reported as missing it.** 0.7273 against 0.90.
It is scored per *session* over 44 held-out sessions rather than per window:
operating mode is a property of the SA, and per-window scoring would have
counted one tunnel's eighteen windows as eighteen independent correct answers
and inflated the figure into passing.

### Fixed — temperature scaling drove every confidence to 1.0

The first training run fitted **T = 0.0375**. A temperature below 1 does not
calibrate, it *sharpens*: dividing every logit by 0.0375 multiplies it by 26.7
and pushes every prediction towards certainty.

The cause is the task's separability. Temperature scaling minimises NLL, and on
a calibration fold the model never gets wrong (584/584 correct here) NLL falls
monotonically as confidence rises, so the optimiser walks T towards zero. The
model would then have gone on to be wrong in deployment at essentially 100%
confidence — the worst property a number can have when it sits in a security
report next to the word INFERRED, and precisely the failure PRD §8.3 exists to
prevent.

No temperature fixes this, because a fold with no errors carries no information
about how wrong the model is when it is wrong. `fit_temperature` now detects the
condition and returns T=1.0 with the reason logged and recorded, rather than a
number that would have looked like successful calibration:

```
WARNING: the calibration fold contains no errors (584/584 correct), so
temperature scaling is degenerate and would drive confidence to 1.0.
Leaving the CNN uncalibrated (T=1.0)
```

Test scores are unchanged by the fix, as they must be — temperature scaling
never alters a prediction, only its confidence.

### Added — per-session progress in the verification harness

`testbed.verify` over 248 sessions is the better part of an hour, and it
printed nothing until the end. There was no way to tell a slow run from a stuck
one. It now logs `[n/total] session-name` as it goes, with `--quiet` to
suppress it.

### Open spec question — LLD §7.6's window floor makes PRD §9.2's sparsest class unlearnable

> **Resolved** by resolution 1 below — the messaging generator was enriched, not
> the floor lowered. See "the `messaging` class is learnable, by making the
> generator honest" at the top of this file. Left in place because the reasoning
> is what makes the resolution defensible, and because the measurements below
> are what a future change to the windowing would have to argue against.

Found by counting scorable windows per class across the finished dataset, and
it is a conflict between two specifications rather than a bug in either
implementation of them.

LLD §7.6 requires fixed 10-second windows and says "a window needs at least 20
packets to be scored". PRD §9.2 requires a `messaging` class, defined by its
silences — small payloads separated by long irregular gaps. The testbed's
generator realises that as a 1–12 second idle gap around each
message-and-reply, which produces roughly one packet per second.

Ten seconds at one packet per second is seven to ten packets. The floor is
twenty. **Every messaging window in the dataset is discarded, so the class
contributes zero training rows:**

```
class          sessions   windows/session (sampled)
email                32   [14, 19, 19]
file_transfer        48   [18, 18, 18]
icmp                 28   [19, 18, 18]
messaging            32   [ 0,  0,  0]
video                32   [18, 18, 18]
voip                 36   [18, 18, 18]
web                  40   [19, 19, 19]
```

A longer session does not help: this is a rate, not a duration. At the matrix's
own 180-second default the packet count doubles and the per-window count does
not move.

**The consequence for PRD §8.4's target.** Macro-F1 is defined over the seven
classes. With one class absent from both training and test, a model that is
perfect on the other six scores 6/7 = 0.857 — a figure that would sit just
above the 0.85 threshold while the classifier had never seen a seventh of the
problem. Reporting it that way would be the most misleading number this project
could produce, so `metrics.json` and the model card record the class count the
score is actually computed over.

**This was not resolved by retuning the generator.** Raising the messaging
packet rate until windows clear the floor would make the target met by
changing the data, which is the failure this project has spent its whole
lifetime guarding against. Two defensible resolutions exist and both are
decisions about the specification rather than about the code:

1. **Enrich the messaging model.** The generator sends messages and replies and
   nothing else. Real XMPP or Signal traffic also carries presence updates,
   typing indicators, delivery and read receipts, and keepalives, all of which
   are genuine messaging packets. A model including them would clear the floor
   *and* be more faithful, not less.
2. **Make the window floor rate-aware.** The floor exists because percentile
   features over three packets are noise. For a class whose defining property
   *is* sparsity, discarding the sparse windows throws away precisely the
   evidence that identifies it. A floor expressed as "enough packets to
   estimate the features, or enough elapsed time at a stable low rate" would
   admit messaging without admitting noise.

Until one is chosen, the traffic classifier is a six-class model and is
reported as one.

### Fixed — the observed rekey interval was 0 seconds on every capture

Reported as INFERRED at 0.95 confidence, which is the combination this project
exists to prevent: a number, stated with near-certainty, that was never
measured.

`service.analyse` built its SPI series from a single `SAPair` — its forward
SPI and its reverse SPI. Those are the two *directions* of one SA generation
and they come up at the same instant, so the only interval available was
between them, and it was always approximately zero. A rekey installs a new
Child SA, hence a new SPI, which `ingest.assemble_flows` groups into a wholly
**separate** `SAPair`; successive generations of a tunnel were therefore never
visible from inside the pair being analysed.

`replay.spi_series` now groups SPIs by *directed* endpoint pair across the
whole capture, and `api/pipeline.py` hands each SA the series for its own
direction. Directed rather than unordered because merging both directions
reintroduces the same fault one level down: each generation contributes two
simultaneous entries, so every other interval in the merged series is a
spurious zero and the median collapses back to it.

**Blast radius.** No rule in `policies/baseline.yaml` reads
`observed_rekey_s`, so no score or finding was ever wrong because of this. What
was wrong is the technical report, which renders "Observed rekey interval (s)"
directly, and `Assessment.capabilities.rekey_observed`, which claimed the
measurement had been made.

**Done when — an observed rekey interval within 10% of a 300-second
lifetime.** Demonstrated on a real 700-second capture from
`testbed/rekey_probe.py`, which exists because nothing in the sampled matrix
can produce one (every matrix row runs a 3600-second lifetime for 90 seconds,
so no dataset session ever rekeys inside its own capture):

```
10.10.3.2 -> 10.10.3.3: SPI first-seen offsets 0.0, 288.5, 578.5
   observed_rekey_s = 290s (inferred, confidence 0.95)
   vs 300s configured: 3.3% -> WITHIN 10%
10.10.3.3 -> 10.10.3.2: SPI first-seen offsets 0.0, 288.4, 578.5
   observed_rekey_s = 290s (inferred, confidence 0.95)
```

Three generations, two rotations. Two rather than one on purpose: a single
rotation cannot distinguish "rekeyed on time" from "rekeyed once, for some
other reason".

### Fixed — `over_time = 0s` stopped SAs rekeying at all

A defect introduced by this project's own earlier fix, and found by the probe
above rather than by any test.

Zeroing `over_time` made the negotiated lifetime equal the configured one,
which was the point. It also meant strongSwan deleted each SA at the exact
instant it tried to rekey — the daemon expires an SA that has not rekeyed
within `rekey_time + over_time`, and with no window there is nothing to rekey
in. A 300-second tunnel captured for 700 seconds died at t=300 with the rekey
exchange on the wire and 400 seconds of silence after it, while the session was
recorded as successful.

The dataset never saw it: at a 3600-second lifetime and 90-second sessions, no
SA comes within an hour of expiry. That is the only reason this was not a
corrupt corpus.

`lifetime_s` now means the **hard lifetime that IKEv1 puts on the wire** —
which is what `labels.json` claims it is — with `rekey_time` derived
`REKEY_WINDOW_S` (10 seconds) below it. The negotiated value is unchanged, so
sessions generated before and after this change agree; the SA now has a window
three orders of magnitude larger than a CREATE_CHILD_SA needs; and the observed
interval lands within a few percent of the configured lifetime rather than on
the 10% boundary a proportional window would put it on.

### Fixed — Track A observed *nothing* on real captures, and its tests could not tell

The single most serious defect this project has had. Phase 4 was written with
no Docker and no tshark, so `ike_parser.py` guessed tshark's ISAKMP JSON field
names from documented `isakmp.*` display-filter names. Every structural guess
was wrong. The parser ran cleanly, raised nothing, and returned an empty
negotiation list for every capture — so every ESP flow came back
`no IKE negotiation in this capture correlates to this SA`, and *every*
Track A field was UNAVAILABLE with a plausible-sounding reason.

The tests passed throughout, because `tests/_tshark_json.py` built its fixtures
from the same guesses. Parser and fixtures agreed with each other and neither
agreed with tshark.

Found by running the pilot batch's first real capture through the pinned tshark
(4.4.18) rather than through the test suite.

**What tshark actually emits**, now read off real output rather than inferred:

| Phase 4 assumed | tshark 4.4.18 emits |
|---|---|
| `isakmp.sa.proposals` / `isakmp.sa.proposal` / `isakmp.tf` container keys | no container keys at all — payloads are repeated `isakmp.typepayload` (a type number) and `isakmp.typepayload_tree` (its contents), aligned by position and nested recursively |
| `isakmp.tf.attr` for both IKE versions | `isakmp.ike.attr` (IKEv1) and `isakmp.ike2.attr` (IKEv2) |
| `isakmp.tf.id` | `isakmp.tf.id.encr` / `.prf` / `.integ` / `.dh` / `.esn` (IKEv2), `isakmp.trans.id` (IKEv1) |
| `isakmp.init_spi` / `isakmp.icookie` | `isakmp.ispi` / `isakmp.rspi`, as colon-separated octets |
| `isakmp.version` is a major version | the packed byte `0x20` — read as an integer it is 32, so **every IKEv2 capture was classified as IKEv1** and then searched for IKEv1 attributes that were not there |
| attribute values are decimal | colon-separated octets (`00:05`, `00:01:73:40`) |
| NAT detection is notify 16406/16407 | 16388/16389 (RFC 7296 §3.10.1) — the old pair matches nothing, so `nat_detected` was unreachable |

`tests/_tshark_json.py` was rebuilt from that output. Its builders now take a
neutral description of a message and render it in the dialect matching the IKE
version, so a test says "an IKEv1 aggressive-mode proposal offering 3DES"
without restating tshark's spelling — and a fixture cannot drift into a shape
only the parser believes in.

**Done when — Track A reproduces `labels.json`.** Demonstrated on both PRD §16
reference tunnels, verified inside the backend image against the pinned tshark:

```
2 sessions verified
  match          8
  honest_gap     6
  inferred       5
  not_reported   2

PASS
```

Before the fix the same two captures gave `match 0`, `not_reported 9`.

### Fixed — `nat_traversal` was OBSERVED true on tunnels with no NAT

A narrowing of the contract, and a deliberate deviation recorded below.
`schema.py` and LLD §6 both define the field as "UDP/4500 encapsulation, **or**
NAT_DETECTION notify payloads". Read literally that reports NAT traversal for
every IKEv2 tunnel ever captured: RFC 7296 §3.10.1 *requires* the
NAT_DETECTION notifies in every IKE_SA_INIT, so strongSwan sends them whether
or not a NAT exists. Both reference tunnels — on a flat /24 with no NAT
anywhere — reported `nat_traversal: true` as an OBSERVED fact.

The notifies say the peers *looked* for a NAT. Only the switch to UDP/4500 says
they *found* one, and RFC 3948 makes that switch mandatory when they do. So
encapsulation is now the observation, and the discovery having run is demoted
to the note. `PacketRecord.udp_encapsulated` carries the signal from ingest,
where it was previously discarded — UDP-encapsulated ESP was recorded as plain
`esp`, indistinguishable from the real thing.

The field is now answerable on an ESP-only capture with no IKE in it at all,
which it was not before.

### Fixed — the testbed's ground truth disagreed with its own wire by 10%

`negotiated_lifetime_s` came back 95040 against a `labels.json` expecting
86400: strongSwan's `over_time` defaults to 10% of `rekey_time`, and IKEv1 puts
the *hard* lifetime on the wire. Track A was reading it correctly; the label
was wrong.

Fixed in `swanctl.conf.j2` rather than by teaching the label about
strongSwan's arithmetic — the configured value should be the negotiated value,
which is what the ground truth claims it is. `over_time` is accepted on the
connection only; a child block carrying it fails the whole connection with
`unknown option: over_time`, which is verified empirically rather than assumed.

**The first attempt at this — `over_time = 0s` — was wrong, and is superseded
by "`over_time = 0s` stopped SAs rekeying at all" above.** It produced the
right negotiated value and stopped every SA rekeying, which no test and no
dataset session could see. The correct form keeps a small non-zero window and
derives `rekey_time` below the configured lifetime instead.

### Added — key lengths that the cipher fixes rather than negotiates

`encryption_keylen` was UNAVAILABLE for every 3DES tunnel, because IKEv1 3DES
carries no key-length attribute — there is nothing to negotiate. Reporting
"unknown" for a value that is not unknown is the mirror image of a fabricated
value, and `EncryptionAlg`'s own docstring already says these two ciphers'
lengths are fixed by the algorithm. `transforms.FIXED_KEY_LENGTH_BITS` supplies
168 for 3DES-CBC and 56 for DES-CBC (56 rather than 64: the parity bits are not
key material, and 64 would overstate the weakest cipher in the matrix). The
attribute always wins when present, so this can never overwrite an observation.

Deliberately limited to those two. The AEAD members are excluded even though
they are commonly deployed at one size: their IANA transform IDs do not pin a
key length, and FR-4.9 is about exactly that.

### Fixed — every IPv6 session in the matrix produced an empty capture

Half the sampled matrix is IPv6. Every one of those sessions brought its tunnel
up, generated nothing at all, and was recorded as a complete session whose
`labels.json` said it contained 180 seconds of the traffic class it was
sampled for. The captures held 8 to 11 packets: the IKE exchange and the
DELETE, and no ESP.

Found by counting scorable windows per class in the pilot batch. Every IPv6
row had zero.

Every traffic generator built IPv4-only command lines, and several distinct
faults were stacked on top of each other:

| Generator | Fault |
|---|---|
| all listeners | bound `0.0.0.0`, which is IPv4-only, so the client connected to `fd00:...` and found nothing there |
| web, email | `http://fd00:10:10::3:8080` — an IPv6 literal in a URL needs brackets or it is not a URL with a port |
| voip, video | same, in `rtp://` |
| icmp | `ping` with an IPv6 `-I` source and no `-6` |
| filexfer | `iperf3 --client <v6 literal>` resolves as IPv4 without `-6` |
| email | swaks refuses IPv6 with "requires IO::Socket::INET6" — it tests for that module by name and will not use `IO::Socket::IP`, which the image had |
| email | with that module installed, `IO::Socket::INET6` then failed with "Bad protocol 'tcp'": debian-slim ships no `/etc/protocols`, and `netbase` provides it |

`traffic/base.py` gained `is_ipv6`, `host_for_url`, `bind_address` and
`ping_command`, and every generator goes through them. `Dockerfile.peer` gained
`libio-socket-inet6-perl` and `netbase`, both there solely so swaks can reach an
IPv6 server. All seven classes verified generating real traffic over IPv6.

### Added — a session that carried no traffic now fails instead of being labelled

The reason the above was invisible for a whole phase. `run_for` wraps every
generator command in `|| true`, deliberately, because several of the tools exit
non-zero in normal operation — and the cost is that a command line that fails
outright looks exactly like one that worked.

`run_session` now counts ESP packets before writing the session and refuses
below `max(20, duration_s // 4)`. Messaging, the sparsest class in the matrix
at roughly one packet per second, clears that at every duration; a tunnel that
carried nothing but its own negotiation cannot clear it at any. The check
earned itself immediately, refusing a 25-second messaging session during the
concurrency tests.

**A capture labelled as traffic it does not contain is worse than a failed
session**: it is training data that teaches a classifier the wrong thing, and
nothing downstream can tell.

### Added — step 8.3 can run as concurrent shards

`--shard I/N` splits the configuration list so several batches can generate
disjoint slices at once. Interleaved rather than contiguous, so no shard draws
all the IPv6 rows and finishes hours after the others.

Two things had to be fixed before that was possible, and neither was obvious
until three shards were actually running:

- **Every session created its Docker network on the same subnet.** The second
  concurrent session got `invalid pool request: Pool overlaps with other one on
  this address space` and failed, as did every session after it.
  `PeerAddressing.offset()` gives each shard its own outer subnet
  (`10.10.<i>.0/24`, `fd00:10:10:<i>::/64`); index 0 is unchanged, so a
  single-process run and every existing manifest behave exactly as before. The
  *protected* subnets behind each gateway are deliberately **not** offset — they
  live in their own network namespaces and cannot collide, and holding them
  fixed keeps the inner traffic identical across shards, so a shard index is
  not something a classifier could learn.
- **A failure in one shard destroyed the others' work.** The per-failure
  cleanup called `prune_orphans()` unrestricted, which force-removes every
  container carrying the testbed label — including the live peers of the other
  two shards, which would then fail, prune in turn, and cascade. `prune_orphans`
  now takes a session, and the batch names the session it is cleaning up after.
  The startup sweep, which genuinely cannot tell an orphan from a sibling, is
  skipped entirely when sharded.

Each shard also keeps its own manifest (`manifest-I-of-N.json`), because one
shared file rewritten after every session by three processes would have each
erasing the other two's record of what had completed.

### Added — repeat runs that are actually different sessions

PRD §9.3 wants at least 200 sessions; the pairwise sample is 62
configurations. `with_repeats` expands each configuration into *N* traffic
runs, and `--repeats 4` reaches 248.

The point of the step is that those repeats must not be copies. Only the
messaging generator was seeded, and it was seeded with a constant — every other
generator produced byte-identical traffic on every run, so 248 sessions would
have been 62 distinct feature rows and 186 duplicates of them: a dataset that
counts to 200 without knowing 200 things.

`SessionConfig.seed` now reaches the generators, each repeat gets its own, and
every generator draws within-class parameters from it: ICMP its rate and sizes,
web its burst length and think time, VoIP its packetisation interval (20/30/40
ms, which moves both packet rate and size), video its resolution and bitrate,
email its attachment sizes and gaps, file transfer its offered rate. Each
variant keeps the property that defines its class, so the seven remain as
separable as MT-13 found them.

VoIP's carrier frequency is deliberately *not* varied: a different sine tone
through G.711 produces identical packet geometry, so it would be a label the
features cannot see — variation that looks like diversity in the manifest and
is not.

### Added — Phase 9, Track B: the learned half

Steps 9.5 through 9.12, which the previous entry recorded as "not performed"
because they need the Phase 8 dataset. The dataset now exists.

**9.5 Windowing and the split** — `track_b/windows.py`
- LLD §7.6's fixed 10-second windows at 50% overlap, scored only above 20
  packets. A window is turned into an `SAPair` covering just its packets and
  handed to the existing `features.extract`, so a window's vector is computed
  by exactly the same code as a whole capture's.
- **Split by configuration, never by window**, which is the step's whole point.
  Windows overlap by half, so two adjacent ones share half their packets
  outright; a window-level split puts one in train and the other in test and
  reports a memory test as an accuracy. It comes out high, which is why nobody
  questions it.
- Stricter than the plan asks: a configuration's repeat runs are held together
  too. They share a tunnel and differ only in traffic parameters, so splitting
  by session alone would leak the configuration even though no single session
  spans folds.
- Deterministic, on a SHA-256 of the configuration name rather than `hash()`,
  which is salted per process — a split that differed between runs would make
  "the test set" a thing that existed only in the session that trained the
  model.
- Stratified by traffic class, because an unstratified 20% draw over 62
  configurations routinely leaves a class out of the test fold entirely, and a
  macro-F1 over a fold missing a class is not PRD §8.4's number.

**9.6 LightGBM baseline, 9.7 CNN** — `track_b/traffic_clf.py`
- The CNN is LLD §7.6's architecture transcribed without changes. It returns
  logits, not probabilities: both the training loss and step 9.8's temperature
  scaling are defined on logits, and a model that softmaxed internally would
  need it undone in both places.
- Best-epoch selection uses the *calibration* fold. Choosing an epoch by test
  macro-F1 is model selection on the test set, and the reported number stops
  being held out the moment it decides something.
- Class-weighted loss, because window count per class follows traffic rate: one
  file-transfer session yields far more scorable windows than one messaging
  session of equal length, and unweighted that accident of bitrate becomes a
  prior.

**9.8 Calibration** — `track_b/calibration.py`
- Temperature scaling for the CNN, isotonic regression per class for LightGBM,
  both fitted on the disjoint calibration fold.
- Temperature scaling **cannot change a prediction** — dividing every logit by
  the same positive number leaves the argmax alone — which is asserted, and is
  why it is the right tool: a calibration step that also changed answers would
  make the accuracy figure conditional on it.
- The isotonic fit is exported as knots and applied at inference with
  `np.interp`, so a deployment needs no scikit-learn for it. Asserted to
  reproduce the fitted estimator exactly, because a confidence in a report that
  differed from the confidence the model was evaluated with would make the
  committed ECE describe something the deployment does not do.

**9.9 Mode classifier** — `track_b/mode.py`
- LLD §7.3's four features. The ordering dependency the step requires be
  documented is in the *signature*: `predict` takes a traffic-class
  distribution as an argument rather than computing one, so ML-1 must have run
  first and the cycle cannot be closed backwards by a later edit.
- Weighted by ML-1's whole distribution rather than its argmax, so an uncertain
  classification contributes a blurred baseline instead of a confidently wrong
  one.
- Scored per *session*, not per window: operating mode is a property of the SA,
  and per-window scoring would count one tunnel's thirty windows as thirty
  independent correct answers.

**9.10 Feature attribution** — `track_b/attribution.py`
- Exact TreeSHAP, from LightGBM's own `pred_contrib=True`. The `shap` package
  is **not** a dependency: its numba/llvmlite chain does not resolve against
  this project's numpy on Python 3.11, and it would have been a large
  dependency added to get a number LightGBM already computes exactly.
- The CNN's tabular half gets occlusion attribution instead, and says so. It is
  an approximation of a Shapley value, not one, and calling it TreeSHAP would
  be dressing a weaker method in a stronger method's name.

**9.11 Inference service** — `track_b/service.py`
- Loads real artefacts and predicts through them, or reports UNAVAILABLE with
  `NO_MODEL_NOTE` when the directory is empty. **Both are supported states**:
  an air-gapped deployment handed the code and not the artefacts runs in the
  second permanently, and has to produce a correct assessment that is honest
  about what it could not determine.
- LightGBM and torch are imported lazily and failures tolerated, because they
  are the `ml` dependency group and absent from the offline image (step 11.4).
  An artefact that will not load is logged and treated as absent — it is
  exactly as informative as no model, and crashing over it would lose the
  Track A analysis too.
- `model_versions` is a content hash of the artefact, not a string written
  beside it, so it cannot fall out of step with the bytes it names.
- The API loads the *LightGBM* traffic classifier rather than the CNN, even
  though the CNN scores higher: loading the CNN would make torch a runtime
  dependency of the offline image, and LightGBM also gives exact TreeSHAP that
  the CNN can only approximate. `metrics.json` records both so the trade is
  visible rather than implicit.

**9.4 PFS inference is now actually wired.** The previous entry recorded it as
implemented but fed empty lists, because Track A did not extract exchange
sizes. `ike_parser.exchange_sizes` now collects CREATE_CHILD_SA and
INFORMATIONAL message lengths per endpoint pair off the same parsed messages —
no second tshark run — and the pipeline hands them to `infer_pfs`.


### Added — step 8.5, ISCXVPN2016 ingestion

`analyzer.dataset.iscx` maps the University of New Brunswick's ISCXVPN2016
captures into the feature format `track_b.features` produces for testbed
captures, so step 9.12 can evaluate a classifier on traffic this project did
not generate.

**Done when — external captures produce feature vectors with the same schema as
testbed captures.** Demonstrated: an adapted external capture and a testbed ESP
capture both yield **74 columns**, and the comparison is set equality on the
names, not on the count.

```
external columns : 74
testbed columns  : 74
schemas identical: True
comparable subset: 55 of 74
```

- `label_for()` reads ISCXVPN2016's filename convention into PRD §9.2's seven
  classes. The mapping is **partial on purpose**: `tor_*` and unrecognised
  names return `None` and are reported as unmapped rather than forced into the
  nearest bucket, which would inject label noise into the one evaluation whose
  purpose is to be trusted. Pattern order is load-bearing and tested —
  `skype_file` must reach file transfer, not the VoIP rule that also matches
  `skype`.
- `adapt_directory()` returns `unmapped`, `empty` and `unreadable` alongside
  the flows, each with its reason. A batch that silently dropped what it could
  not handle would overstate its own coverage, and coverage is the point of an
  external set. ISCXVPN2016 ships some captures as pcapng, which `read_packets`
  refuses; those land in `unreadable` with the reader's message.
- `comparable_feature_names()` removes the 19 ESP-geometry features
  (`esp_len_mod16_*`, `esp_len_modal*`, `esp_len_distinct`), leaving 55.

**The honest part, and the reason to read the module docstring before trusting
any number from it.** ISCXVPN2016 is not IPsec — its "VPN" captures are
OpenVPN over UDP and the rest is plaintext. There is no ESP header, so there is
no SPI to key a flow on and no `esp_payload_len` to measure. Two substitutions
bridge that, and both change what the numbers mean:

1. Flows are keyed on the **address pair**, with `_synthetic_spi()` filling
   `FlowKey.spi` from a stable non-cryptographic digest. It is not an SPI and
   is never reported as one. It is deterministic rather than `hash()`-based,
   because a row identity that changed between runs would make a feature matrix
   impossible to trace back to its capture.
2. `ip_payload_len` stands in for `esp_payload_len`. These are different
   measurements — the ESP figure is `IV || ciphertext || ICV` and nothing more.
   Without the substitution every external vector would carry all-zero geometry,
   which reads as a *perfectly padded tunnel* rather than an unmeasured one.
   That is a silent wrong answer of exactly the kind this project exists to
   avoid, so it is tested against.

Substitution 2 is why the geometry features do not transfer: they measure a
padding rule these captures do not have, and a cross-corpus score computed over
them would look like generalisation and be an artefact. The timing, flow and
directionality groups do transfer — they describe application behaviour, which
is what the classifier is meant to be reading.

`ExternalFlow.tunnelled` keeps the `vpn_` half separate from the plaintext
half. A classifier trained on IPsec should do better on OpenVPN than on
plaintext; if it does not, that is a finding rather than a detail.

26 tests, on synthetic captures shaped like ISCXVPN2016's. The real corpus needs
a registration form and several gigabytes; the adapter's contract does not.

### Not verified — step 8.5

- **No real ISCXVPN2016 capture has been adapted.** The corpus was not
  downloaded. The filename patterns are written from the published naming
  convention, not from a directory listing, so a distribution that names files
  differently will land in `unmapped` — visibly, which is the intended failure
  mode, but it will need the patterns extended.
- **The proportion of the corpus that is pcapng is unknown**, so how much of it
  `read_packets` will refuse outright is unknown. `unreadable` reports it; no
  one has read that report.
- **Step 9.12 itself is not done.** This is the adapter it depends on, not the
  evaluation. There is no model to evaluate.

### Fixed — Track B wrote a cipher *suite* label into an enum-typed field

Not a plan step; found by running a real capture through the running API rather
than through the test suite. Every analysis whose capture had enough ESP length
diversity for the sieve to answer failed with **HTTP 500**:

```
2 validation errors for Assessment
security_associations.0.encryption_alg.value
  Input should be 'null', 'des-cbc', '3des-cbc', 'aes-cbc', ...
  [type=enum, input_value='AES-CBC + HMAC-SHA256-128', input_type=str]
```

`cipher_family.detect()` returns a human-readable suite name — encryption and
integrity joined into one string — and `InferenceService.apply()` assigned it
straight to `SecurityAssociation.encryption_alg`, which the contract types as
`Attribute[EncryptionAlg]`. `model_copy(update=...)` performs no validation, so
the bad object was built happily and detonated one layer later, when the
finished `Assessment` was validated.

**Why the whole suite missed it.** Every cipher-sieve test asserted on the
`Attribute` the sieve returns, and every degradation test drives a capture where
the sieve *refuses* — an ESP-only capture, a truncated one, a single-length one.
Nothing carried a **successful** inference through `SecurityAssociation` into
`Assessment`. The one path that mattered in production was the one path with no
end-to-end coverage.

The fix does more than cast the value:

- `CipherCandidate` now carries `encryption_alg: EncryptionAlg` and
  `integrity_alg: IntegrityAlg` alongside its display `name`. The contract
  stores those as two separate fields and the sieve now answers them separately.
- `detect_encryption()` and `detect_integrity()` produce the enum-typed
  attributes. `detect()` is retained, documented as *display prose only*, and a
  test asserts its output is not a member of `EncryptionAlg`.
- **Confidence is now computed per field**, counting distinct values of *that*
  field among the survivors rather than the survivor count. This is a real
  gain, not bookkeeping: lengths congruent to 28 mod 4 leave four suites
  standing that name four ciphers but only two integrity algorithms — three
  are AEAD and take `none` — so the same evidence pins integrity down harder
  than the cipher, and the two confidences now say so. `confidence_for()` and
  LLD §7.2's ranking are unchanged for the suite label.
- `detect()`, `detect_encryption()` and `detect_integrity()` share one `_sieve()`
  gate, so they cannot drift into disagreeing about whether a capture was usable.
- `apply()` fills `integrity_alg` as well, and only where Track A left the field
  unavailable. An inference still never overwrites a parsed fact.

Five regression tests, including one that drives a lattice-sufficient capture
through `analyse_capture()` into a validated `Assessment` — the coverage gap
itself, closed.

An interim version of the fix refused to answer whenever survivors disagreed.
That was wrong: it discarded LLD §7.2's ranking-plus-confidence design and made
step 9.2's **Done when** unreachable. Ambiguity belongs in the confidence.

### Verified — the API end to end, against a running server

`uvicorn analyzer.api.main:create_app --factory` → upload → analyze → poll →
assessment → both PDFs, on SQLite, with a 78 KB 398-packet ESP-only capture:

| Step | Result |
|---|---|
| `GET /api/v1/health` | `{"status":"ok","database":"up","version":"0.1.0"}` |
| `POST /api/v1/captures` | 201, UUIDv7 id |
| `POST /api/v1/captures/{id}/analyze` | run id, `status: queued` |
| `GET /api/v1/runs/{id}` | reaches `succeeded`, `assessmentId` populated |
| `GET /api/v1/assessments/{id}` | score 100 `strong` — nothing proven wrong |
| `?format=executive` | 200, `application/pdf`, 12,918 bytes |
| `?format=technical` | 200, `application/pdf`, 32,042 bytes |
| unknown id | `application/problem+json`, RFC 9457 shape |

Recorded as MT-21. This is what found the defect above, and it also
closed MT-20's outstanding Linux column.

### Deviations from the specs — API key casing

**The `Assessment` document is served in `snake_case`, not `camelCase`.**
[CLAUDE.md](CLAUDE.md) says conversion to camelCase happens at the API boundary
via Pydantic aliases, and the *envelope* types do exactly that — `runId`,
`captureId`, `assessmentId`. The assessment document itself does not:
`GET /api/v1/assessments/{id}` returns `security_associations`,
`capture_quality`, `model_versions`.

This is deliberate and consistent from end to end — the generated
`frontend/src/lib/types.ts`, the fixture files and the report templates all use
snake_case for the document — but it *is* a divergence from the stated rule and
was not previously written down. The reason to keep it: the document is stored
verbatim as JSON and served verbatim, which is what makes NFR-4's
byte-identical guarantee checkable against what the API actually returns.
Re-casing on the way out would put a transformation between the determinism
test and the wire. Whoever wants one convention everywhere should change
CLAUDE.md or the storage format, not add a re-caser to the read path.

### Fixed — cross-platform: the backend now starts on Windows

Not a plan step. `uv run uvicorn analyzer.api.main:create_app --factory`
failed outright on Windows with `OSError: cannot load library
'libgobject-2.0-0'`, and the same import took `test_api.py`, `test_api_jobs.py`
and `test_reports.py` down at **collection**, so a third of the suite could not
even be enumerated. NFR-6 wants this stack runnable on an analyst's own
machine; two thirds of that promise was Linux-only.

**WeasyPrint is no longer a startup dependency** — `report/render.py`
- WeasyPrint's cffi bindings `dlopen` Pango, Cairo and GObject at *import*
  time, so a module-level `from weasyprint import CSS, HTML` fails on any
  machine without a GTK stack — every stock Windows install. The traceback
  named `libgobject-2.0-0` and read like a broken Python package, which is
  why it did not point at the report renderer.
- The import moved into `_weasyprint()`, called only by `render_pdf`.
  `render_html` is Jinja2 and nothing else, so the HTML path — and therefore
  the whole API, the pipeline, and both dashboards — no longer depends on a
  PDF toolchain being present.
- **Both outcomes of the probe are cached.** `functools.cache` would only have
  memoised the success: it re-raises without storing the exception. A failed
  import is not cached in `sys.modules` either — Python discards the half-built
  module — so without the module-level `_PDF_BACKEND_FAILURE` sentinel, every
  report request on a GTK-less machine re-ran the dlopen probe and re-printed
  WeasyPrint's multi-line installation banner to stdout.
- `pdf_backend_available()` exposes the probe for tests and callers that can
  degrade.

**A missing PDF backend is a 503, not a 500** — `api/errors.py`,
`api/routes/reports.py`
- New `DependencyUnavailableError`. The request was valid and the assessment
  is readable; this deployment simply cannot render it to PDF, and retrying
  unchanged will fail identically until an operator installs something. A 500
  would have said "we crashed", which is both wrong and unactionable.
- The `detail` carries the remedy per platform *and* points at `?inline=1`,
  because the person reading the error is the person who can fix it. Safe to
  expose: it names packages, never anything about the machine.

**The fake `tshark` runs on Windows** — `tests/_fakebin.py` (new)
- Five Track A tests wrote a `#!/bin/sh` fake and executed it. Windows
  `CreateProcess` refuses a file with no recognised executable format, so they
  died with `WinError 193 — %1 is not a valid Win32 application`, which says
  nothing about shebangs.
- The behaviour is now expressed as data (`stdout`, `stderr`, `exit_code`) and
  rendered into whatever the platform can launch: a shebanged Python script on
  POSIX, a `.cmd` shim beside a Python body on Windows. Python on both sides
  rather than shell-and-batch, so there is one set of quoting rules and the
  fake cannot drift between platforms. Step 4.1 keeps its real subprocess
  coverage on both.

**CI ordering** — `scripts/ci-local.sh`, `.github/workflows/ci.yml`
- `next build` now runs before `tsc --noEmit`. Next 16 generates its
  typed-route definitions under `.next/types` during a build, so on a clean
  checkout the type check failed with ~10 phantom `PageProps` errors before
  the build that would have satisfied it. Both files were wrong in the same
  way; both are fixed.

**The WeasyPrint guard test now supplies its own configuration** —
`tests/test_reports.py`
- `test_importing_the_api_does_not_import_weasyprint` spawns a subprocess that
  calls `create_app()`, which validates settings eagerly and so requires
  `DATABASE_URL`. On a developer machine the repo-root `.env` satisfies that
  silently; CI has no `.env` and its pytest step sets `TEST_POSTGRES_URL`, not
  `DATABASE_URL`. The child died with `ConfigurationError` and the test failed
  on Linux for a reason unrelated to what it guards.
- The child now gets an explicit `DATABASE_URL=sqlite+aiosqlite:///:memory:`
  (no connection is opened — `create_app` only constructs the engine), and
  `check=True` gave way to asserting on `returncode` with the child's `stderr`
  as the message, so the next failure of this kind names itself instead of
  arriving as a bare `CalledProcessError`.

Verified on Windows 10: `uv run pytest` is **514 passed, 62 skipped, 0
failed** (was 5 failed plus 3 collection errors). `uvicorn` starts,
`/api/v1/health` returns 200, and upload → analyse → assessment → HTML report
completes end to end. `ruff`, `ruff format` and `mypy --strict` are clean.

### Not verified — cross-platform fix

- **The Linux side of this change has not been re-run here.** The reasoning
  holds on both — a lazy import cannot break an eager one, and `_fakebin.py`'s
  POSIX branch writes the same shebanged script the old helper did — but the
  suite was run on Windows only. CI covers Linux on the next push.
- **The 503 path is tested by monkeypatching `render_pdf`**, plus the real
  unpatched 503 observed against a live server on this machine. What has not
  been observed is a Linux box that has WeasyPrint installed *correctly*
  producing the same PDFs as before; the PDF assertions skip here rather than
  pass.
- **`MT-20` is new and unrun on Linux** — see `manualtesting.md`.

### Added — Phase 11, hardening (partial: 11.1–11.4 and 11.7)

**11.1 Degradation suite** — `tests/test_degradation.py`
The step the plan says is "most likely to be dropped under time pressure and
the one most likely to save the demo". All five degraded inputs pass, and each
assertion checks two things — that the value is absent *and* that the reason is
present, because an UNAVAILABLE with an empty note passes a weaker test and
fails a real analyst:
- **ESP only** — no IKE anywhere. `encryption_keylen` comes back unavailable,
  which is FR-4.9 made executable, and the pipeline still produces a complete
  assessment rather than erroring.
- **Truncated** — `tcpdump -s 96`. The cipher sieve refuses rather than
  sieving on the snaplen.
- **Single-length** — the VoIP case that is guaranteed to appear in the PRD
  §16 demo. One distinct length is not diversity, and the detector says so.
- **One-directional** — a legitimate analyst situation, not an error: one
  flagged unpaired SA, no fabricated responder SPI.
- **IKE mid-stream** — `has_ike` true, `ike_complete` false, and Track A does
  not treat the former as the latter.
- Plus a **control**: given a complete capture, Track A must actually observe
  something. Without it the whole suite would pass by reporting UNAVAILABLE
  for everything always.

**11.2 DB portability** — the full API suite now runs on SQLite *and*
PostgreSQL, not just the model layer. An endpoint that works on one and not the
other is exactly the failure a model-only test survives. The Postgres half
skips locally and runs in CI, which already provisions the service.

**11.3 Performance** — `tests/test_performance.py`. A 100 MB, 171,901-packet
capture analyses in **1.67 s** against NFR-1's 60-second budget. See Not
verified for what that number excludes.

**11.4 Offline stack** — `docker-compose.offline.yml`, plus the frontend
Dockerfile and the backend Dockerfile's API entrypoint.
- The backing network is `internal: true`, so Docker creates no gateway off
  the box for it. The backend publishes **no port at all** and is reachable
  only through the frontend's proxy route. NFR-6 becomes a property of the
  topology rather than a promise about the code.
- The backend image gained Pango, Cairo and the DejaVu fonts (WeasyPrint fails
  at import without them, with an error that reads like a Python problem and is
  not) and `alembic.ini`, which the compose file's migration step needs.

**11.7 Documentation** — README now states Gate G3 and, in the same breath,
says plainly that no model has been trained and that tshark's field names are
unverified. `manualtesting.md` gains MT-17 (both reports read correctly to
their audience — run and passed), MT-18 (offline stack, not run) and MT-19
(demo rehearsal, not run).

### Not verified — Phase 11

- **The 1.67 s figure excludes Track A.** tshark is not installed here, so that
  stage raised and was skipped; the measurement is ingest + Track B + assess.
  tshark over a 100 MB capture is not free and the number will move. NFR-1 is
  met with room to spare, but not yet on the whole pipeline.
- **The offline stack has never been started** (MT-18). Both Dockerfiles are
  written and the frontend's standalone build is verified, but `docker compose
  up` has not run, so the `internal: true` isolation is a claim about the file
  rather than an observed result.
- **Step 11.5 (demo captures) and 11.6 (rehearsal) were not performed.** 11.5
  needs the testbed to generate the two PRD §16 captures; 11.6 needs 11.5 and
  a running offline stack. Both are Docker-blocked.
- **Step 11.8 (demonstration video) was not produced.** It needs a rehearsed
  demo to record.

### Added — Phase 10, reports

Implementation-plan steps 10.1–10.4. Fully verified: both formats render to
real PDFs from the step 1.4 fixtures.

**10.1 Template scaffolding** — Jinja2 plus WeasyPrint, `report/templates/`
- Print styling rather than screen styling: A4, real margins, running headers,
  page numbers, `break-inside: avoid` on findings so one never splits across a
  page boundary.
- Rendering takes an `Assessment` and nothing else — no database, no network —
  so a report is reproducible from its stored document alone, years later,
  without the capture or the policy file that produced it.

**10.2 Executive report** — two pages, business language
- Leads every finding with its consequence, not its mechanism. **No hex and no
  packet indices**, asserted directly against the fixture's own SPI and
  evidence-method strings.
- Says explicitly that nothing was guessed to fill a gap, and explains why
  metadata exposure does not improve when the cryptography does.

**10.3 Technical report** — every finding with its evidence
- Full parameter table with provenance per row; an unavailable value renders
  as its **reason**, matching the dashboard's `AttributeCell` rather than
  diverging from it.
- Carries PRD §7's capability matrix — including the rows that say "not
  determinable", which is the point of printing it — and a limitations section
  stating the AES key-length case explicitly, plus the anti-replay window and
  the sequence-gap distinction from LLD §7.5.
- When no model ran, the report says so rather than letting a reader assume
  one did.

**10.4 Report endpoints** — `GET /assessments/{id}/report?format=…`
- Streams `application/pdf` with a filename. The query parameter is `format`
  because LLD §9 specifies that wire name; the Python parameter is aliased so
  it does not shadow the builtin.
- `?inline=1` returns the HTML, which is what you want when iterating on a
  template — the PDF renderer is the slow part and the HTML is what changed.

### Added — Phase 9, Track B (partial: the deterministic half)

**Steps 9.6–9.10 and 9.12 were not performed.** Every one of them trains or
evaluates a model on the Phase 8 dataset, which needs Docker and does not
exist. No model was faked, no accuracy number was invented, and no
`models/` artefact was committed.

What *did* land is everything in Track B that needs no training data — which
includes the step the plan marks "never cut".

**9.2 Cipher family detector** — `track_b/cipher_family.py`
- LLD §7.2's congruence sieve over the eight candidate suites. A **single**
  counterexample eliminates a candidate: this is a sieve, not a vote, so 399
  agreeing packets do not outvote one that disagrees (asserted).
- Survivors are ranked by constraint strength — a 16-byte block survived a
  stricter test than a 4-byte one on the same evidence — and the **full
  survivor set** goes into the evidence, not just the winner.
- **The refusals are the point.** Truncated capture, insufficient length
  diversity, or no surviving candidate all return UNAVAILABLE with the reason.
  AES-GCM-16 and ChaCha20-Poly1305 have *identical* geometry, so a GCM capture
  correctly reports two survivors and a confidence below 1.0 rather than
  picking one and sounding certain.

**9.3 Replay and lifetime** — `track_b/replay.py`
- `replay_sane` means "sequence numbers behave correctly on the wire", not
  "anti-replay is enabled", and the note says so. Gaps are counted and
  explicitly **not** called an attack — capture drops and reordering
  middleboxes produce the same pattern.
- `anti_replay_window_size()` takes no arguments and always returns
  UNAVAILABLE. There is no input that could change the answer: the window is a
  receiver-side local setting that is never transmitted (LLD §7.5).

**9.4 PFS inference** — `track_b/pfs.py`
- `CREATE_CHILD_SA` size delta against the group's KE payload size. MODP
  groups get 0.9 confidence; **ECP groups get 0.65**, because a 64-byte delta
  overlaps ordinary traffic-selector variation and a flat confidence there
  would invite exactly the misplaced trust PRD §8.3 warns about.

**9.1 Feature extractor** — `track_b/features.py`
- Every feature group from LLD §7.1 in Polars, plus the 128-value signed
  sequence for the CNN. No NaNs and no infinities on short flows,
  single-packet flows, or one-directional captures — all asserted.

**9.11 Inference service** — `track_b/service.py`, wired into `api/pipeline.py`
- Runs the deterministic analyses for real and reports UNAVAILABLE **with the
  reason** for the model-backed ones. The seam is the finished shape: when
  models arrive, nothing downstream changes — the pipeline stage, the
  attribute types, the dashboard cell and the policy's confidence guards are
  all already correct.
- Track A's observations are never overwritten by an inference. The cipher
  sieve only speaks where Track A could not, which is the ESP-only case.

### Fixed — Phase 9

- **A non-determinism bug in the feature extractor**, caught by its own test.
  `Series.mode()` returns ties in arbitrary order, and when every packet
  length is distinct *every* value is a mode — so `esp_len_modal` differed
  between two runs over identical input. That would have broken NFR-4 and, far
  worse, put a column that changes run-to-run into a training matrix.

### Not verified — Phase 9

- **No model has been trained or evaluated.** Steps 9.6 (LightGBM baseline),
  9.7 (CNN, macro-F1 ≥ 0.85), 9.8 (calibration, ECE ≤ 0.10), 9.9 (mode
  classifier), 9.10 (SHAP) and 9.12 (ISCXVPN2016 validation) all require the
  Phase 8 dataset. PRD §8.4's targets are therefore unmet and unmeasured — not
  missed, unmeasured.
- **The sieve has never seen a real ESP capture.** Its candidate geometry is
  RFC-derived and its tests construct lengths from that same table, so they
  prove the sieve implements the rule, not that real strongSwan traffic obeys
  it. The Phase 2 spike (CHANGELOG above) did confirm the premise on 60 real
  packets, which is the closest thing to independent evidence available here.
- **PFS inference has no real `CREATE_CHILD_SA` sizes to work from**, because
  Track A does not yet extract exchange sizes; `service.analyse` passes empty
  lists, so PFS reports UNAVAILABLE in the live pipeline today. The inference
  itself is tested against constructed sizes.

### Added — Phase 8, dataset generation (partial: 8.2 and 8.4 only)

**Steps 8.1 and 8.3 were not performed.** Both generate sessions with real
tunnels and need a Docker daemon plus a kernel with XFRM; neither was
available. Nothing was faked to stand in for them — `dataset/sessions/` does
not exist, and `dataset/dataset.md` says so in its second paragraph rather
than describing data that is not there.

**8.2 Label verification harness** — `testbed/verify.py`
- `python -m testbed.verify <batch-dir>` compares Track A's output against
  every `labels.json` in a batch.
- **The classification rule is the whole point of this step**, and a strict
  equality check would have been actively harmful. Six outcomes, of which only
  two fail:
  - `match` — observed and equal.
  - `honest_gap` — ground truth's `not_observable_from_ike` says no parser can
    recover this field, and Track A said `UNAVAILABLE`. A **pass**. Without
    this, the easiest way to turn the harness green would be to teach the
    parser to guess.
  - `inferred` — reported as an inference. Not scored either way. This is the
    resolution of **Phase 4's open spec question**: the matrix runs IKE on CBC
    while ESP carries AEAD, so Track A's same-family inference is *expected* to
    diverge on every GCM row, and counting that as a failure would mean the
    harness only passes if Track A lies.
  - `mismatch` — observed and wrong. A real parser bug.
  - `fabricated` — a value reported where ground truth says the field is not
    observable. **The most serious outcome the harness can produce**, worse
    than a mismatch, because it is a guess the report would present as a fact.
  - `not_reported` — unavailable where ground truth expects a value; a parser
    that gave up, which is not the same as a field that cannot be read.
- 11 tests over constructed ground truth and constructed parser output. One of
  them caught a wrong lifetime in its own fixture on first run, which is the
  behaviour being asked for.

**8.4 Dataset documentation** — `dataset/dataset.md`
- Schema, generation procedure, the three-block `labels.json` contract, the
  pinned tool versions and why they must not drift, licence and provenance
  (synthetic throughout; no real traffic, no personal data), and the DVC
  layout.

### Not verified — Phase 8

- **Steps 8.1 (20-session pilot) and 8.3 (≥200 sessions) have not been run.**
  They need Docker. The harness that would grade them exists and is tested;
  what it has never seen is a real capture.
- **DVC is documented but not initialised.** `dataset/sessions.dvc` and a
  configured remote both belong to a run that has not happened; creating them
  empty would be scaffolding pretending to be a dataset.
- **Step 8.5 (ISCXVPN2016 adapter) is deferred to Phase 9**, where the feature
  extractor it must map onto (step 9.1) is defined. Building an adapter to a
  schema that does not exist yet would be guesswork.

### Added — Phase 7, frontend

Implementation-plan steps 7.1–7.12. Next.js 16 with the App Router, built
against the step 1.4 fixtures throughout — every view below was verified
rendering with the backend process not running at all.

**7.1–7.3 Scaffold, proxy, and the fixture-backed data layer**
- `app/api/[...path]/route.ts` forwards to the backend with `runtime = "nodejs"`
  and streams SSE straight through: hop-by-hop headers are stripped per RFC
  9110 §7.6.1, and `x-accel-buffering: no` is set on event streams, because
  anything that buffers turns a live progress bar into a jump from 0 to 100.
- `USE_FIXTURES=1` serves every read from the two fixtures, including a
  locally-computed comparison. **Verified**: the whole dashboard renders with
  the API offline.

**7.4 AttributeCell** — the most important component in the product
- Three renderings at three visual weights. Observed is plain and undecorated;
  inferred carries a confidence bar (coloured by band) plus the note and
  evidence; **unavailable renders the reason in prose**. Verified on the weak
  fixture's configuration view: 8 unavailable attributes, each showing its
  actual explanation ("IKEv1 does not negotiate a PRF as a separate
  transform…"), and not one dash.

**7.5, 7.6 Upload and live progress**
- Upload uses `XMLHttpRequest`, not `fetch`, because `fetch` has no upload
  progress event and a 2 GB PCAP behind a motionless spinner is
  indistinguishable from a hang.
- `RunProgress` consumes the SSE stream with `EventSource` and shows the full
  stage list, not just completed stages — a bar that hides what has not
  started yet also hides where a stalled run is stalled.

**7.7–7.9 Assessment layout, overview, configuration, findings**
- Score header with the rating, metadata exposure (labelled as inverted,
  because it is), severity breakdown, category penalty attribution, and
  capture quality including whether the cipher-family sieve could run at all.
- Findings filter and sort client-side; NFR-2 budgets 200 ms for a view change
  and a round trip per click does not fit in it.

**7.10–7.12 Traffic, threats, comparison**
- The traffic timeline gives each label its own series so the 50%-overlapping
  prediction windows render without collision, and says in the caption that
  the confidence *is* the leakage measurement.
- The threat grid links each ATT&CK technique through to its contributing
  findings.
- The comparison view renders the weak/hardened pair side by side — 15 vs 90,
  with changed rows highlighted and provenance shown next to each value.

### Added — Phase 6, API and jobs

Implementation-plan steps 6.1–6.8. Also fully verified: every endpoint is
driven over ASGI against a real SQLite database in the test suite.

**6.1 FastAPI skeleton** — `api/main.py`, `api/deps.py`
- `create_app()` builds everything onto `app.state`, so a test stands the whole
  API up against a throwaway database without patching a module global.
- `/api/v1/health` reports `degraded` with a 200 rather than a 503 when the
  database is unreachable. A 503 reads to a load balancer as "take this
  instance out", which is the wrong response to a Neon endpoint that is merely
  cold.

**6.2 Problem Details** — `api/errors.py`
- Every error shape FastAPI can produce — `ApiError`, Starlette's
  `HTTPException`, request validation, and anything unhandled — is routed
  through one `problem_response`. The unhandled case is deliberately opaque:
  an exception message can carry a connection string, and NFR-6 keeps analyst
  data local, error text included.

**6.3, 6.4 Upload and CRUD** — `api/routes/captures.py`
- Streams to a staged temp file in 8 MB chunks, hashing as it goes; the size
  cap and the magic-byte check both apply before anything reaches its final
  path, so a rejected upload leaves nothing behind (asserted).
- Re-uploading identical bytes returns the existing capture rather than a 409:
  an analyst re-uploading a capture they already have wants the row they own.
- Delete removes the row *and* the stored PCAP.

**6.5 Pipeline orchestrator** — `api/pipeline.py`
- ingest → Track A → Track B (stub) → assess → persist. Track A failing —
  no IKE in the capture, or no tshark on the host — is a *degraded* analysis,
  not a failed one: every IKE-derived attribute becomes UNAVAILABLE with a
  reason and the run still produces an assessment.
- Persistence writes the document and its denormalised `findings` and
  `security_associations` rows in one transaction.

**6.6 Background jobs and SSE** — `api/jobs.py`, `api/routes/runs.py`
- `asyncio.Semaphore` bounds concurrency; the CPU stages run in a
  `ProcessPoolExecutor`. The SSE stream matches LLD §9's wire format exactly.
- The event bus **replays history to a late subscriber**. Without it a
  dashboard that opens the stream a moment after POSTing misses the first
  stage, and a run that finished before anyone subscribed streams nothing.

**6.7 Assessment endpoints** — `api/routes/assessments.py`
- Findings are served from the relational table with real SQL filtering and
  ordering; the document endpoint returns the stored mapping as-is rather than
  round-tripping it through Pydantic, so a later contract change cannot
  silently rewrite an assessment that was already issued.
- `/assessments/compare` diffs scores, finding sets, and every
  provenance-carrying attribute — the backbone of the step 7.12 view.

**6.8 OpenAPI type generation** — `scripts/gen-types.sh`
- Dumps the schema without starting a server and runs `openapi-typescript`
  into `frontend/src/types/generated.ts`. `--check` mode is wired into
  `ci-local.sh`, so a Pydantic change the frontend has not absorbed fails the
  build.

**Testing**
- 27 new tests covering every endpoint, both error paths, the semaphore bound,
  the event bus, and the real process-pool path.

### Fixed — Phase 6

- **`Assessment` could not cross a process boundary.** `Attribute[T]` is a
  *parametrised* generic Pydantic model, and a parametrised generic has no
  importable module-level name, so `Attribute[IkeVersion]` is unpicklable and
  the whole document with it. LLD §9's `ProcessPoolExecutor` requirement was
  therefore unimplementable as written. The worker now returns
  `model_dump_json()` and the parent re-validates — JSON is the form the
  document is stored in anyway. Found by actually running the pool path rather
  than by reading it.
- **`JobRunner.aclose()` did not await the runs it cancelled**, so a cancelled
  run's failure-marking path could touch an engine the caller had already
  disposed. It now gathers them.
- **The analyze handler held a SQLite write lock across its own response.**
  The background job's first write is `_mark_running`, which blocked behind the
  request's still-open transaction until the request finished. The handler now
  commits before submitting, and `get_session` checks `in_transaction()` rather
  than assuming it still owns one.

### Added — Phase 5, assessment engine

Implementation-plan steps 5.1–5.9. Unlike Phases 3 and 4, **this phase is
fully verified**: the engine is a pure function of fixture input (LLD §8.2),
so nothing here needed Docker, tshark, or a capture.

**5.1, 5.2 Policy schema, loader and confidence guard** — `assess/policy.py`
- `Condition` is either a leaf (`attribute`/`operator`) or a composite
  (`all`/`any`), with LLD §8.1's operator set exactly: `eq`, `in`, `lt`, `gt`,
  `confidence_gte`.
- Malformed YAML fails with a real line and column from the parser's own mark;
  a schema error resolves the offending rule's `id:` back to its line number,
  because "rules.3.penalty" alone is not a usable message for someone editing
  a policy file.
- **The confidence guard is a load-time error.** A rule keyed on any attribute
  that can arrive `INFERRED` must carry a `confidence_gte` on that same
  attribute or the policy refuses to load. `INFERABLE_ATTRIBUTES` is
  deliberately a denylist of what can be inferred rather than an allowlist of
  what is always observed: a newly-inferred attribute that nobody remembers to
  list would otherwise slip past the guard silently, whereas a newly-observed
  one listed here costs only a redundant guard.

**5.3 Baseline policy** — `assess/policies/baseline.yaml`
- All 14 rules from the step 5.3 minimum set, each with severity, penalty,
  a description explaining the actual attack, remediation naming the exact
  strongSwan parameter and value (FR-5.7), standards references and ATT&CK IDs.
- Every rule's penalty is validated against its own category cap at load.
  ("Penalties sum within the category caps" is read as *per rule*, not as the
  sum across a category — 3DES alone is 30, the whole cryptographic cap, and
  the fixtures themselves carry categories summing past their caps for the
  scorer to clamp.)

**5.4 Rule evaluator** — `assess/engine.py`
- An `UNAVAILABLE` attribute matches nothing, ever. Firing a rule against a
  value the capture never showed is exactly the fabrication the provenance
  system exists to prevent, so this is a hard rule rather than a default.
- `confidence_gte` treats `OBSERVED` as passing any threshold (a parsed fact
  carries no confidence by construction), `UNAVAILABLE` as never passing, and
  `INFERRED` as passing only above the bar.
- Three **derived attributes** (`metadata_exposure_confidence`,
  `rekey_observed`, `sa_duration_s`) are computed per SA because three of the
  required rules cannot be expressed against contract fields alone — see
  Deviations.

**5.5, 5.6 Scoring and metadata exposure** — `assess/scoring.py`
- Category caps consumed by the most severe finding first, floor at zero, per
  LLD §8.3. Rating bands are 20 points wide (`RATING_BANDS`); the contract
  explicitly left the thresholds to this step, and these put the two PRD §16
  demo tunnels at opposite ends without having been drawn to flatter them.
- Exposure scales from the 1/7 chance level (LLD §8.4), so a classifier that
  learned nothing scores 0 rather than 14. Both fixtures' stored exposure
  scores (95 and 92) are reproduced exactly by the formula.

**5.7, 5.8 Threat matrix and evidence caps**
- Findings grouped by ATT&CK technique with the PRD §10.3 names and tactics.
- `capped_evidence()` truncates `packet_indices` to 20 and records
  `total_matching` — a finding matching 100,000 packets serialises to well
  under 2 KB.

**5.9 Determinism (NFR-4)**
- `evaluate()` takes `assessment_id`, `capture_id` and `generated_at` as
  arguments rather than generating them, so two runs over identical input
  produce byte-identical JSON. Both the identical-run and the
  differs-only-by-injected-identity cases are asserted.

**Testing**
- 55 new tests. The engine reproduces **both fixtures exactly**: the same
  finding IDs, the same severities, categories and penalties per finding, the
  same category penalty breakdown, the same total, the same rating, and the
  same exposure score — for a policy file written from the specs rather than
  reverse-engineered from the fixtures.

### Deviations from the specs — Phase 5

- **`SecurityAssociation` gained `downgrade_available: Attribute[bool]`.**
  LLD §6.3 puts `downgrade_available` on Track A's `IkeNegotiation` and step
  5.3 requires a `CRYPTO-DOWNGRADE-OFFER` rule, but LLD §3 gave the value
  nowhere to live in the document the rule evaluates — the rule was
  unimplementable as specified. The contract was changed first and propagated:
  Track A's `correlate.py` now populates it, both step 1.4 fixtures carry it,
  and `tests/test_contract.py`'s builder sets it. No migration was needed;
  SAs are stored as JSON.
- **Three derived attributes extend the policy language.** LLD §8.1 only
  contemplates rules keyed on `SecurityAssociation` fields.
  `META-HIGH-EXPOSURE` needs an aggregate over `inner_traffic`, and
  `KEYMGMT-NO-REKEY-OBSERVED` needs both whether a rekey was seen and how long
  the SA was watched — "no rekey in a three-minute capture" is a fact about the
  capture, not the deployment, so the rule carries a 2-hour observation floor.
- **`Evidence.measured` on generated findings is thinner than the fixtures'.**
  The hand-written fixtures carry rich domain measurements
  (`sweet32_safe_data_gb`, `modp_prime_bits`); the engine records the attribute
  values the rule actually tested. Step 5.4's Done-when is about finding IDs,
  and inventing measurements a rule did not compute would be the same
  fabrication problem in a different field.

### Added — Phase 4, Track A

Implementation-plan steps 4.1–4.8.

**4.1 tshark invocation wrapper** — `track_a/ike_parser.py`
- `run_tshark()` shells out to `tshark -r <pcap> -Y isakmp -T json
  --no-duplicate-keys` per LLD §6.1, parses the JSON, and raises `TrackAError`
  with the actual cause for a missing binary, a non-zero exit, a timeout, or
  output that is not valid JSON. `--no-duplicate-keys` is load-bearing: without
  it, tshark's default JSON rendering overwrites a repeated field (a second
  proposal, a second transform) instead of producing a list.

**4.2, 4.3 SA payload extraction** — `track_a/transforms.py`, `ike_parser.py`
- The IANA-registered numeric IDs (RFC 7296 §3.3.2 for IKEv2, RFC 2409
  Appendix A for IKEv1) live in `transforms.py` and do not depend on
  Wireshark's JSON field *naming* — only on protocol constants that do not
  drift. All of the naming risk LLD §6.1 warns about is deliberately
  concentrated in one function, `ike_parser.py`'s `parse_isakmp_json()` and
  its helpers, so a future field-name correction touches one place.
- IKEv1's exchange mode (main = 2, aggressive = 4) and IKEv2's SA-payload
  transform types (1 ENCR, 2 PRF, 3 INTEG, 4 DH, 5 ESN) both come out of the
  same `Proposal`/`Transform`/`TransformAttr` IR, despite IKEv1 encoding
  everything as attributes of one monolithic transform and IKEv2 splitting
  them into distinct transform types.

**4.4 Proposed vs selected** — `IkeNegotiation` in `ike_parser.py`
- `build_negotiations()` groups messages by `init_spi` and treats the
  earlier-captured message with an SA payload as proposed, the later as
  selected — needing no per-version "which message is the response" field,
  since IKEv1 has no such flag at all and capture order settles it for both.
- `downgrade_available` walks every ENCR choice in every offered proposal
  (not just the first) against a deliberately coarse strength ranking
  (`transforms.is_weaker_encryption`): family first — NULL < DES < 3DES <
  everything AES/ChaCha-sized — then key length within a family. An unmapped
  transform ID is unknown strength, never treated as weaker by default.

**4.5 Lifetime handling**
- IKEv1 attributes 11 (Life Type) and 12 (Life Duration) map to
  `negotiated_lifetime_s` only when Life Type is seconds (1), not kilobytes
  (2). IKEv2 is `None` unconditionally in the IR and `UNAVAILABLE` in the
  assembled `SecurityAssociation` — RFC 7296 removed lifetime negotiation.

**4.6 SPI correlation** — `track_a/correlate.py`
- **Child SA SPIs are not observable from either IKE version**, and this
  governs the whole step. IKEv1 proposes Child SA parameters in Quick Mode,
  IKEv2 in `IKE_AUTH`/`CREATE_CHILD_SA` — both encrypted under keys derived
  from the exchange above them, so tshark shows neither the SPI nor the
  transforms without decryption keys nobody has. `correlate_negotiation()`
  therefore matches an ESP/AH flow to the negotiation that plausibly created
  it by outer endpoints plus timing (`CORRELATION_WINDOW_S = 30s`) instead —
  the most recent negotiation between the same two addresses that completed
  before the flow's first packet.

**4.7 NAT-T and auth method**
- NAT-T: `NAT_DETECTION_SOURCE_IP` (16406) / `_DESTINATION_IP` (16407) notify
  payloads, checked on both the request and response side of a negotiation.
- Auth method: IKEv1 transform attribute 3, mapped through
  `transforms.ikev1_auth_method`. IKEv2 is `UNAVAILABLE` unconditionally — the
  AUTH payload is inside `IKE_AUTH`, and the parser does not fabricate a value
  there.

**4.8 Track A → SecurityAssociation** — `track_a/correlate.py`
- `assemble_security_association()` is where LLD §6.4's distinction becomes
  concrete and where most of this step's design judgement sits.
  `SecurityAssociation`'s crypto fields (`encryption_alg`, `encryption_keylen`,
  `integrity_alg`) describe the **Child/ESP SA** — the thing that actually
  encrypts traffic — but Track A can only ever observe the **IKE SA's own**
  proposal (§4.6: the Child SA's is encrypted for both IKE versions). These
  three fields are therefore `INFERRED` same-family guesses from the IKE SA's
  values, at a deliberately moderate confidence (0.6), with a note explaining
  why — never `OBSERVED`, per LLD §6.4's explicit instruction not to dress an
  inference up as a fact.
- `dh_group` and `prf_alg` are the exception and are genuinely `OBSERVED`:
  both belong to the IKE SA's *own* `IKE_SA_INIT`/Phase 1 proposal, not to a
  guess about the Child SA, so there is nothing inferred about them.
- `operating_mode`, `pfs_enabled`, `observed_rekey_s` and `replay_sane` are
  honestly `UNAVAILABLE` — they are Track B's job (steps 7.3, 7.4, 7.5 /
  9.x), not yet built, and Track A does not guess at them to look more
  complete than it is.

**Testing**
- 39 new tests, all against hand-built tshark JSON (`tests/_tshark_json.py`)
  rather than a real capture — no Docker or tshark binary was available in
  this environment (see CHANGELOG's Phase 2/3 entries for the same
  constraint). `run_tshark()` itself is still exercised as a genuine
  subprocess against a small fake `tshark` shell script, so step 4.1's
  process-and-JSON-parse path is real, even though the JSON it parses is not
  from a real tshark.
- Ruff, ruff-format and mypy strict clean. No new dependencies — Track A
  shells out rather than importing anything.

### Not verified — Phase 4

- **tshark's JSON field names, entirely.** This is the largest gap of the
  three phases landed so far. Where Phase 3's dpkt-based reader was checked
  interactively against the real, installed `dpkt` library, `ike_parser.py`'s
  `parse_isakmp_json()` was written from documented, long-stable `isakmp.*`
  display-filter names with no way to run it against a real `tshark -T json`
  output in this environment (no Docker, no `tshark`, and installing it needs
  interactive `sudo`). LLD §6.1's own warning — a field-name drift "silently
  breaks the parser" and produces wrong values, not an error — applies at
  full strength here. The adapter reads defensively (multiple candidate keys,
  suffix-matching for the most deeply nested structures, tolerant integer
  parsing) specifically because of this, but that is a mitigation, not a
  verification. **Running this against one real IKEv1 and one real IKEv2
  testbed capture, comparing the raw JSON against this module's assumptions
  field by field, should be the first thing anyone with tshark available
  does with Track A.**
- **Step 4.8's actual Done-when** — a `SecurityAssociation` matching
  `labels.json` exactly for every parseable field, on a real testbed capture
  — has not been run. See the open spec question below for why "parseable"
  is doing real work in that sentence for this step specifically.
- **The correlation window (30s) is a documented guess**, not tuned against
  real inter-arrival timing between an IKE negotiation completing and its
  Child SA's first packet. LLD §10.2's session lifecycle only guarantees it
  is short, not exactly how short.
- **`downgrade_available`'s strength ranking is coarse by design** — everything
  AES-CBC/CTR/CCM/GCM-sized and ChaCha20 rank equally. It has not been asked
  to make a finer distinction than the LLD §6.3 example (3DES vs AES-256), and
  extending it without a rule that needs the extra precision would be
  speculative.

### Deviations from the specs — Phase 4

- **`track_a/correlate.py` also holds `assemble_security_association()` and
  `run_track_a()`**, not just correlation. LLD §2's tree gives `track_a/`
  exactly three files (`ike_parser.py`, `transforms.py`, `correlate.py`) with
  no fourth file for assembly; assembling a `SecurityAssociation` *is*
  correlation's next step and belongs beside it rather than forcing a new
  module the plan does not list.
- **`Proposal`, `Transform`, `TransformAttr` and `IkeNegotiation` are this
  module's own schemas.** LLD §6.3 names `IkeNegotiation` and `Proposal`
  without giving either a field list (the same situation Phase 3's `SAPair`
  was in). `IkeNegotiation` also carries `request_frame`/`response_frame` —
  not mentioned anywhere in LLD — purely so assembled `SecurityAssociation`
  attributes can cite real packet indices in their `Evidence` instead of
  none at all.
- **`IsakmpMessage` carries no `is_response` field.** IKEv2 has an explicit
  flag for this; IKEv1 has none. Rather than reading an uncertain flag name
  for one version and inventing a fallback for the other, negotiations are
  built by capture order for both, which is simpler and equally correct as
  long as tcpdump's own ordering is trusted — which everywhere else in this
  project it already is.

### Open spec questions — Phase 4

- **LLD §6.4's same-family Child SA inference and this project's own testbed
   are in tension.** §6.4 assumes the common case is that a Child SA reuses
   the IKE SA's algorithm family — reasonable in general, but this project's
   *own* testbed (step 2.2's `ike_proposal_crypto`, Phase 2 deviations above)
   deliberately negotiates the IKE SA on CBC-plus-HMAC even when the ESP
   suite is AEAD, specifically because IKEv1 cannot negotiate AEAD for Phase
   1. That means the one dataset this project can generate on demand is
   exactly the case where step 4.8's same-family guess is *expected* to be
   wrong for every GCM-suite session — not an edge case, a matrix cell. Two
   fields in `labels.json`'s `expected` block (`encryption_alg`,
   `encryption_keylen`, `integrity_alg`) record the true Child SA suite,
   which a correctly-honest Track A cannot match by design once it differs
   from the IKE SA's family; the automated regression test for step 4.8 will
   need to treat these three as "must be `INFERRED` with a note", not
   "must equal `labels.json`", and that distinction needs to be explicit
   before step 8.2's label-verification harness is built, or it will flag
   correct, honest output as a mismatch.

### Added — Phase 3, ingest

Implementation-plan steps 3.1–3.6.

**3.1 PacketRecord and FlowKey** — `ingest/reader.py`
- Both `NamedTuple`s from LLD §5, exactly as specified.

**3.2 PCAP reader — IPv4** — `ingest/reader.py`
- Hand-rolled classic-pcap framing (global header, then per-record headers)
  rather than `dpkt.pcap.Reader`'s convenience iterator, because that iterator
  discards the per-record `orig_len` field and there is no public way to get
  it back — and `orig_len` vs `caplen` is exactly what step 3.6's `truncated`
  flag needs. `dpkt` still does every bit of header decoding: Ethernet, SLL,
  SLL2 and raw IP at the link layer; IPv4, IPv6, ESP, AH and UDP above it.
- Every frame produces exactly one `PacketRecord`, classified or not
  (`proto="other"` for anything else), so the reader's packet count is
  directly comparable to `tshark -r file | wc -l`.
- `esp_payload_len` is always the actual ESP ciphertext-plus-ICV length — the
  bytes left after ESP's own 8-byte SPI-and-sequence header — computed the
  same way regardless of encapsulation: raw ESP (protocol 50), NAT-T-in-UDP,
  or IPv6 via an extension header. A fixed subtraction from the declared IP
  payload length would be wrong for NAT-T by exactly the 8-byte UDP header,
  silently shifting every length-lattice congruence in LLD §7.2 for every
  NAT-T session.

**3.3 UDP 4500 disambiguation** — folded into `ingest/reader.py`
- First four bytes of a UDP/4500 payload: all-zero is the non-ESP marker
  (IKE), anything else is an ESP SPI. Port 500 is always IKE. A NAT-T
  keepalive (a single `0xFF` byte) is neither, and falls back to
  `proto="other"` rather than guessing or raising.

**3.4 IPv6 support** — `ingest/reader.py`
- `dpkt`'s IPv6 unpacker resolves ESP and AH as `extension_hdrs` entries
  rather than as `.data` — worth naming, since `ip6.p` is never set at all
  when the chain terminates in ESP (`IP6ESPHeader` has no `nxt` field for the
  walk to continue from). ESP is checked before AH; this project's testbed
  never negotiates AH-then-ESP.

**3.5 Flow assembly** — `ingest/flow.py`
- `assemble_flows()` groups ESP/AH packets by `FlowKey` and pairs
  reverse-direction flows whose time ranges overlap into `SAPair`. `SAPair`
  has no LLD §5 schema — the spec names it without one — so its shape
  (`forward`, optional `reverse`, `paired`) is this step's design decision,
  made to satisfy the Done-when wording exactly: one pair for a bidirectional
  capture, one flagged-unpaired pair for a one-directional one, never a raise.

**3.6 Capture quality** — `ingest/quality.py`
- Builds the `CaptureQuality` that already existed in `core/schema.py` (step
  1.3). `ike_complete` needed a signal `PacketRecord` deliberately does not
  carry — LLD §5's `NamedTuple` is fixed, and "no deep dissection" is the
  point — so the reader also returns `ike_message_ids`, a sidecar list of
  ISAKMP message IDs seen in passing while classifying `isakmp`/`isakmp_natt`
  packets, purely so `ike_complete` can check for message ID 0 without a
  second pass over the file.

**Testing**
- 27 new tests, all synthetic: no Docker was available in the environment this
  work was done in, so `tests/_pcap.py` builds classic-pcap bytes by hand
  (every supported link type, IPv4 and IPv6, ESP/AH/UDP) rather than depending
  on a real Phase 2 capture.
- Added `dpkt` as a runtime dependency and `dpkt.*` to mypy's
  `ignore_missing_imports` overrides — it ships no type stubs. Ruff,
  ruff-format and mypy strict clean.

### Not verified — Phase 3

- **Step 3.2's actual Done-when** — packet count against
  `tshark -r file | wc -l` on a real Phase 2 capture — could not be
  demonstrated: no Docker and no `tshark` were available in the environment
  this work was done in, and installing `tshark` needed interactive `sudo`.
  The synthetic-pcap tests exercise the same decoding paths but are not that
  comparison.
- **Steps 3.2–3.4 against a real testbed capture generally.** All decoding
  logic is validated against hand-built packets whose byte layout is believed
  correct; none of it has run against tcpdump/strongSwan's actual output yet.
- **NAT-T (step 3.3) still has no testbed data to validate against.** Open
  spec question 6 below (carried over from Phase 2) already flagged this: the
  matrix has no NAT dimension, so ESP is always raw protocol 50 in every
  testbed capture. Step 3.3's disambiguation is exercised only by synthetic
  packets until that gap is closed.
- **`esp_sa_count`'s definition.** LLD §5 does not define what counts as one
  ESP "SA" for `CaptureQuality.esp_sa_count`; this counts each *directional*
  flow, so a paired bidirectional tunnel counts as 2 — on the basis that a
  Child SA is unidirectional and each direction gets its own SPI. Worth
  confirming against how Phase 9 actually wants to consume this number.

### Deviations from the specs — Phase 3

- **`ingest/reader.py` does not use `dpkt.pcap.Reader`.** Its `__iter__`
  discards the per-record `orig_len` (the original wire length before snaplen
  truncation) that `truncated` in step 3.6 depends on, and there is no public
  accessor for it. The module parses the classic-pcap global and per-record
  headers directly — the same magic-number, endianness and nanosecond
  detection `dpkt.pcap` itself does — and hands frame bytes to `dpkt`'s
  link-layer and IP/IPv6/ESP/AH/UDP classes for everything past that. pcapng
  is out of scope: nothing in this project's pipeline writes it.
- **`IngestResult` wraps `read_packets`'s return value** rather than a bare
  `list[PacketRecord]`. LLD §5 fixes `PacketRecord`'s and `FlowKey`'s shapes,
  not the reader function's signature; `ike_message_ids` exists solely so
  step 3.6 can compute `ike_complete` without parsing the file twice.
- **`SAPair` is a new type**, not given a schema in LLD §5's code block. See
  step 3.5 above.

### Added — Phase 2, testbed

Implementation-plan steps 2.1–2.10, plus the two Phase 0 spikes (0.1, 0.2) they
depend on, which had not been run.

**0.1, 0.2 De-risking spikes**
- Kernel IPsec in Docker works on this host. Two containers on a user-defined
  bridge, an IKEv2 tunnel between them, ESP on the wire during a ping across the
  protected subnets.
- The packet-geometry premise of [LLD §7.2](docs/LLD.md) holds: for an
  AES-CBC-128 + SHA1 tunnel, `(esp_len - 16 - 12) % 16 == 0` for **60 of 60**
  captured packets, across two distinct payload sizes. The cipher-family sieve
  of step 9.2 can be built as designed.
- Both are now standing checks — [manualtesting.md](manualtesting.md) MT-12 —
  rather than a spike somebody remembers doing.

**2.1 Peer container image** — `testbed/Dockerfile.peer`
- One image serves both ends: strongSwan, tcpdump, and every generator the seven
  PRD §9.2 classes need, because the peers only ever talk to each other.
- **`kernel-libipsec` is deleted from the image**, and the build fails if it
  survives. It ships in Debian's `libcharon-extra-plugins` and would have loaded
  silently. [LLD §10.3](docs/LLD.md) is emphatic about why: Track B's entire
  feature set is packet geometry, and userspace ESP need not reproduce the
  kernel's padding, IV placement or MTU behaviour. Config can be edited; a
  deleted shared object cannot be loaded at 2am by someone debugging a stubborn
  host.
- strongSwan 5.9.8 and tcpdump 4.99.3 pinned and recorded in `pyproject.toml`
  beside the tshark pin, for the same reason: between them they decide the
  cryptography and the packet geometry the models learn from, so a silent
  upgrade mid-dataset would split the corpus in two with nothing failing. Every
  session copies `/etc/testbed-versions.json` into its labels.
- Aggressive-mode PSK is enabled, deliberately and only here. strongSwan refuses
  the combination by default because it exposes the PSK hash to a passive
  observer — which is exactly the weakness `ikev1-aggressive` exists in the
  matrix to generate, and what the weak-reference demo tunnel is built on.

**2.2 Config templating** — `testbed/config.py`, `render.py`, `templates/`
- `SessionConfig` is frozen and is both the input and the ground truth, so a
  config cannot be mutated between rendering and labelling.
- Matrix labels (`aes128gcm16`) and contract values (`EncryptionAlg.AES_GCM_16`
  plus a key length) are kept explicitly apart, with one mapping table between
  them. Conflating the two is how a dataset ends up mislabelled.
- Both sides render from one config, so the two ends of a tunnel cannot disagree
  about what they are negotiating — a failure that surfaces not as an error but
  as a tunnel that never establishes, twenty minutes into a batch.

**2.3 Peer lifecycle** — `testbed/peers.py`
- `peer_pair()` creates the network and both containers with fixed addresses and
  destroys everything on the way out, including on exception and cancellation.
  Cleanup failures are logged, never raised: they must not mask the exception
  that caused them.
- Every resource is labelled, and `prune_orphans()` cleans up after a process
  that was killed outright and never ran its `finally`.
- `preflight()` checks kernel XFRM before a batch rather than halfway through
  one, with the modprobe incantation in the error text. The failure it catches
  otherwise looks like a configuration bug and costs a day.

**2.4 Bring-up and the assertion** — `testbed/tunnel.py`
- `assert_sa_established()` requires both an ESTABLISHED IKE SA and an INSTALLED
  Child SA. LLD §10.2 calls this guard non-negotiable and it is: without it, a
  failed negotiation produces a capture full of retries carrying a label that
  says it is a working tunnel.
- Errors name the proposals, the mode, and the responder's log, because the
  initiator only ever sees `AUTHENTICATION_FAILED`.
- `bring_up_tunnel(..., responder_cfg=...)` configures the far end differently.
  A normal session never uses it; it is the only way to exercise the guard, and
  step 4.4 will need it to build a peer offering 3DES alongside AES-256.

**2.5 Capture wrapper** — `testbed/capture.py`
- `start_tcpdump()` waits for tcpdump to report *listening* before returning, so
  the IKE exchange initiated moments later is inside the capture.
- `stop()` sends SIGINT rather than SIGKILL, waits for the process to actually
  finish, and **refuses to return an empty capture**. An empty PCAP beside a
  valid `labels.json` is worse than a failed session: the batch reports success
  and the row poisons whatever is trained on it.

**2.6 Traffic generators** — `testbed/traffic/`
- One module per class. Each commits to the distinguishing shape of its class
  rather than approximating all seven with a parameterised stream, because two
  classes that look alike here will look alike to the classifier in step 9.7.
- Measured over 25-second sessions, every class separates on packet rate and on
  at least one of size, directionality or idle structure — the table is in
  MT-13. `voip` and `icmp` deliberately produce very few distinct ESP lengths;
  that is what makes `sufficient_for_lattice` false for them in step 3.6, which
  is the honest-failure case the demo is built around.

**2.7 Ground truth** — `SessionConfig.to_ground_truth()`
- `labels.json` keeps three things apart: `dimensions` (what the matrix chose),
  `expected` (what a correct parser should report, keyed by
  `SecurityAssociation` field), and **`not_observable_from_ike`** (the fields no
  parser can recover from this capture, with the reason).
- That third block is load-bearing. Without it, step 8.2 would flag a parser
  correctly reporting `UNAVAILABLE` for an IKEv2 lifetime as a mismatch, and the
  obvious way to turn the harness green would be to teach the parser to guess.

**2.8 Session runner** — `testbed/orchestrator.py`
- `run_session()` in the LLD §10.2 order, with the teardown inside the capture
  window so the IKE DELETE exchange is recorded, and the result verified rather
  than assumed: IKE packets are counted before and after the teardown.
- Nothing is written to the output directory until the capture is proven
  non-empty, so a failed session leaves no half-written row.

**2.9 Matrix and sampler** — `testbed/matrix.yaml`, `sampler.py`
- The LLD §10.1 matrix, and a deterministic covering-array sampler: **60
  configurations** covering all 257 pairs, from a cross-product of 3360.
- Every value of every dimension appears; re-running with the same seed produces
  an identical list, which the resume manifest depends on.

**2.10 Batch orchestrator** — `testbed/batch.py`
- `run_batch()` with a manifest rewritten after every session, resume, and
  per-session failure isolation. `python -m testbed.batch <dir>` is the entry
  point.
- A session counts as done only when the manifest records it **and** its capture
  and labels are still on disk. A manifest can outlive the files it describes,
  and a resume that trusted it alone would produce a dataset with holes that
  nothing reports.

**Testing**
- 85 automated tests: config and ground truth, rendering, sampling, manifest and
  resume logic (no Docker), plus Docker-backed tests for each **Done when**.
- A new `testbed` CI job builds the peer image, loads the kernel modules and
  runs them with `REQUIRE_TESTBED=1`, so a testbed that silently never ran
  cannot leave a green build. Slow tests stay opt-in behind `TESTBED_SLOW=1`.
- `manualtesting.md` MT-12, MT-13, MT-14.

### Verified

- All 25 Docker-backed testbed tests pass, including the 20-iteration
  container-leak check and all seven traffic generators.
- Both LLD §10.1 reference fixtures negotiate: `weak-reference` establishes
  3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024 over IKEv1 aggressive mode in
  transport mode; `hardened-reference` establishes
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_256 with AES_GCM_16-256
  ESP in tunnel mode.
- A mismatched PSK fails in seconds with a message naming the proposals, and
  leaves no established SA.
- ESP on the wire is raw IP protocol 50, not UDP-encapsulated, and the LLD §7.2
  congruence holds for every captured packet.
- A 10-session batch `SIGKILL`ed after 7 sessions: manifest intact, resume
  cleaned up the 2 orphaned containers and 1 network the kill left behind,
  skipped exactly those 7, ran the remaining 3, finished with zero orphans.
- IPv4 and IPv6 sessions both complete; `docker compose`-free, all through the
  Docker SDK.
- Ruff, ruff-format and mypy strict clean across `analyzer` and `testbed`.

### Not verified

- **The `testbed` CI job has not run on GitHub Actions.** It passes locally via
  `./scripts/ci-local.sh testbed`. Whether an Actions runner permits
  `modprobe esp4` and `NET_ADMIN` containers is untested; if it does not, the
  job needs either a privileged step or removal, and Phase 2 falls back to being
  verified locally only.
- **Step 2.6 at full duration.** The generator profiles were measured over
  25-second sessions, not the 180 seconds the matrix specifies. Rates and shapes
  should hold; absolute packet counts will not.
- **Step 2.9 at scale.** The sampler produces 60 configurations, but no full
  60-session batch has been run end to end — the longest is 10. That is step 8.1.

### Deviations from the specs

- **`guarantee_full_coverage` is read as full-strength coverage across those
  dimensions**, not merely as a promise that each value appears. Plain greedy
  all-pairs covers this matrix in 37 rows, below the 40–60 that step 2.9
  specifies, and covers `mode`, `esp`, `pfs` and `ike` only in pairs — so there
  would be no 3DES-with-PFS-on-IKEv2 row unless the greedy step happened to want
  one. Those four are exactly what Track A parses and the policy scores. Reading
  the key the way covering-array tools read it gives all 60 of their
  combinations, covers all 257 pairs, and lands inside the planned range.
- **The IKE proposal is CBC-plus-HMAC even for the AEAD suites.** IKEv1 cannot
  negotiate an AEAD cipher for Phase 1, so deriving the IKE proposal from the
  ESP suite would make every `ikev1` × `gcm` cell of the matrix fail to
  negotiate. ESP still carries the AEAD. This is also how a great many real
  deployments are configured.
- **Rekey jitter is disabled** (`rand_time = 0`). strongSwan jitters by up to
  10% of `rekey_time` by default — exactly the tolerance step 9.3 measures
  against. Real deployments do jitter; a labelled dataset should not.
- **`testbed/` gained six modules** the LLD §2 tree does not list (`config.py`,
  `peers.py`, `tunnel.py`, `capture.py`, `sampler.py`, `batch.py`). §2 lists
  `orchestrator.py` alone; the lifecycle, capture and sampling concerns are
  genuinely separate and testable apart.
- **Captures are filtered** to `esp or ah or udp port 500 or udp port 4500`.
  The peers also emit ARP, neighbour discovery and multicast chatter that has
  nothing to do with the tunnel, and a model trained on unfiltered captures
  would have that container noise available as signal.

### Open spec questions

6. **The matrix has no NAT dimension.** ESP here is raw protocol 50 because the
   peers share a bridge and no NAT is detected, so nothing in the dataset
   exercises UDP-encapsulated ESP. Step 4.7 must parse NAT-T and step 3.3 must
   disambiguate IKE from ESP on port 4500, and neither will have testbed data to
   work from. Either the matrix needs a `nat` dimension or those steps need
   captures from elsewhere.
7. **`SessionConfig.duration_s` versus PRD §9.3.** The matrix specifies 180
   seconds per session and ≥200 sessions; 60 configurations at 180 seconds is
   about 3 hours of tunnel time before traffic-run multiplicity. Step 8.3
   budgets 8 hours, so this fits — but the number of traffic runs per
   configuration is specified nowhere.

### Added

- `README.md` — what the project is, the two-track thesis, honest current status,
  and where the documentation lives.
- `startup.md` — fresh machine to passing test suite, with the offline and Neon
  paths kept separate and a troubleshooting section of failures people have
  actually hit rather than hypotheticals.
- `manualtesting.md` MT-11, which runs `startup.md` verbatim in a clean clone. A
  setup guide nobody re-runs rots quietly.

### Fixed

- **Alembic could not see `.env`.** `alembic/env.py` read `os.environ` directly,
  so a developer who had configured `.env` exactly as documented still got
  "DATABASE_URL is not set" from `alembic upgrade head`. It now falls back to
  `core.config`, which reads the dotenv file and validates the URL. Explicit
  environment variables still take precedence, so CI and one-off
  `DATABASE_URL_DIRECT=... alembic upgrade head` invocations are unchanged.

  Not caught during Phase 1 because every migration run in that session passed
  the URL on the command line, which is the one path that always worked.

---

## [0.1.0] — 2026-09-04

Gate **G1 — Contract locked**. `core/schema.py` is the single source of truth,
the storage layer runs on both backends, and all four workstreams are unblocked.

Commit `2165a44`. Implementation-plan steps 0.3–0.6 and 1.1–1.8.

### Added — Phase 0, foundations

**0.3 Repository skeleton**
- Tree from [LLD §2](docs/LLD.md): uv-managed Python 3.11 backend under
  `backend/src/analyzer/`, Next.js 16 frontend, `testbed/`, `dataset/`.
- A docstring-only placeholder module for every later phase, so the import graph
  and the plan agree from day one.
- `.gitignore`, `.gitattributes` (LF everywhere, so Windows checkouts do not
  rewrite the tree), `.editorconfig`, MIT `LICENSE`, `CLAUDE.md`.

**0.4 CI pipeline**
- `.github/workflows/ci.yml`: ruff, ruff-format, mypy strict, pytest across both
  database backends, the Alembic upgrade/downgrade round trip on each, plus
  `tsc --noEmit`, ESLint and `next build`.
- `scripts/ci-local.sh` runs the same set locally, so "green here" means "green
  there".
- `REQUIRE_POSTGRES=1` turns a skipped PostgreSQL backend into a CI failure. A
  backend that silently never ran is a green build proving half of what it
  claims.

**0.5 Neon configuration**
- `.env.example` with placeholder pooled and direct connection strings.
- [docs/database-setup.md](docs/database-setup.md): branch-per-developer setup,
  which endpoint each consumer uses, and the three Neon gotchas that each cost a
  day — PgBouncer versus asyncpg's prepared statements, scale-to-zero, and
  `sslmode` being libpq's spelling rather than asyncpg's.
- `scripts/pg-dev.sh` for a throwaway local PostgreSQL on port 55432.

**0.6 tshark version pin**
- `backend/Dockerfile` pinning tshark **4.4.18** (`wireshark-common` pinned
  alongside it, or apt resolves a newer common package and fails the solve).
- The same version recorded in `pyproject.toml` under
  `[tool.ipsec-analyzer.external-tools]` and asserted by
  `tests/test_tshark_version.py`. Wireshark's JSON field names change between
  releases and break the Track A parser silently, so three places must agree and
  the build fails loudly when Debian rotates the package out.

### Added — Phase 1, contract and storage

**1.1 Enums** — `core/enums.py`
- Every enum from [LLD §3](docs/LLD.md), plus `CaptureSource`, `RunStatus` and
  `RunStage` for the storage layer.
- `CATEGORY_CAPS` sits beside `FindingCategory` so a new category cannot be
  added without deciding its cap (PRD §10.1, summing to 100).
- `EncryptionAlg` deliberately carries no AES key length: from ESP alone the
  cipher family is inferable and the key length is not, so folding them together
  would make FR-4.9 unrepresentable.

**1.2 `Evidence` and `Attribute[T]`** — `core/schema.py`
- The provenance invariant, enforced by a model validator: `INFERRED` must carry
  a confidence, `OBSERVED` must not.
- Strengthened beyond LLD §3 so the same dishonesty cannot re-enter by another
  door — `UNAVAILABLE` must explain itself in a note and must hold no value, and
  a null value may not hide behind `OBSERVED` or `INFERRED`.
- `validate_assignment` keeps the invariant true after construction, not only at
  it.
- `Evidence.packet_indices` capped at 20 with `total_matching` alongside
  (LLD §8.4).

**1.3 Full contract** — `core/schema.py`
- `CaptureQuality`, `FeatureAttribution`, `TrafficPrediction`,
  `SecurityAssociation`, `StandardRef`, `Finding`, `ThreatMatrixEntry`,
  `ScoreBreakdown`, `MetadataExposure`, `Assessment`.
- `UtcDatetime` rejects naive datetimes, normalises to UTC, and serialises with
  a trailing `Z` so identical input is byte-identical output (NFR-4).
- `Uuid7`, `HexSpi`, `FindingKey` and `AttackTechniqueId` validate their formats.
- Cross-model validation: no finding may reference an unknown SA, no threat
  matrix entry may cite a finding that is not in the document, a score total must
  equal 100 minus its category penalties, and an informational finding may not
  cost points.
- `core/ids.py` — `new_id()` returning UUIDv7.

**1.4 Fixture assessments** — `backend/tests/fixtures/`
- `assessment_weak.json` and `assessment_strong.json`, the two
  [PRD §16](docs/ipsec-analyzer-prd.md) demo tunnels, written by hand.
- Weak: 15/100 `critical`, 8 findings, ATT&CK T1040/T1110/T1557/T1600.
- Strong: 90/100 `strong`, one surviving finding — `META-HIGH-EXPOSURE`, because
  hardening the cryptography did almost nothing to what the traffic pattern
  reveals. That contrast is PRD §4.1's thesis stated as data.
- Both encode the failure mode guaranteed to appear on stage: a VoIP call
  produces too few distinct ESP lengths for the cipher-family sieve, so
  `sufficient_for_lattice` is false in both.
- `fixtures/README.md` records which properties are deliberate, so nobody
  "fixes" them.

**1.5 SQLAlchemy models** — `db/models.py`, `db/types.py`
- The five tables of LLD §4.3. `sa.JSON` never `JSONB`, `sa.Uuid` keys,
  `ON DELETE CASCADE` throughout, and a metadata naming convention so every
  constraint has a stable name a downgrade can drop.
- Enum columns are portable `VARCHAR` with `values_callable`, so the database
  stores `3des-cbc` rather than `TRIPLE_DES_CBC`.
- `UtcDateTime` column type returns aware UTC values on both backends; SQLite
  otherwise hands back naive datetimes that compare wrong without complaint.

**1.6 Alembic** — `alembic/`
- Initial migration `6173d44f0cce`, with the dialect-guarded `JSON → JSONB`
  promotion for PostgreSQL.
- `env.py` reads `DATABASE_URL_DIRECT` first, because DDL through Neon's pooler
  fails intermittently and looks like network flakiness.
- A `render_item` hook keeps `analyzer.*` out of version files, so a migration
  survives the module it was generated from being renamed.

**1.7 Session factory** — `db/session.py`
- Neon pooled endpoints get `statement_cache_size=0`,
  `prepared_statement_cache_size=0` and a unique statement-name function.
  Disabling one cache and not the other is the usual half-fix, and it fails only
  under concurrency.
- `pool_pre_ping` and `pool_recycle=280` for scale-to-zero.
- `PRAGMA foreign_keys=ON` per SQLite connection, without which every
  `ON DELETE CASCADE` in the schema is decorative on the offline backend.
- `session_scope()` for the single-transaction write path, `check_connection()`
  for the future health endpoint.

**1.8 Settings** — `core/config.py`
- `DATABASE_URL`, `DATABASE_URL_DIRECT`, `STORAGE_PATH`, `POLICY_PATH`,
  `MODEL_DIR`, `MAX_UPLOAD_BYTES`, `MAX_CONCURRENT_ANALYSES`.
- Refuses to start, with instructions, on a missing `DATABASE_URL`, a
  synchronous driver URL, or libpq's `sslmode` spelling.

### Verified

- 219 tests pass across SQLite and PostgreSQL 16; 2 skipped (live Neon, and the
  host-tshark check that runs inside the image).
- `alembic upgrade head` then `downgrade base`, twice, on both backends. All six
  JSON columns read `jsonb` on PostgreSQL and `JSON` on SQLite.
- `docker run ipsec-analyzer-backend:0.1.0 tshark --version` → `4.4.18`.
- Ruff, ruff-format, mypy strict, `tsc --noEmit`, ESLint and `next build` clean.

### Not verified

- **Step 0.5** — no team member has `psql`'d into their own Neon branch. Needs
  the Neon account.
- **Step 1.7** — the live smoke test against Neon's *pooled* endpoint is skipped
  until `NEON_POOLED_URL` is set. The settings it depends on are verified
  against a real PostgreSQL, but PgBouncer itself has not been in the path.
- **Step 0.4** — the "a PR with a lint error is blocked" condition was shown
  locally via `scripts/ci-local.sh`; no PR has run through GitHub Actions yet.

### Deviations from the specs

Recorded so the specs can be corrected rather than quietly diverged from.

- **Next.js 16.3.4**, where LLD §11.1 says 15. Agreed deliberately; §11.1 needs
  amending and Next 16's breaking changes are a live risk for Phase 7.
- **Enum values are lowercase throughout.** LLD §8.1's policy example writes
  `"3DES-CBC"` while `Provenance`, `Severity` and `FindingCategory` in the same
  document are lowercase. Policy files must use the enum values.
- **`Evidence.measured` accepts `int`**, not only `float | str`. Otherwise a
  technical report reads "exchange type 4.0" and NFR-4's byte-identical round
  trip breaks on integers.
- **`Evidence.total_matching` added.** Required by LLD §8.4, absent from §3's
  listing.
- **`ThreatMatrixEntry` and `FeatureAttribution` designed here.** Both are
  referenced by the LLD and defined nowhere in it.
- **`captures.sha256` is `String(64)`, not `CHAR(64)`.** PostgreSQL `CHAR`
  blank-pads and compares padded, which would let an identical hash miss the
  unique index.
- **`TrafficClass.FILE_TRANSFER = "file_transfer"`**, where the LLD §10.1 matrix
  spells it `filexfer`. The matrix loader owns the mapping.
- **`docker-compose.yml` not created.** It belongs to step 11.4 and would
  reference a frontend Dockerfile that does not exist.

### Open spec questions

Raised during this work, still unanswered. See the summary in
[manualtesting.md](manualtesting.md) for how each is currently worked around.

1. **T1600 cannot reach the weak fixture as specified.** Step 5.7 requires it;
   PRD §10.3 maps T1600 only to downgrade-permitting proposals, and the weak
   demo tunnel selects the weakest algorithm it offers, so
   `CRYPTO-DOWNGRADE-OFFER` cannot fire. Currently mapped from `CRYPTO-3DES` and
   `KEX-WEAK-DH` on a reduced-key-space reading.
2. **`ScoreBreakdown.rating` thresholds are defined nowhere.** LLD §8.3 calls an
   unspecified `_rating(total)`. No validator ties rating to total; step 5.5
   owns the decision.
3. **IKEv1 Quick Mode is encrypted too.** LLD §6.4 carves out only IKEv2's
   `IKE_AUTH`, but IKEv1 Phase 2 is protected by the Phase 1 SA, so the ESP
   transform set is not directly observable there either — while PRD §7 says
   "Certain with IKE captured". Phase 4 needs one consistent rule.
4. **`SecurityAssociation` conflates the IKE SA and the Child SA.** It carries
   ESP SPIs and `protocol: esp|ah` alongside `ike_version`, `prf_alg` and
   `dh_group`. Which SA does `encryption_alg` describe? Drives question 3.
5. **Step 7.8 wants an ESP-only fixture** that step 1.4 does not create.

---

[Unreleased]: https://github.com/Piyush800x/ipsec-analyzer/compare/2165a44...HEAD
[0.1.0]: https://github.com/Piyush800x/ipsec-analyzer/commit/2165a44
