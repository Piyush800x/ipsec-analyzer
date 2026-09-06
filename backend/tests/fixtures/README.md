# Assessment fixtures

Two hand-written `Assessment` documents, one per demo tunnel in
[PRD §16](../../../docs/ipsec-analyzer-prd.md). Produced by step 1.4.

These are **not** throwaway test data. Three things now depend on them: the
frontend renders them directly under `USE_FIXTURES=1`, both report templates
render from them, and step 5.4 asserts that the engine reproduces the weak
fixture's finding set exactly. Changing one of these files changes a contract
three workstreams depend on — run `uv run pytest tests/test_fixtures.py
tests/test_report.py` after any edit, and re-check the frontend fixture pages.

| File | Tunnel | Score | Findings |
|---|---|---|---|
| `assessment_weak.json` | IKEv1 aggressive, 3DES-CBC, HMAC-SHA1-96, DH 2, no PFS, 24 h lifetime, transport mode, VoIP | 15/100 `critical` | 8 |
| `assessment_strong.json` | IKEv2, AES-256-GCM, DH 19, tunnel mode, VoIP | 90/100 `strong` | 1 |

## What each fixture is there to exercise

**`assessment_weak.json`** is the demo's opening move: a deep red score, a full
findings table across three severities, and a threat matrix that lights up four
ATT&CK techniques. Provenance is mostly `observed`, because IKEv1 Phase 1 puts
its whole proposal on the wire in the clear.

**`assessment_strong.json`** is the more interesting file to build UI against.
Its provenance mix is 4 observed / 5 inferred / 6 unavailable, so a single
configuration table renders all three `AttributeCell` states (step 7.4) with
real data rather than contrived rows.

## Deliberate properties, so nobody "fixes" them

- **Neither capture supports the length lattice.** Both carry a VoIP call, and
  constant-bitrate traffic produces two or three distinct ESP payload lengths
  where the sieve needs eight (LLD §7.2). `sufficient_for_lattice` is `false` in
  both. This is the failure mode guaranteed to appear on stage, and the fixtures
  encode it on purpose.
- **The hardened tunnel's IKEv2 Child SA crypto is `inferred`, not `observed`.**
  Only `IKE_SA_INIT` is cleartext; the Child SA proposal travels inside the
  encrypted `IKE_AUTH` exchange (LLD §6.4). The values are inferred from the IKE
  SA proposal, with the reasoning in each `note`.
- **The hardened tunnel reports no SA lifetime at all.** IKEv2 does not negotiate
  one (RFC 7296), and no `CREATE_CHILD_SA` occurred in the 176-second window, so
  the observed rekey interval is unavailable too. Both are `unavailable` with a
  note. Emitting a fabricated IKEv2 lifetime is the single correctness bug the
  LLD calls out by name.
- **PFS is `unavailable` on the hardened tunnel**, for the same reason — it is
  read from a `CREATE_CHILD_SA` KE payload, and there wasn't one.
- **Both tunnels leak the same amount of metadata** (exposure 95 vs 92). Fixing
  the cryptography did essentially nothing to the traffic classifier's
  confidence, which is PRD §4.1's thesis stated as data. The hardened tunnel's
  one surviving finding is `META-HIGH-EXPOSURE`.
- **`operating_mode` is `inferred` in both.** Tunnel versus transport is not
  carried in any cleartext field, so it is never `observed` — not even with a
  complete IKE capture.

## Arithmetic the engine must reproduce

- `metadata_exposure.score` follows LLD §8.4: `round(100 × (mean − 1/7) / (1 − 1/7))`.
- `metadata_exposure.mean_classifier_confidence` is the plain mean of every
  `inner_traffic[].probability` in the document.
- `score.category_penalties` is the per-category sum of finding penalties,
  capped by `CATEGORY_CAPS` (PRD §10.1). The weak fixture's cryptographic
  strength sums to 38 and caps at 30; key exchange sums to 27 and caps at 20.
- `score.total` is `100 −` the sum of the capped penalties.

`tests/test_fixtures.py` checks every one of these, so the fixtures cannot drift
away from the formulas the engine will implement.

## Changes since step 1.4

- **`downgrade_available` was added to `SecurityAssociation`** in Phase 5, so
  both fixtures carry it. It is what the `IKE-DOWNGRADE` rule reads, and it is
  `unavailable` in both — detecting a downgrade needs the initiator's full
  proposal list, and the fixtures record only the selected proposal.
- **`model_versions` names two models that do not exist.** These fixtures
  describe the finished system, so they cite `traffic-cnn1d` and `mode-lgbm`
  version strings; no such artefact has been trained (see
  [../../models/README.md](../../models/README.md)). That is deliberate — they
  are what a real assessment will look like, and the report templates need a
  populated capability matrix to render against. Do not read them as evidence
  that a model exists.

## Known gaps

- Neither fixture is **ESP-only**, which step 7.8 wants in order to render AES
  key length as unavailable. Step 1.4 asks for two fixtures and these are those
  two. `tests/test_degradation.py` covers the case instead, building ESP-only
  captures on the fly.
- No `low` or `informational` severity appears in either fixture, because the
  step 5.3 rule set has no rule that produces one. The findings table should
  still be built to render all five.
