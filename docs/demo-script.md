# Demo script — PRD §16

The shot list and narration for the live demo and for step 11.8's recording.
Two prepared tunnels, run through the tool, no slides. **Target: under three
minutes.**

The captures are `dataset/demo/demo-tunnel-a/capture.pcap` and
`demo-tunnel-b/capture.pcap` (step 11.5). They are held outside
`dataset/sessions/`, so no fold of the training split contains them.

---

## Before you start

```bash
docker compose -f docker-compose.offline.yml up -d --build
python scripts/demo_rehearsal.py --runs 1     # sanity: should print "1/1 clean"
```

Then open <http://localhost:3000> and hard-refresh.

**Rehearse on the offline stack, not on Neon.** Neon scales to zero and a cold
start mid-demo is an avoidable risk — step 11.6 says so explicitly. The offline
stack also has no route off the box at all (`internal: true`), so nothing can
stall on a network call.

Two things to have ready and *not* on screen: a terminal in the repo root, and
both capture files somewhere you can drag from in one motion.

Measured timings from the rehearsal, for pacing — analysis is about 8 seconds
per capture, the comparison 2, the report 2.

---

## 1 — Tunnel A, the weak one · ~45 s

**Do:** upload `demo-tunnel-a/capture.pcap`. Let the progress bar run. Land on
the assessment overview.

**Say:**

> This is a real IPsec tunnel, captured off the wire. No keys, no agent on
> either endpoint — just the packets a passive observer sees.
>
> It scores **25 out of 100**. Seven findings, one critical: IKEv1 in
> aggressive mode, which puts the identity and a hash of the pre-shared key on
> the wire in cleartext. Triple-DES, which has about 112 bits of effective
> strength. Diffie-Hellman group 2 — 1024-bit. Perfect forward secrecy off, so
> one compromised key opens every session ever recorded. And a 24-hour SA
> lifetime.

**Point at the provenance column.** This is the part that distinguishes the
tool:

> Every one of these says where it came from. `OBSERVED` means it was read
> directly out of the IKE exchange. `INFERRED` carries a confidence. And where
> we could not tell, it says **why** — not a dash, not a blank, a sentence.

**Do:** open the threat matrix. Let it be seen lighting up.

---

## 2 — What the tunnel leaks anyway · ~40 s

This is the point PRD §4.1 exists for, and **step 11.8's Done-when requires it
be stated explicitly.** Do not rush it.

**Do:** open the metadata exposure panel.

**Say:**

> Now the part that is not about the cryptography.
>
> The tool ran its own traffic classifier over the *encrypted* payload. It
> never decrypted anything — it only measured packet sizes and timing. It says
> the traffic inside is **VoIP**, at **confidence 1.0**.
>
> That confidence is not a diagnostic about our model. **It is the
> measurement.** It is exactly what a passive adversary learns by watching this
> tunnel: not what was said, but that someone is on a call, when it started,
> how long it ran, and who with. For a lot of threat models that is most of
> what they wanted.
>
> So the metadata exposure score is **100**, and it costs this deployment
> points — separately from the cipher. That is deliberate. A tunnel can be
> cryptographically perfect and still leak this, because padding and cover
> traffic are a different problem from key exchange.

---

## 3 — Tunnel B, the hardened one · ~45 s

**Do:** upload `demo-tunnel-b/capture.pcap`. Land on its overview beside A.

**Say:**

> Same VoIP call, same testbed, same capture length. IKEv2, AES-256-GCM,
> Diffie-Hellman group 19, PFS on, one-hour lifetime.
>
> **80 out of 100.** Two findings instead of seven, and nothing critical.

**Do:** open the comparison view.

**Say:**

> Fifty-five points, and five findings that exist in A and not in B — each one
> traceable to a specific parameter and the packet it was read from.
>
> But look at the metadata exposure. It has not moved **at all** — still 100,
> still VoIP, still confidence 1.0. Same call, same shape, same timing, so the
> classifier reads it exactly as well through AES-256-GCM as through
> triple-DES. Hardening the cryptography did not touch the leak, because the
> leak was never about the cryptography.

Optional, if you have the technical report open and the time:

> One more thing worth pointing at. The tool also worked out that A is
> **transport** mode and B is **tunnel** mode — which is not carried in any
> cleartext field of either capture. It inferred it from the encapsulation
> overhead, and it says so: `INFERRED`, with a confidence, not `OBSERVED`.

---

## 4 — The report · ~25 s

**Do:** download tunnel A's executive report. Open the PDF.

**Say:**

> Two pages. No hex, no packet indices, no jargon — every finding leads with
> what it costs you, not with what it is. This goes to whoever signs off the
> remediation.
>
> There is a technical report as well, with the full parameter table and the
> evidence for every value.
>
> And one line matters more than the rest: it states what could **not** be
> determined from this capture, and why. Nothing here is guessed to fill a gap.
> An honest "unavailable, and here is the reason" is the correct answer — a
> plausible-looking fabricated value in a security report is a defect.

---

## Closing · ~15 s

> Deterministic — same capture, same assessment, every time. Runs air-gapped:
> that stack has no route off the machine. And it tells you what it does not
> know.

---

## For the recording (step 11.8)

- **Under three minutes.** The timings above total roughly 2:50 with the
  narration read at pace.
- **The §4.1 point must be spoken, not just shown.** Section 2 is the one
  section that cannot be cut for time.
- Record at 1920×1080, browser zoom at 100%, and hide bookmarks and any
  extension icons.
- Do the uploads by drag-and-drop; a file picker dialog reads as dead air.
- Do not record the terminal. If the stack needs a restart mid-take, cut.

## If something goes wrong

| symptom | cause |
|---|---|
| Traffic class shows as unavailable | The image is not carrying the models, or `MODEL_DIR` is not reaching the runner. See **MT-26**. |
| Progress bar jumps 0 → 100 | A proxy is buffering the SSE stream. `X-Accel-Buffering: no` and `Cache-Control: no-cache` must survive to the browser. |
| Backend will not start on the offline stack | Almost certainly a network call at startup. Nothing in that container can reach anything. See **MT-18**. |
| Scores differ from those above | Check you are on the demo captures and not the matrix's `weak-reference` / `hardened-reference`, which are different captures of the same parameters. |
