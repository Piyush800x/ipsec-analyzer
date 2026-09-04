# Product Requirements Document

## AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

| Field | Value |
|---|---|
| Version | 1.0 (draft) |
| Status | For team review |
| Context | Smart India Hackathon 2026 |
| Working title | *(TBD — see §14)* |
| Owner | Project lead |
| Last updated | 3 September 2026 |

---

## 1. Background and problem

IPsec underpins secure communication across enterprise, government, military, and cloud infrastructure. Its security, however, is entirely dependent on how it is configured. A tunnel using 3DES with DH Group 2 and no Perfect Forward Secrecy is functionally "encrypted" and will pass a naive audit, yet offers materially weaker protection than one using AES-256-GCM with DH Group 19.

Today, verifying which of those two a deployment actually runs requires an expert with Wireshark, manual filter expressions, and knowledge of how IKE payloads are laid out. That expertise is scarce, the process does not scale across hundreds of tunnels, and it produces no standardised output that a CISO or auditor can act on.

There is a second, harder gap. Even a correctly configured tunnel leaks information through traffic metadata — packet sizes, timing, and burst patterns reveal what kind of application is running inside the encrypted channel. No mainstream tool quantifies that leakage as part of a VPN's security posture.

### 1.1 Problem statement

Security analysts cannot rapidly and consistently determine the security posture of an IPsec deployment from network traffic alone, because doing so requires deep protocol expertise, manual packet inspection, and there is no standard framework for scoring what they find.

---

## 2. Goals and non-goals

### 2.1 Goals

- **G1** — Determine an IPsec deployment's cryptographic configuration from captured or live traffic, without access to the endpoint devices or their config files.
- **G2** — Infer characteristics that are not directly observable (operating mode, traffic type inside ESP, PFS status) using machine learning, with calibrated confidence values.
- **G3** — Score the deployment against published standards and produce a defensible, reproducible security assessment.
- **G4** — Quantify metadata leakage as a first-class security metric rather than a footnote.
- **G5** — Present all of the above through a dashboard and two report formats aimed at different audiences.
- **G6** — Ship a labelled IPsec dataset that others can reuse, since none of adequate breadth exists publicly.

### 2.2 Non-goals

- **NG1** — Breaking IPsec encryption or recovering plaintext. The tool operates purely on observable metadata and cleartext negotiation.
- **NG2** — Active exploitation, fuzzing, or attacking live VPN gateways. This is a passive analysis tool.
- **NG3** — Supporting non-IPsec VPN technologies (WireGuard, OpenVPN, SSL VPN) in v1.
- **NG4** — Real-time inline blocking or enforcement. The tool observes and reports; it does not intervene.
- **NG5** — Endpoint agent deployment. Analysis is network-side only.

---

## 3. Target users

| Persona | Context | Primary need |
|---|---|---|
| **SOC analyst** | Monitors network traffic, mid-level protocol knowledge | Fast triage: is this tunnel weak? Give me a verdict and evidence. |
| **Security auditor / compliance officer** | Needs to attest to standards, limited packet-level skill | A report mapping observed configuration to a named standard. |
| **Network engineer** | Owns the VPN gateways | Specific, actionable remediation: which parameter, what to change it to. |
| **CISO / management** | Non-technical, decision-making | A single score, a trend, and a risk summary. |

The SOC analyst is the primary persona. The executive report exists for the CISO; everything else serves the first three.

---

## 4. Product thesis

The system is built on one architectural decision that governs everything else:

> **IPsec leaks in two distinct ways, and each requires a different technique. Conflating them produces a weak product.**

**Track A — deterministic parsing.** IKE negotiation is partially cleartext. The IKEv2 `IKE_SA_INIT` exchange and IKEv1 Phase 1 SA payloads carry the proposed transforms in the open: encryption algorithm, integrity algorithm, PRF, DH group, and SPIs. These are extracted by a parser with certainty. No model is involved and none should be.

**Track B — statistical inference.** Once the SA is established, all application traffic is inside ESP. Only the outer IP header, SPI, sequence number, and an opaque ciphertext blob are visible. Everything derived from this stage — inner traffic type, operating mode, cipher family when IKE was not captured — is inferred from flow statistics and packet geometry, and must carry a confidence value.

Every field in every output is tagged as **observed** (Track A) or **inferred** (Track B, with probability). An analyst acting on the report needs to know which claims are facts and which are estimates.

### 4.1 The metadata thesis

The system's own traffic classifier doubles as the metadata exposure metric. If the classifier identifies inner traffic as VoIP with 94% confidence, that confidence *is* the measurement of how much the deployment leaks to a passive observer. A well-configured, well-padded tunnel should make the classifier uncertain, and that uncertainty is a good security outcome. This inverts the usual ML objective in one specific place and gives the security score a component no comparable tool reports.

---

## 5. System architecture

Six modules, in pipeline order.

| ID | Module | Responsibility |
|---|---|---|
| **M1** | Testbed orchestrator | Bring up IPsec tunnels across a configuration matrix, generate application traffic, capture with ground-truth labels |
| **M2** | Capture and ingest | Accept PCAP upload or live interface capture; normalise into internal flow records |
| **M3** | IKE parser (Track A) | Deterministic extraction of negotiated parameters from IKE exchanges |
| **M4** | ESP inference engine (Track B) | Feature extraction and ML classification over encrypted flows |
| **M5** | Assessment engine | Rule-based evaluation, compliance mapping, risk scoring, threat matrix |
| **M6** | Presentation layer | Interactive dashboard, executive report, technical report |

M1 exists to produce training data and is also a required project deliverable. M3 and M4 run in parallel over the same capture and their outputs are merged by M5.

---

## 6. Functional requirements

Priority uses MoSCoW: **M** must have, **S** should have, **C** could have, **W** won't have in v1.

### 6.1 M1 — Testbed orchestrator

| ID | Requirement | Priority |
|---|---|---|
| FR-1.1 | Provision IPsec tunnels using strongSwan (primary) and Libreswan (secondary) inside containers | M |
| FR-1.2 | Drive tunnel configuration from a declarative YAML matrix (see §9.1) | M |
| FR-1.3 | Support Tunnel and Transport mode | M |
| FR-1.4 | Support AES-128-CBC, AES-256-CBC, AES-128-GCM, AES-256-GCM cipher configurations | M |
| FR-1.5 | Support HMAC-SHA1-96 and HMAC-SHA256-128 integrity algorithms for CBC modes | M |
| FR-1.6 | Support DH Groups 2, 14, 19, 20 spanning weak-to-strong | M |
| FR-1.7 | Support PFS enabled and disabled | M |
| FR-1.8 | Support IKEv1 (main and aggressive mode) and IKEv2 | M |
| FR-1.9 | Support IPv4 and IPv6 transport | S |
| FR-1.10 | Generate labelled traffic for: ICMP, web browsing, VoIP, video streaming, email, bulk file transfer, messaging | M |
| FR-1.11 | Emit a JSON ground-truth sidecar per capture recording every configured parameter and the traffic label | M |
| FR-1.12 | Support configurable SA lifetimes to allow rekeying observation within a capture window | S |
| FR-1.13 | Include deliberately weak reference configurations (3DES, DH Group 2, IKEv1 aggressive, no PFS) for demo and negative testing | M |

### 6.2 M2 — Capture and ingest

| ID | Requirement | Priority |
|---|---|---|
| FR-2.1 | Accept PCAP and PCAPNG file upload through the dashboard | M |
| FR-2.2 | Capture live from a named network interface | S |
| FR-2.3 | Group packets into flows keyed by (outer src, outer dst, SPI, direction) | M |
| FR-2.4 | Handle captures containing no IKE exchange (ESP-only, analyst joined mid-session) and degrade gracefully to Track B only | M |
| FR-2.5 | Report capture quality metrics: packet count, duration, truncation, whether IKE was present | M |
| FR-2.6 | High-throughput capture path for line-rate live analysis | C |

### 6.3 M3 — IKE parser (Track A)

| ID | Requirement | Priority |
|---|---|---|
| FR-3.1 | Identify IKE version (v1 or v2) and, for v1, the exchange mode (main or aggressive) | M |
| FR-3.2 | Extract all proposed and selected transforms: encryption algorithm and key length, integrity algorithm, PRF, DH group | M |
| FR-3.3 | Extract negotiated SA lifetime values where present | M |
| FR-3.4 | Extract SPIs and correlate IKE SAs to their Child SAs | M |
| FR-3.5 | Identify the authentication method (pre-shared key, RSA signature, EAP) where visible | S |
| FR-3.6 | Detect NAT-Traversal (UDP 4500 encapsulation) | S |
| FR-3.7 | Parse Vendor ID payloads to fingerprint the implementation | C |
| FR-3.8 | Detect AH usage alongside or instead of ESP | C |

### 6.4 M4 — ESP inference engine (Track B)

| ID | Requirement | Priority |
|---|---|---|
| FR-4.1 | Classify inner traffic type across the seven categories in FR-1.10 | M |
| FR-4.2 | Classify operating mode (tunnel vs transport) from encapsulation overhead | M |
| FR-4.3 | Classify cipher family (block/CBC vs stream/GCM) from payload length modularity | M |
| FR-4.4 | Infer ICV length, and therefore the integrity algorithm class, from fixed per-packet overhead | S |
| FR-4.5 | Infer PFS status from `CREATE_CHILD_SA` message size | S |
| FR-4.6 | Measure observed rekeying interval from SPI rotation, and compare against the negotiated lifetime | S |
| FR-4.7 | Verify replay protection from sequence number monotonicity and detect Extended Sequence Numbers | M |
| FR-4.8 | Output a calibrated confidence value for every inferred field | M |
| FR-4.9 | Explicitly report AES key length as *undeterminable* when IKE is absent (see §12, R-4) | M |
| FR-4.10 | Provide per-prediction feature attribution so an analyst can see why a classification was made | S |

### 6.5 M5 — Assessment engine

| ID | Requirement | Priority |
|---|---|---|
| FR-5.1 | Evaluate cryptographic strength of each observed algorithm against a maintained rule set | M |
| FR-5.2 | Map findings to RFC 8221 (ESP/AH algorithm requirements) and RFC 8247 (IKEv2 algorithm requirements) | M |
| FR-5.3 | Map findings to NIST SP 800-77 Rev. 1 guidance | M |
| FR-5.4 | Produce a 0–100 risk score using the published rubric in §10 | M |
| FR-5.5 | Produce a threat matrix mapping each finding to MITRE ATT&CK techniques | M |
| FR-5.6 | Produce a metadata exposure score derived from classifier confidence (§4.1) | M |
| FR-5.7 | Emit specific remediation text per finding, naming the parameter and the recommended value | M |
| FR-5.8 | Every finding must carry the evidence that produced it (packet indices, measured values) | M |
| FR-5.9 | Allow the rule set to be edited without code changes (YAML or JSON policy file) | S |
| FR-5.10 | Support a user-selectable compliance profile (e.g. baseline vs high-assurance) | C |

### 6.6 M6 — Presentation layer

| ID | Requirement | Priority |
|---|---|---|
| FR-6.1 | Dashboard landing view: overall score, severity breakdown, capture summary | M |
| FR-6.2 | Configuration view: every parameter, tagged observed or inferred, with confidence | M |
| FR-6.3 | Findings view: sortable by severity, expandable to evidence and remediation | M |
| FR-6.4 | Traffic analysis view: inferred traffic composition over time | M |
| FR-6.5 | Threat matrix view | M |
| FR-6.6 | Export executive report as PDF (1–2 pages, non-technical) | M |
| FR-6.7 | Export technical report as PDF (full findings, evidence, methodology) | M |
| FR-6.8 | Comparison view for two captures side by side | S |
| FR-6.9 | Machine-readable JSON export of the full assessment | S |
| FR-6.10 | Historical trend view across repeated captures of the same deployment | C |
| FR-6.11 | Multi-tenant user accounts and RBAC | W |

---

## 7. Analysis capability matrix

The single most important table for reviewers. It states plainly what the system can determine and how.

| Attribute | With IKE captured | ESP only | Method |
|---|---|---|---|
| IPsec present | Certain | Certain | Protocol/port identification |
| IKE version | Certain | Not available | Parse |
| IKEv1 exchange mode | Certain | Not available | Parse |
| Encryption algorithm | Certain | Family only (CBC vs GCM) | Parse / length modularity |
| **AES key length (128 vs 256)** | Certain | **Not determinable** | Parse only — see §12 R-4 |
| Integrity algorithm | Certain | Class inferred from ICV length | Parse / fixed overhead |
| DH group | Certain | Not available | Parse |
| PFS enabled | Certain | Inferred | Parse / `CREATE_CHILD_SA` size |
| Negotiated SA lifetime | Certain | Observed lifetime only | Parse / SPI rotation timing |
| Tunnel vs transport mode | Inferred | Inferred | Encapsulation overhead |
| Replay protection | Inferred | Inferred | Sequence number analysis |
| Inner traffic type | Inferred | Inferred | Flow-statistics ML |
| SA characteristics | Certain | Partial | Parse / SPI observation |

---

## 8. Machine learning requirements

### 8.1 Models

| Model | Task | Input | Baseline approach |
|---|---|---|---|
| **ML-1** | Inner traffic classification (7 classes) | Flow statistics + packet size/direction sequence | Gradient boosting baseline; 1D-CNN over the size/direction sequence as the target model |
| **ML-2** | Operating mode classification (2 classes) | Overhead distribution features | Gradient boosting |
| **ML-3** | Cipher family classification (2 classes) | Length modularity features | Decision tree or rule-derived classifier |

ML-3 may reduce to a deterministic rule once the length lattice is characterised. If so, that is a correct outcome and should be reported as such rather than dressed up as a model.

### 8.2 Feature set

**Packet geometry.** ESP payload length distribution; length modulo 16 histogram; fixed per-packet overhead estimate; inferred ICV length; padding-length distribution.

**Flow statistics.** Packet count; byte count; flow duration; packets per second; mean, variance, and percentiles of packet size; mean, variance, and percentiles of inter-arrival time; upstream/downstream byte ratio; upstream/downstream packet ratio; burst count and burst duration; idle-period distribution.

**Sequence.** First N packet sizes with direction sign, as an ordered vector for the CNN.

**SA behaviour.** SPI count per endpoint pair; SPI rotation interval; sequence number gaps and monotonicity; ESN presence.

### 8.3 Confidence calibration

Raw softmax outputs are not probabilities. Apply temperature scaling (or Platt scaling for binary heads) fitted on a held-out calibration split. Report Expected Calibration Error alongside accuracy. A confidence value that is not calibrated is worse than no confidence value, because it invites misplaced trust in a security report.

### 8.4 Performance targets

| Metric | Target | Stretch |
|---|---|---|
| ML-1 traffic classification, macro-F1 | ≥ 0.85 | ≥ 0.92 |
| ML-2 mode classification, accuracy | ≥ 0.90 | ≥ 0.96 |
| ML-3 cipher family, accuracy | ≥ 0.95 | ≥ 0.99 |
| Expected Calibration Error (all models) | ≤ 0.10 | ≤ 0.05 |
| Track A parse correctness on testbed captures | 100% | — |

Evaluation must include a held-out split by *configuration*, not just by flow, to prove the models generalise to configurations they have not seen.

---

## 9. Data requirements

### 9.1 Configuration matrix

The testbed enumerates combinations of:

| Dimension | Values |
|---|---|
| Mode | tunnel, transport |
| IKE version | IKEv1-main, IKEv1-aggressive, IKEv2 |
| Encryption | AES-128-CBC, AES-256-CBC, AES-128-GCM, AES-256-GCM, 3DES-CBC *(weak reference)* |
| Integrity | HMAC-SHA1-96, HMAC-SHA256-128, *(none for GCM)* |
| DH group | 2, 14, 19, 20 |
| PFS | on, off |
| IP version | IPv4, IPv6 |
| Traffic | ICMP, web, VoIP, video, email, file transfer, messaging |

The full cross-product is impractical. Use a stratified sample that guarantees coverage of every value of every dimension and every pairwise combination of the security-relevant dimensions (mode × encryption × PFS × IKE version).

### 9.2 Traffic generation

| Traffic class | Generator |
|---|---|
| ICMP | `ping` at varied intervals and payload sizes |
| Web browsing | Selenium or `curl` against a local web server with realistic asset mixes |
| VoIP | `sipp` or a SIP softphone with RTP media |
| Video streaming | `ffmpeg` RTP/HLS from a local media server |
| Email | `swaks` over SMTP, plus IMAP fetch |
| File transfer | `scp` / `iperf3` bulk |
| Messaging | Scripted short bursty exchanges over a local XMPP or WebSocket service |

### 9.3 Dataset deliverable

- Target: at least 200 capture sessions covering the stratified matrix.
- Each session ships as `capture.pcap` plus `labels.json` containing the full ground-truth configuration and traffic label.
- A `dataset.md` documents the schema, generation method, and licence.
- External validation set: ISCXVPN2016 for the traffic classification task, to demonstrate the model is not overfitted to the team's own testbed.

---

## 10. Scoring rubric

The risk score must be reproducible and explainable. Two identical captures must produce identical scores, and every point deducted must be traceable to a named finding.

### 10.1 Score composition

Start at 100. Subtract weighted penalties. Floor at 0.

| Category | Max penalty | Example findings |
|---|---|---|
| Cryptographic strength | 30 | Broken or deprecated cipher; short key; weak integrity algorithm |
| Key exchange | 20 | DH group below 2048-bit equivalent; PFS disabled |
| Protocol version and mode | 15 | IKEv1 in use; aggressive mode (PSK hash exposure) |
| Key management | 15 | Excessive SA lifetime; no observed rekeying |
| Replay and integrity | 10 | Replay protection absent; no ESN on high-volume SA |
| Metadata exposure | 10 | Inner traffic classified with high confidence |

### 10.2 Severity levels

| Severity | Meaning | Example |
|---|---|---|
| Critical | Practically exploitable today | 3DES; DH Group 1; IKEv1 aggressive mode with PSK |
| High | Significantly below current standards | DH Group 2; PFS disabled; 24-hour SA lifetime |
| Medium | Below best practice, not immediately exploitable | SHA-1 integrity; AES-128 where 256 is warranted |
| Low | Hygiene | Verbose Vendor ID exposure; suboptimal lifetime |
| Informational | Observation, not a defect | NAT-T in use; IPv6 transport |

### 10.3 Threat matrix

Each finding maps to one or more MITRE ATT&CK techniques. Working mapping:

| Finding class | ATT&CK technique |
|---|---|
| Weak cipher, metadata exposure | T1040 Network Sniffing |
| Weak authentication, aggressive mode | T1557 Adversary-in-the-Middle |
| Downgrade-permitting proposals | T1600 Weaken Encryption |
| Credential-exposing negotiation | T1110 Brute Force *(offline PSK cracking)* |

---

## 11. Non-functional requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-1 | Analysis latency for a 10-minute, 100 MB capture | < 60 seconds end to end |
| NFR-2 | Dashboard interaction responsiveness | < 200 ms for view changes on loaded results |
| NFR-3 | Deployment | Single `docker compose up` brings up the full stack |
| NFR-4 | Reproducibility | Same input produces byte-identical assessment JSON |
| NFR-5 | Passive safety | The tool must never transmit packets onto the analysed network |
| NFR-6 | Data handling | Uploaded captures are processed locally; no external service calls |
| NFR-7 | Auditability | Every finding traceable to specific packets and measured values |
| NFR-8 | Extensibility | Adding a new compliance rule requires only a policy-file edit |

---

## 12. Risks and mitigations

| ID | Risk | Impact | Mitigation |
|---|---|---|---|
| R-1 | Testbed automation consumes most of the build time and starves the ML work | High | Timebox M1 to weeks 1–3; freeze the config matrix early; parallelise M1 and M4 across the team |
| R-2 | Models overfit to a single-vendor testbed (strongSwan-only artefacts) | High | Add Libreswan as a second implementation; hold out entire configurations in evaluation; validate against ISCXVPN2016 |
| R-3 | Traffic classification accuracy under-delivers on real-world traffic | Medium | Ship the deterministic Track A regardless; Track A alone is a working product |
| R-4 | Reviewers expect AES-128/256 discrimination from ESP alone | Medium | State the limitation openly in the capability matrix and the reports. Credibility from a stated limit exceeds the credit from an unsupportable claim |
| R-5 | Report generation left to the final days and ships as a placeholder | Medium | Build the report templates against mock assessment JSON in week 4, before the engine is finished |
| R-6 | Live capture path proves unstable during demo | Low | Demo from pre-recorded PCAPs by default; live capture is a bonus, not the critical path |
| R-7 | Scope creep into WireGuard or OpenVPN | Medium | Explicitly out of scope (NG3); revisit only after all must-have requirements pass |

---

## 13. Milestones

Twelve-week plan. Weeks are relative to project start.

| Phase | Weeks | Exit criteria |
|---|---|---|
| **P0 — Foundations** | 1–2 | Containerised strongSwan tunnel established; single PCAP captured with a label sidecar; repository, CI, and module skeletons in place |
| **P1 — Testbed** | 2–4 | Config matrix driven end to end; at least 100 labelled sessions generated; dataset schema frozen |
| **P2 — Track A** | 3–5 | IKE parser extracts all FR-3 must-have fields with 100% accuracy on testbed captures |
| **P3 — Track B** | 5–8 | Feature pipeline complete; ML-1/2/3 trained; calibration applied; §8.4 targets met on held-out configurations |
| **P4 — Assessment** | 7–9 | Rule set encoded; scoring rubric implemented and reproducible; threat matrix mapped |
| **P5 — Presentation** | 8–11 | Dashboard views complete; both report formats generating from real assessment output |
| **P6 — Hardening and demo** | 11–12 | End-to-end run on unseen capture; demo script rehearsed; documentation and video complete |

Track A and Track B overlap deliberately. Report templates (P5) begin against mock data during P3.

---

## 14. Open questions

| ID | Question | Owner | Needed by |
|---|---|---|---|
| OQ-1 | Product name and branding | Team | Week 4 |
| OQ-2 | Dashboard framework — React SPA against a FastAPI backend, or server-rendered? | Frontend lead | Week 6 |
| OQ-3 | PDF generation approach for reports | Frontend lead | Week 7 |
| OQ-4 | Is the high-throughput live capture path (FR-2.6) in scope, given the timeline? | Project lead | Week 5 |
| OQ-5 | Which compliance profile is the default — RFC 8221 baseline or a stricter high-assurance set? | Security lead | Week 7 |
| OQ-6 | Dataset licence for public release | Project lead | Week 10 |

---

## 15. Deliverables mapping

Traceability from the problem statement's required deliverables to this document.

| Required deliverable | Covered by |
|---|---|
| Working software prototype | M1–M6, all must-have functional requirements |
| AI classification engine | M4, §8 |
| Interactive dashboard | M6, FR-6.1 through FR-6.5 |
| Security assessment report | M5, M6, FR-6.6 and FR-6.7, §10 |
| Demonstration video | P6 (§13), demo script in §16 |
| Technical documentation | This PRD, plus architecture and API docs produced in P6 |
| Training/testing dataset | M1, §9.3 |

---

## 16. Demo script

Two prepared tunnels, run live through the tool.

**Tunnel A — deliberately weak.** IKEv1 aggressive mode, 3DES-CBC, HMAC-SHA1-96, DH Group 2, PFS disabled, 24-hour SA lifetime, transport mode, carrying a VoIP call.

**Tunnel B — hardened.** IKEv2, AES-256-GCM, DH Group 19, PFS enabled, 1-hour lifetime, tunnel mode, carrying the same VoIP call.

**Sequence.**

1. Load Tunnel A's capture. Show the score, the critical findings, and the threat matrix lighting up.
2. Show that the traffic classifier identifies the inner traffic as VoIP with high confidence. Explain that this confidence is exactly what a passive adversary learns, and that it is why the metadata exposure component costs points.
3. Load Tunnel B. Show the contrasting score and the near-empty findings list.
4. Open the executive report for Tunnel A. One page, no packet hex, actionable.

Target runtime: two minutes, no slides.

---

## Appendix A — Glossary

| Term | Meaning |
|---|---|
| **AH** | Authentication Header — IPsec protocol providing integrity and authentication without confidentiality |
| **ESP** | Encapsulating Security Payload — IPsec protocol providing confidentiality, integrity, and authentication |
| **ESN** | Extended Sequence Number — 64-bit sequence numbering for high-volume SAs |
| **ICV** | Integrity Check Value — the authentication tag appended to an ESP packet |
| **IKE** | Internet Key Exchange — the protocol that negotiates IPsec Security Associations |
| **PFS** | Perfect Forward Secrecy — fresh DH exchange per Child SA, so compromise of long-term keys does not expose past sessions |
| **SA** | Security Association — a one-way negotiated set of parameters protecting traffic |
| **SPI** | Security Parameter Index — identifier selecting the SA a packet belongs to |
| **Track A** | Deterministic parsing of cleartext IKE |
| **Track B** | Statistical inference over encrypted ESP |

## Appendix B — Standards referenced

| Standard | Relevance |
|---|---|
| RFC 8221 | Cryptographic algorithm implementation requirements for ESP and AH |
| RFC 8247 | Algorithm implementation requirements and usage guidance for IKEv2 |
| RFC 7296 | IKEv2 protocol specification |
| RFC 4301 | Security architecture for IP |
| RFC 4303 | ESP specification |
| NIST SP 800-77 Rev. 1 | Guide to IPsec VPNs |
| NIST SP 800-57 Part 1 | Key management recommendations, key-length guidance |
| MITRE ATT&CK | Threat matrix technique mapping |

*Confirm the current revision of each standard before the technical report is finalised.*
