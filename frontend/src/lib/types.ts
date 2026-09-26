/**
 * Domain types mirroring `backend/src/analyzer/core/schema.py`.
 *
 * `src/types/generated.ts` covers the API's request and response envelopes,
 * but the assessment *document* crosses the wire as an opaque object (the API
 * serves the stored artefact verbatim, deliberately), so its shape is declared
 * here. Keys stay snake_case because that is what the document itself uses --
 * only the API envelopes are camelCase (CLAUDE.md).
 */

export type Provenance = "observed" | "inferred" | "unavailable";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type Rating = "critical" | "poor" | "fair" | "good" | "strong";

export type FindingCategory =
  | "cryptographic_strength"
  | "key_exchange"
  | "protocol_version_mode"
  | "key_management"
  | "replay_integrity"
  | "metadata_exposure";

/** `core/enums.py` `EmailDelivery`. Rides on the run's SSE `complete` event. */
export type EmailDelivery = "sent" | "failed";

export type TrafficClass =
  | "icmp"
  | "web"
  | "voip"
  | "video"
  | "email"
  | "file_transfer"
  | "messaging";

export interface FeatureAttribution {
  feature: string;
  contribution: number;
  observed_value?: number | string | null;
}

export interface Evidence {
  method: string;
  packet_indices: number[];
  measured: Record<string, number | string>;
  total_matching?: number | null;
}

/** The load-bearing type. See `AttributeCell` for how each state renders. */
export interface Attribute<T> {
  value: T | null;
  provenance: Provenance;
  confidence?: number | null;
  evidence?: Evidence | null;
  note?: string | null;
}

export interface TrafficPrediction {
  label: TrafficClass;
  probability: number;
  window_start: string;
  window_end: string;
  top_features?: FeatureAttribution[];
}

export interface SecurityAssociation {
  spi_initiator: string;
  spi_responder: string | null;
  src: string;
  dst: string;
  ip_version: 4 | 6;
  protocol: "esp" | "ah";
  first_seen: string;
  last_seen: string;
  packet_count: number;
  byte_count: number;

  ike_version: Attribute<string>;
  ike_exchange_mode: Attribute<string>;
  encryption_alg: Attribute<string>;
  encryption_keylen: Attribute<number>;
  integrity_alg: Attribute<string>;
  prf_alg: Attribute<string>;
  dh_group: Attribute<number>;
  operating_mode: Attribute<string>;
  pfs_enabled: Attribute<boolean>;
  auth_method: Attribute<string>;
  negotiated_lifetime_s: Attribute<number>;
  observed_rekey_s: Attribute<number>;
  esn_negotiated: Attribute<boolean>;
  replay_sane: Attribute<boolean>;
  nat_traversal: Attribute<boolean>;
  downgrade_available: Attribute<boolean>;

  inner_traffic: TrafficPrediction[];
}

export interface StandardRef {
  ref: string;
  clause?: string | null;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  penalty: number;
  description: string;
  remediation: string;
  standards: StandardRef[];
  attack_techniques: string[];
  sa_spi: string | null;
  evidence: Evidence;
}

export interface CaptureQuality {
  packet_count: number;
  duration_s: number;
  truncated: boolean;
  has_ike: boolean;
  ike_complete: boolean;
  esp_sa_count: number;
  sufficient_for_lattice: boolean;
  warnings: string[];
}

export interface ScoreBreakdown {
  total: number;
  category_penalties: Partial<Record<FindingCategory, number>>;
  rating: Rating;
}

export interface MetadataExposure {
  score: number;
  mean_classifier_confidence: number;
  identified_classes: TrafficClass[];
  rationale: string;
}

export interface ThreatMatrixEntry {
  technique_id: string;
  technique_name: string;
  tactics: string[];
  finding_ids: string[];
  max_severity: Severity;
}

export interface Assessment {
  schema_version: string;
  assessment_id: string;
  capture_id: string;
  generated_at: string;
  engine_version: string;
  policy_version: string;
  model_versions: Record<string, string>;
  capture_quality: CaptureQuality;
  security_associations: SecurityAssociation[];
  findings: Finding[];
  score: ScoreBreakdown;
  metadata_exposure: MetadataExposure;
  threat_matrix: ThreatMatrixEntry[];
}

/** API envelopes (camelCase, per the boundary rule). */
export interface CaptureSummary {
  id: string;
  filename: string;
  sha256: string;
  sizeBytes: number;
  source: "upload" | "live" | "testbed";
  packetCount: number | null;
  durationS: number | null;
  hasIke: boolean | null;
  truncated: boolean | null;
  createdAt: string;
}

export interface CapturePage {
  items: CaptureSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface RunSummary {
  id: string;
  captureId: string;
  status: "queued" | "running" | "succeeded" | "failed";
  stage: string | null;
  progress: number;
  engineVersion: string;
  policyVersion: string;
  error: Record<string, unknown> | null;
  startedAt: string | null;
  finishedAt: string | null;
  assessmentId: string | null;
}

export interface AttributeDiff {
  field: string;
  aValue: unknown;
  aProvenance: Provenance | null;
  bValue: unknown;
  bProvenance: Provenance | null;
  changed: boolean;
}

export interface ComparisonResponse {
  a: { id: string; scoreTotal: number; rating: Rating };
  b: { id: string; scoreTotal: number; rating: Rating };
  scoreDelta: number;
  findingsOnlyInA: string[];
  findingsOnlyInB: string[];
  findingsInBoth: string[];
  attributeDiffs: AttributeDiff[];
}
