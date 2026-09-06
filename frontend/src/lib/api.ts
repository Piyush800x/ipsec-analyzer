/**
 * The data layer. Step 7.3.
 *
 * With `USE_FIXTURES=1` every read is served from the two step 1.4 fixtures,
 * so the whole dashboard renders with the backend entirely offline. That is
 * not a testing convenience bolted on afterwards: the frontend was built
 * against those fixtures months before the engine produced anything, and the
 * flag is what kept that possible.
 */

import type { Assessment, CapturePage, ComparisonResponse, RunSummary } from "./types";
import weakFixture from "./fixtures/assessment_weak.json";
import strongFixture from "./fixtures/assessment_strong.json";

export const USE_FIXTURES = process.env.USE_FIXTURES === "1";

const API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:8000";

const FIXTURES: Record<string, Assessment> = {
  weak: weakFixture as unknown as Assessment,
  strong: strongFixture as unknown as Assessment,
  [(weakFixture as unknown as Assessment).assessment_id]: weakFixture as unknown as Assessment,
  [(strongFixture as unknown as Assessment).assessment_id]: strongFixture as unknown as Assessment,
};

export function fixtureAssessments(): Assessment[] {
  return [weakFixture as unknown as Assessment, strongFixture as unknown as Assessment];
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(detail);
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}/api/v1${path}`, {
    ...init,
    headers: { accept: "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    // Problem Details (RFC 9457) if the backend produced it, plain text if
    // something in front of it did.
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail ?? body.title ?? detail;
    } catch {
      /* keep the status text */
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

/**
 * An assessment is immutable once written, so it is safe to cache hard and
 * key on its id (LLD section 11.2).
 */
export async function getAssessment(id: string): Promise<Assessment> {
  if (USE_FIXTURES) {
    const fixture = FIXTURES[id];
    if (!fixture) throw new ApiError(404, `No fixture assessment ${id}`);
    return fixture;
  }
  const response = await fetch(`${API_BASE_URL}/api/v1/assessments/${id}`, {
    cache: "force-cache",
  });
  if (!response.ok) throw new ApiError(response.status, `No assessment ${id}`);
  return (await response.json()) as Assessment;
}

export async function listCaptures(limit = 50, offset = 0): Promise<CapturePage> {
  if (USE_FIXTURES) {
    return { items: [], total: 0, limit, offset };
  }
  return apiFetch<CapturePage>(`/captures?limit=${limit}&offset=${offset}`);
}

export async function getRun(id: string): Promise<RunSummary> {
  return apiFetch<RunSummary>(`/runs/${id}`);
}

export async function compareAssessments(a: string, b: string): Promise<ComparisonResponse> {
  if (USE_FIXTURES) {
    return fixtureComparison(a, b);
  }
  return apiFetch<ComparisonResponse>(`/assessments/compare?a=${a}&b=${b}`);
}

/** The offline half of step 7.12, computed from the fixtures themselves. */
function fixtureComparison(aId: string, bId: string): ComparisonResponse {
  const a = FIXTURES[aId];
  const b = FIXTURES[bId];
  if (!a || !b) throw new ApiError(404, "Unknown fixture assessment");

  const aFindings = new Set(a.findings.map((f) => f.id));
  const bFindings = new Set(b.findings.map((f) => f.id));
  const saA = a.security_associations[0];
  const saB = b.security_associations[0];

  const fields = [
    "ike_version",
    "ike_exchange_mode",
    "encryption_alg",
    "encryption_keylen",
    "integrity_alg",
    "prf_alg",
    "dh_group",
    "operating_mode",
    "pfs_enabled",
    "auth_method",
    "negotiated_lifetime_s",
    "esn_negotiated",
    "replay_sane",
    "nat_traversal",
    "downgrade_available",
  ] as const;

  return {
    a: { id: a.assessment_id, scoreTotal: a.score.total, rating: a.score.rating },
    b: { id: b.assessment_id, scoreTotal: b.score.total, rating: b.score.rating },
    scoreDelta: b.score.total - a.score.total,
    findingsOnlyInA: [...aFindings].filter((id) => !bFindings.has(id)).sort(),
    findingsOnlyInB: [...bFindings].filter((id) => !aFindings.has(id)).sort(),
    findingsInBoth: [...aFindings].filter((id) => bFindings.has(id)).sort(),
    attributeDiffs: fields.map((field) => {
      const left = saA?.[field];
      const right = saB?.[field];
      return {
        field,
        aValue: left?.value ?? null,
        aProvenance: left?.provenance ?? null,
        bValue: right?.value ?? null,
        bProvenance: right?.provenance ?? null,
        changed: left?.value !== right?.value || left?.provenance !== right?.provenance,
      };
    }),
  };
}
