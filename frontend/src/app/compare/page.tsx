/**
 * Side-by-side assessment comparison. Step 7.12.
 *
 * The backbone of the demo: the weak and hardened tunnels differ in almost
 * every parameter, and this view is where that lands in one screen. The
 * provenance column matters as much as the value column -- hardening the
 * cryptography moves `encryption_alg` from observed-3DES to inferred-AES-GCM,
 * and it barely moves metadata exposure at all, which is the point.
 */

import { notFound } from "next/navigation";

import { Card, EmptyState } from "@/components/ui";
import { compareAssessments, fixtureAssessments, USE_FIXTURES } from "@/lib/api";
import type { Provenance } from "@/lib/types";

const FIELD_LABELS: Record<string, string> = {
  ike_version: "IKE version",
  ike_exchange_mode: "Exchange mode",
  encryption_alg: "Encryption algorithm",
  encryption_keylen: "Key length",
  integrity_alg: "Integrity algorithm",
  prf_alg: "PRF",
  dh_group: "DH group",
  operating_mode: "Operating mode",
  pfs_enabled: "Perfect Forward Secrecy",
  auth_method: "Authentication",
  negotiated_lifetime_s: "Negotiated lifetime",
  esn_negotiated: "Extended Sequence Numbers",
  replay_sane: "Sequence numbers sane",
  nat_traversal: "NAT traversal",
  downgrade_available: "Weaker proposal offered",
};

function Cell({ value, provenance }: { value: unknown; provenance: Provenance | null }) {
  if (provenance === "unavailable" || value === null || value === undefined) {
    return <span className="text-zinc-400 italic dark:text-zinc-500">not determinable</span>;
  }
  const rendered = typeof value === "boolean" ? (value ? "Yes" : "No") : String(value);
  return (
    <span>
      <span className="font-medium">{rendered}</span>
      {provenance === "inferred" && (
        <span className="ml-1.5 text-[10px] uppercase tracking-wide text-violet-700 dark:text-violet-400">
          inferred
        </span>
      )}
    </span>
  );
}

export default async function ComparePage({ searchParams }: PageProps<"/compare">) {
  const query = await searchParams;
  const defaults = USE_FIXTURES ? fixtureAssessments() : [];
  const a = (typeof query.a === "string" ? query.a : undefined) ?? defaults[0]?.assessment_id;
  const b = (typeof query.b === "string" ? query.b : undefined) ?? defaults[1]?.assessment_id;

  if (!a || !b) {
    return (
      <EmptyState
        title="Pick two assessments"
        detail="Pass ?a=<id>&b=<id>. With USE_FIXTURES=1 the two demo assessments are the default."
      />
    );
  }

  let comparison;
  try {
    comparison = await compareAssessments(a, b);
  } catch {
    notFound();
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Comparison</h1>
        <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
          Two deployments, parameter by parameter.
        </p>
      </div>

      <Card>
        <div className="grid grid-cols-3 items-center gap-4 text-center">
          <div>
            <p className="text-3xl font-semibold tabular-nums">{comparison.a.scoreTotal}</p>
            <p className="text-xs capitalize text-zinc-500 dark:text-zinc-400">
              {comparison.a.rating}
            </p>
          </div>
          <div>
            <p
              className={`text-2xl font-semibold tabular-nums ${
                comparison.scoreDelta > 0
                  ? "text-emerald-600 dark:text-emerald-400"
                  : comparison.scoreDelta < 0
                    ? "text-red-600 dark:text-red-400"
                    : "text-zinc-500"
              }`}
            >
              {comparison.scoreDelta > 0 ? "+" : ""}
              {comparison.scoreDelta}
            </p>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">points</p>
          </div>
          <div>
            <p className="text-3xl font-semibold tabular-nums">{comparison.b.scoreTotal}</p>
            <p className="text-xs capitalize text-zinc-500 dark:text-zinc-400">
              {comparison.b.rating}
            </p>
          </div>
        </div>
      </Card>

      <Card title="Parameters">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-200 text-left text-xs uppercase tracking-wide text-zinc-500 dark:border-zinc-800 dark:text-zinc-400">
              <th className="pb-2 font-medium">Parameter</th>
              <th className="pb-2 font-medium">A</th>
              <th className="pb-2 font-medium">B</th>
            </tr>
          </thead>
          <tbody>
            {comparison.attributeDiffs.map((diff) => (
              <tr
                key={diff.field}
                className={`border-b border-zinc-100 last:border-0 dark:border-zinc-800 ${
                  diff.changed ? "bg-amber-50/50 dark:bg-amber-950/20" : ""
                }`}
              >
                <td className="py-2 text-zinc-600 dark:text-zinc-400">
                  {FIELD_LABELS[diff.field] ?? diff.field}
                </td>
                <td className="py-2">
                  <Cell value={diff.aValue} provenance={diff.aProvenance} />
                </td>
                <td className="py-2">
                  <Cell value={diff.bValue} provenance={diff.bProvenance} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Only in A">
          <ul className="flex flex-col gap-1 font-mono text-xs">
            {comparison.findingsOnlyInA.map((id) => (
              <li key={id} className="text-red-700 dark:text-red-400">
                {id}
              </li>
            ))}
            {comparison.findingsOnlyInA.length === 0 && (
              <li className="font-sans text-zinc-500 dark:text-zinc-400">none</li>
            )}
          </ul>
        </Card>
        <Card title="In both">
          <ul className="flex flex-col gap-1 font-mono text-xs">
            {comparison.findingsInBoth.map((id) => (
              <li key={id} className="text-amber-700 dark:text-amber-400">
                {id}
              </li>
            ))}
            {comparison.findingsInBoth.length === 0 && (
              <li className="font-sans text-zinc-500 dark:text-zinc-400">none</li>
            )}
          </ul>
        </Card>
        <Card title="Only in B">
          <ul className="flex flex-col gap-1 font-mono text-xs">
            {comparison.findingsOnlyInB.map((id) => (
              <li key={id} className="text-red-700 dark:text-red-400">
                {id}
              </li>
            ))}
            {comparison.findingsOnlyInB.length === 0 && (
              <li className="font-sans text-zinc-500 dark:text-zinc-400">none</li>
            )}
          </ul>
        </Card>
      </div>
    </div>
  );
}
