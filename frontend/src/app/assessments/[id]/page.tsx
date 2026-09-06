/** Assessment overview. Step 7.7. */

import { notFound } from "next/navigation";

import { Card, SeverityBadge } from "@/components/ui";
import { getAssessment } from "@/lib/api";
import type { Severity } from "@/lib/types";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];

const CATEGORY_LABELS: Record<string, string> = {
  cryptographic_strength: "Cryptographic strength",
  key_exchange: "Key exchange",
  protocol_version_mode: "Protocol version and mode",
  key_management: "Key management",
  replay_integrity: "Replay and integrity",
  metadata_exposure: "Metadata exposure",
};

export default async function OverviewPage({ params }: PageProps<"/assessments/[id]">) {
  const { id } = await params;
  let assessment;
  try {
    assessment = await getAssessment(id);
  } catch {
    notFound();
  }

  const counts = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: assessment.findings.filter((f) => f.severity === severity).length,
  })).filter((entry) => entry.count > 0);

  const quality = assessment.capture_quality;

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title="Findings by severity">
        {counts.length === 0 ? (
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            No findings. Nothing in the policy matched this deployment.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {counts.map(({ severity, count }) => (
              <li key={severity} className="flex items-center justify-between text-sm">
                <SeverityBadge severity={severity} />
                <span className="tabular-nums font-medium">{count}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Where the points went">
        <ul className="flex flex-col gap-2 text-sm">
          {Object.entries(assessment.score.category_penalties).map(([category, penalty]) => (
            <li key={category} className="flex items-center justify-between gap-4">
              <span className="text-zinc-700 dark:text-zinc-300">
                {CATEGORY_LABELS[category] ?? category}
              </span>
              <span className="tabular-nums font-medium text-red-700 dark:text-red-400">
                −{penalty}
              </span>
            </li>
          ))}
          <li className="mt-2 flex items-center justify-between border-t border-zinc-100 pt-2 font-medium dark:border-zinc-800">
            <span>Total</span>
            <span className="tabular-nums">{assessment.score.total} / 100</span>
          </li>
        </ul>
      </Card>

      <Card title="Metadata exposure" className="lg:col-span-2">
        <p className="max-w-prose text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
          {assessment.metadata_exposure.rationale}
        </p>
      </Card>

      <Card title="Capture quality" className="lg:col-span-2">
        <dl className="grid grid-cols-2 gap-x-8 gap-y-3 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">Truncated</dt>
            <dd>{quality.truncated ? "Yes — snaplen cut packets short" : "No"}</dd>
          </div>
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">ESP SAs</dt>
            <dd className="tabular-nums">{quality.esp_sa_count}</dd>
          </div>
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">Cipher-family sieve</dt>
            <dd>
              {quality.sufficient_for_lattice
                ? "Enough length diversity to run"
                : "Not enough length diversity — the detector refuses to guess"}
            </dd>
          </div>
        </dl>
        {quality.warnings.length > 0 && (
          <ul className="mt-4 flex flex-col gap-1 border-t border-zinc-100 pt-3 text-xs text-amber-700 dark:border-zinc-800 dark:text-amber-400">
            {quality.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
