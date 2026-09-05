/** ATT&CK threat matrix. Step 7.11. */

import Link from "next/link";
import { notFound } from "next/navigation";

import { EmptyState, SeverityBadge } from "@/components/ui";
import { getAssessment } from "@/lib/api";

export default async function ThreatsPage({ params }: PageProps<"/assessments/[id]"> ) {
  const { id } = await params;
  let assessment;
  try {
    assessment = await getAssessment(id);
  } catch {
    notFound();
  }

  if (assessment.threat_matrix.length === 0) {
    return (
      <EmptyState
        title="No techniques on the board"
        detail="No finding in this assessment maps to a MITRE ATT&CK technique."
      />
    );
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {assessment.threat_matrix.map((entry) => (
        <Link
          key={entry.technique_id}
          href={`/assessments/${id}/findings?technique=${entry.technique_id}`}
          className="flex flex-col rounded-lg border border-zinc-200 bg-white p-4 transition-colors hover:border-sky-400 dark:border-zinc-800 dark:bg-zinc-900"
        >
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-xs text-zinc-500 dark:text-zinc-400">
              {entry.technique_id}
            </span>
            <SeverityBadge severity={entry.max_severity} />
          </div>
          <h3 className="mt-1 text-sm font-semibold">{entry.technique_name}</h3>
          <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
            {entry.tactics.join(" · ")}
          </p>
          <ul className="mt-3 flex flex-col gap-0.5 text-xs text-zinc-600 dark:text-zinc-400">
            {entry.finding_ids.map((findingId) => (
              <li key={findingId} className="font-mono">
                {findingId}
              </li>
            ))}
          </ul>
          <span className="mt-3 text-xs text-sky-700 dark:text-sky-400">
            Show contributing findings →
          </span>
        </Link>
      ))}
    </div>
  );
}
