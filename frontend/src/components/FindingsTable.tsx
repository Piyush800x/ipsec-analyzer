"use client";

/**
 * Sortable, filterable findings with expandable evidence. Step 7.9.
 *
 * Client-side because sorting and filtering 50 findings is instant in the
 * browser and a round trip per click is not (NFR-2 budgets 200 ms for a view
 * change). The relational endpoint exists for cross-capture queries, not for
 * re-sorting a list already on screen.
 */

import { useMemo, useState } from "react";

import { SeverityBadge } from "./ui";
import type { Finding, Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

type SortKey = "penalty" | "severity" | "id";

export function FindingsTable({
  findings,
  initialTechnique,
}: {
  findings: Finding[];
  initialTechnique?: string;
}) {
  const [selected, setSelected] = useState<Set<Severity>>(new Set());
  const [sort, setSort] = useState<SortKey>("penalty");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [technique, setTechnique] = useState<string | undefined>(initialTechnique);

  const visible = useMemo(() => {
    let rows = findings;
    if (selected.size > 0) rows = rows.filter((f) => selected.has(f.severity));
    if (technique) rows = rows.filter((f) => f.attack_techniques.includes(technique));
    return [...rows].sort((a, b) => {
      if (sort === "penalty") return b.penalty - a.penalty;
      if (sort === "severity") return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
      return a.id.localeCompare(b.id);
    });
  }, [findings, selected, sort, technique]);

  function toggle(severity: Severity) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(severity)) next.delete(severity);
      else next.add(severity);
      return next;
    });
  }

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((severity) => (
            <button
              key={severity}
              type="button"
              onClick={() => toggle(severity)}
              aria-pressed={selected.has(severity)}
              className={`rounded-full border px-2.5 py-1 text-xs capitalize transition-colors ${
                selected.has(severity)
                  ? "border-sky-500 bg-sky-50 text-sky-800 dark:bg-sky-950 dark:text-sky-300"
                  : "border-zinc-300 text-zinc-600 dark:border-zinc-700 dark:text-zinc-400"
              }`}
            >
              {severity}
            </button>
          ))}
        </div>

        <label className="ml-auto flex items-center gap-2 text-xs text-zinc-600 dark:text-zinc-400">
          Sort by
          <select
            value={sort}
            onChange={(event) => setSort(event.target.value as SortKey)}
            className="rounded border border-zinc-300 bg-white px-2 py-1 dark:border-zinc-700 dark:bg-zinc-900"
          >
            <option value="penalty">Penalty</option>
            <option value="severity">Severity</option>
            <option value="id">Rule ID</option>
          </select>
        </label>

        {technique && (
          <button
            type="button"
            onClick={() => setTechnique(undefined)}
            className="rounded-full border border-violet-400 bg-violet-50 px-2.5 py-1 text-xs text-violet-800 dark:bg-violet-950 dark:text-violet-300"
          >
            {technique} ✕
          </button>
        )}
      </div>

      <p className="mb-2 text-xs text-zinc-500 dark:text-zinc-400">
        {visible.length} of {findings.length} findings
      </p>

      <ul className="flex flex-col gap-2">
        {visible.map((finding) => {
          const open = expanded === finding.id;
          return (
            <li
              key={`${finding.id}-${finding.sa_spi}`}
              className="rounded-lg border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900"
            >
              <button
                type="button"
                onClick={() => setExpanded(open ? null : finding.id)}
                aria-expanded={open}
                className="flex w-full items-center gap-3 px-4 py-3 text-left"
              >
                <SeverityBadge severity={finding.severity} />
                <span className="flex-1 text-sm font-medium">{finding.title}</span>
                <span className="font-mono text-xs text-zinc-500 dark:text-zinc-400">
                  {finding.id}
                </span>
                <span className="tabular-nums text-sm font-medium text-red-700 dark:text-red-400">
                  −{finding.penalty}
                </span>
              </button>

              {open && (
                <div className="border-t border-zinc-100 px-4 py-3 text-sm dark:border-zinc-800">
                  <p className="max-w-prose leading-relaxed text-zinc-700 dark:text-zinc-300">
                    {finding.description}
                  </p>

                  <h4 className="mt-4 text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                    Remediation
                  </h4>
                  <p className="mt-1 max-w-prose leading-relaxed text-zinc-700 dark:text-zinc-300">
                    {finding.remediation}
                  </p>

                  <h4 className="mt-4 text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                    Evidence
                  </h4>
                  <p className="mt-1 font-mono text-xs text-zinc-600 dark:text-zinc-400">
                    {finding.evidence.method}
                    {finding.evidence.packet_indices.length > 0 &&
                      ` · packets ${finding.evidence.packet_indices.slice(0, 10).join(", ")}`}
                    {finding.evidence.total_matching
                      ? ` of ${finding.evidence.total_matching.toLocaleString()}`
                      : ""}
                  </p>
                  {Object.keys(finding.evidence.measured).length > 0 && (
                    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 text-xs">
                      {Object.entries(finding.evidence.measured).map(([key, value]) => (
                        <div key={key} className="contents">
                          <dt className="font-mono text-zinc-500">{key}</dt>
                          <dd className="font-mono text-zinc-700 dark:text-zinc-300">
                            {String(value)}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  )}

                  {finding.standards.length > 0 && (
                    <p className="mt-3 text-xs text-zinc-500 dark:text-zinc-400">
                      {finding.standards
                        .map((s) => (s.clause ? `${s.ref} ${s.clause}` : s.ref))
                        .join(" · ")}
                      {finding.attack_techniques.length > 0 &&
                        ` · ATT&CK ${finding.attack_techniques.join(", ")}`}
                    </p>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
