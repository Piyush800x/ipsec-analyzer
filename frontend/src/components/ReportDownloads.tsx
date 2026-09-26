"use client";

/**
 * Download buttons for the two PDF reports (FR-6.6, FR-6.7).
 *
 * `fetch` and a blob rather than a plain `<a href download>`, because when
 * the endpoint fails its Problem Details `detail` is worth showing. An anchor
 * would save that JSON as a file named `.pdf`, or navigate to it; this shows
 * the sentence instead. (A missing PDF engine is no longer one of those
 * failures: the backend falls back to a pure-Python renderer.)
 */

import { useState } from "react";

type ReportFormat = "executive" | "technical";

const LABELS: Record<ReportFormat, string> = {
  executive: "Executive PDF",
  technical: "Technical PDF",
};

function filenameFrom(disposition: string | null, fallback: string): string {
  const match = disposition?.match(/filename="?([^";]+)"?/i);
  return match?.[1] ?? fallback;
}

export function ReportDownloads({ assessmentId }: { assessmentId: string }) {
  const [pending, setPending] = useState<ReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function download(format: ReportFormat) {
    setPending(format);
    setError(null);
    try {
      const response = await fetch(`/api/assessments/${assessmentId}/report?format=${format}`);
      if (!response.ok) {
        let detail = `The report could not be generated (HTTP ${response.status})`;
        try {
          detail = (await response.json()).detail ?? detail;
        } catch {
          /* not Problem Details; keep the status line */
        }
        setError(detail);
        return;
      }

      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = filenameFrom(
        response.headers.get("content-disposition"),
        `ipsec-${format}-${assessmentId}.pdf`,
      );
      document.body.appendChild(link);
      link.click();
      link.remove();
      // Revoked on the next tick, not immediately: some browsers start the
      // download asynchronously and read the URL after click() returns.
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch {
      setError("Could not reach the API");
    } finally {
      setPending(null);
    }
  }

  return (
    <div>
      <div className="flex flex-wrap gap-2">
        {(Object.keys(LABELS) as ReportFormat[]).map((format) => (
          <button
            key={format}
            type="button"
            onClick={() => download(format)}
            disabled={pending !== null}
            className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-sm font-medium text-zinc-800 hover:bg-zinc-50 disabled:opacity-60 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:hover:bg-zinc-800"
          >
            {pending === format ? "Preparing…" : `↓ ${LABELS[format]}`}
          </button>
        ))}
      </div>
      {error && <p className="mt-2 text-sm text-red-700 dark:text-red-400">{error}</p>}
    </div>
  );
}
