"use client";

/** Starts a run and hands over to the live progress view. Steps 7.5, 7.6. */

import { useState } from "react";

import { RunProgress } from "./RunProgress";

export function AnalyzeButton({ captureId }: { captureId: string }) {
  const [runId, setRunId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  async function start() {
    setStarting(true);
    setError(null);
    try {
      const response = await fetch(`/api/captures/${captureId}/analyze`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) {
        setError(body.detail ?? "Could not start the analysis");
        return;
      }
      setRunId(body.runId);
    } catch {
      setError("Could not reach the API");
    } finally {
      setStarting(false);
    }
  }

  if (runId) return <RunProgress runId={runId} />;

  return (
    <div>
      <button
        type="button"
        onClick={start}
        disabled={starting}
        className="rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-60"
      >
        {starting ? "Starting…" : "Analyse this capture"}
      </button>
      {error && <p className="mt-2 text-sm text-red-700 dark:text-red-400">{error}</p>}
    </div>
  );
}
