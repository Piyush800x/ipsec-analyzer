"use client";

/**
 * Live run progress over SSE. Step 7.6.
 *
 * `EventSource` against the proxy route, which passes the stream through
 * unbuffered. The stage list is fixed rather than derived from the events, so
 * a viewer can see what has not happened yet as well as what has -- a bar that
 * only shows completed stages hides where a stalled run is stalled.
 */

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

const STAGES = ["ingest", "track_a", "track_b", "assess"] as const;

const STAGE_LABELS: Record<string, string> = {
  queued: "Queued",
  ingest: "Reading packets",
  track_a: "Parsing IKE",
  track_b: "Statistical inference",
  assess: "Applying policy",
  report: "Rendering report",
};

interface ProgressEvent {
  runId: string;
  stage: string;
  progress: number;
  message: string;
}

export function RunProgress({ runId }: { runId: string }) {
  const router = useRouter();
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState<string>("queued");
  const [message, setMessage] = useState("waiting for a slot");
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const source = new EventSource(`/api/runs/${runId}/events`);

    source.addEventListener("progress", (event) => {
      const data = JSON.parse((event as MessageEvent).data) as ProgressEvent;
      setProgress(data.progress);
      setStage(data.stage);
      setMessage(data.message);
    });

    source.addEventListener("complete", (event) => {
      const data = JSON.parse((event as MessageEvent).data) as { assessmentId: string };
      setProgress(1);
      setAssessmentId(data.assessmentId);
      source.close();
      router.refresh();
    });

    source.addEventListener("error", (event) => {
      const raw = (event as MessageEvent).data;
      if (raw) {
        setError((JSON.parse(raw) as { detail: string }).detail);
        source.close();
      }
      // A bare error event is a transient reconnect; EventSource retries on
      // its own and saying so would be noise.
    });

    return () => source.close();
  }, [runId, router]);

  const reachedIndex = STAGES.indexOf(stage as (typeof STAGES)[number]);

  return (
    <div>
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium">{STAGE_LABELS[stage] ?? stage}</span>
        <span className="tabular-nums text-zinc-500 dark:text-zinc-400">
          {Math.round(progress * 100)}%
        </span>
      </div>

      <div className="mt-2 h-2 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800">
        <div
          className={`h-full rounded-full transition-[width] ${
            error ? "bg-red-600" : "bg-sky-600"
          }`}
          style={{ width: `${Math.round(progress * 100)}%` }}
        />
      </div>

      <ol className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {STAGES.map((name, index) => (
          <li
            key={name}
            className={
              index < reachedIndex || progress >= 1
                ? "text-emerald-700 dark:text-emerald-400"
                : index === reachedIndex
                  ? "font-medium text-sky-700 dark:text-sky-400"
                  : "text-zinc-400 dark:text-zinc-600"
            }
          >
            {STAGE_LABELS[name]}
          </li>
        ))}
      </ol>

      <p className="mt-2 text-xs text-zinc-500 dark:text-zinc-400">{message}</p>

      {error && (
        <p className="mt-3 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
          The analysis failed: {error}
        </p>
      )}

      {assessmentId && (
        <a
          href={`/assessments/${assessmentId}`}
          className="mt-3 inline-block rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-700"
        >
          View the assessment
        </a>
      )}
    </div>
  );
}
