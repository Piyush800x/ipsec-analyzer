/**
 * Capture detail: summary plus the trigger into analysis. Steps 7.5, 7.6.
 *
 * `AnalyzeButton` and `RunProgress` already existed and were already wired to
 * the live API (upload progress, SSE stage list, hand-off to the assessment
 * once a run completes) -- this page is what was missing to reach them. The
 * capture list on `/` linked here from the start; there was no route here to
 * receive it.
 */

import { notFound } from "next/navigation";

import { AnalyzeButton } from "@/components/AnalyzeButton";
import { Card } from "@/components/ui";
import { getCapture } from "@/lib/api";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

export default async function CaptureDetailPage({ params }: PageProps<"/captures/[id]">) {
  const { id } = await params;
  let capture;
  try {
    capture = await getCapture(id);
  } catch {
    notFound();
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{capture.filename}</h1>
        <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
          Uploaded {new Date(capture.createdAt).toLocaleString()}
        </p>
      </div>

      <Card title="Capture">
        <dl className="grid grid-cols-2 gap-x-8 gap-y-3 text-sm sm:grid-cols-4">
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">Size</dt>
            <dd className="tabular-nums">{formatBytes(capture.sizeBytes)}</dd>
          </div>
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">Packets</dt>
            <dd className="tabular-nums">{capture.packetCount ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">IKE present</dt>
            <dd>{capture.hasIke === null ? "—" : capture.hasIke ? "Yes" : "No"}</dd>
          </div>
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">Truncated</dt>
            <dd>{capture.truncated === null ? "—" : capture.truncated ? "Yes" : "No"}</dd>
          </div>
        </dl>
      </Card>

      <Card title="Analysis">
        <AnalyzeButton captureId={capture.id} />
      </Card>
    </div>
  );
}
