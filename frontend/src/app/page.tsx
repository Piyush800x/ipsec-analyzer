/** Capture list and upload. Step 7.5. */

import Link from "next/link";

import { UploadWidget } from "@/components/UploadWidget";
import { Card, EmptyState } from "@/components/ui";
import { fixtureAssessments, listCaptures, USE_FIXTURES } from "@/lib/api";
import type { CapturePage } from "@/lib/types";

export const dynamic = "force-dynamic";

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

async function safeList(): Promise<CapturePage | null> {
  try {
    return await listCaptures();
  } catch {
    // The dashboard is useful with the backend down -- the fixtures below
    // still render. Surfacing a stack trace here would not be.
    return null;
  }
}

export default async function Home() {
  const page = await safeList();

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Captures</h1>
        <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
          Upload a capture to analyse its IPsec security posture. Nothing leaves this machine.
        </p>
      </div>

      <UploadWidget />

      {USE_FIXTURES && (
        <Card title="Fixture assessments">
          <p className="mb-3 text-sm text-zinc-600 dark:text-zinc-400">
            <code className="font-mono">USE_FIXTURES=1</code> is set, so these render with the
            backend entirely offline.
          </p>
          <ul className="flex flex-wrap gap-3">
            {fixtureAssessments().map((assessment) => (
              <li key={assessment.assessment_id}>
                <Link
                  href={`/assessments/${assessment.assessment_id}`}
                  className="inline-flex items-center gap-2 rounded-md border border-zinc-200 px-3 py-2 text-sm hover:border-sky-400 dark:border-zinc-700"
                >
                  <span className="font-medium">Score {assessment.score.total}</span>
                  <span className="capitalize text-zinc-500 dark:text-zinc-400">
                    {assessment.score.rating}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {page === null ? (
        <EmptyState
          title="The API is not reachable"
          detail="Start the backend with `uv run uvicorn analyzer.api.main:create_app --factory`, or set USE_FIXTURES=1 to work offline."
        />
      ) : page.items.length === 0 ? (
        <EmptyState
          title="No captures yet"
          detail="Upload a PCAP above to get started."
        />
      ) : (
        <Card>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-200 text-left text-xs uppercase tracking-wide text-zinc-500 dark:border-zinc-800 dark:text-zinc-400">
                <th className="pb-2 font-medium">Filename</th>
                <th className="pb-2 font-medium">Size</th>
                <th className="pb-2 font-medium">Packets</th>
                <th className="pb-2 font-medium">IKE</th>
                <th className="pb-2 font-medium">Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((capture) => (
                <tr
                  key={capture.id}
                  className="border-b border-zinc-100 last:border-0 dark:border-zinc-800"
                >
                  <td className="py-2">
                    <Link
                      href={`/captures/${capture.id}`}
                      className="font-medium text-sky-700 hover:underline dark:text-sky-400"
                    >
                      {capture.filename}
                    </Link>
                  </td>
                  <td className="py-2 tabular-nums">{formatBytes(capture.sizeBytes)}</td>
                  <td className="py-2 tabular-nums">{capture.packetCount ?? "—"}</td>
                  <td className="py-2">{capture.hasIke === null ? "—" : capture.hasIke ? "Yes" : "No"}</td>
                  <td className="py-2 text-zinc-500 dark:text-zinc-400">
                    {new Date(capture.createdAt).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
