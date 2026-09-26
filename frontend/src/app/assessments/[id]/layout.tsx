/** Score header and tab navigation. Step 7.7. Server Component. */

import Link from "next/link";
import { notFound } from "next/navigation";

import { ReportDownloads } from "@/components/ReportDownloads";
import { ScoreDial } from "@/components/ui";
import { getAssessment, USE_FIXTURES } from "@/lib/api";

const TABS = [
  { slug: "", label: "Overview" },
  { slug: "configuration", label: "Configuration" },
  { slug: "findings", label: "Findings" },
  { slug: "traffic", label: "Traffic" },
  { slug: "threats", label: "Threats" },
];

export default async function AssessmentLayout({
  children,
  params,
}: LayoutProps<"/assessments/[id]">) {
  const { id } = await params;

  let assessment;
  try {
    assessment = await getAssessment(id);
  } catch {
    notFound();
  }

  const { score, metadata_exposure, capture_quality } = assessment;

  return (
    <div className="flex flex-col gap-6">
      <header className="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div>
            <p className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              Security score
            </p>
            <div className="mt-1">
              <ScoreDial total={score.total} rating={score.rating} />
            </div>
          </div>

          <div className="text-right">
            <p className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              Metadata exposure
            </p>
            <p className="mt-1 text-3xl font-semibold tabular-nums text-zinc-800 dark:text-zinc-100">
              {metadata_exposure.score}
            </p>
            {/* Inverted relative to the score above, which needs saying. */}
            <p className="text-xs text-zinc-500 dark:text-zinc-400">higher means more leakage</p>
          </div>
        </div>

        <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-2 border-t border-zinc-100 pt-4 text-xs sm:grid-cols-4 dark:border-zinc-800">
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">Packets</dt>
            <dd className="tabular-nums">{capture_quality.packet_count.toLocaleString()}</dd>
          </div>
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">Duration</dt>
            <dd className="tabular-nums">{capture_quality.duration_s.toFixed(1)} s</dd>
          </div>
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">IKE captured</dt>
            <dd>{capture_quality.ike_complete ? "complete" : capture_quality.has_ike ? "partial" : "none"}</dd>
          </div>
          <div>
            <dt className="text-zinc-500 dark:text-zinc-400">Engine</dt>
            <dd className="font-mono">{assessment.engine_version}</dd>
          </div>
        </dl>

        {/* Fixture mode has no backend to render a PDF, so offer nothing
            rather than two buttons that can only fail. */}
        {!USE_FIXTURES && (
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-zinc-100 pt-4 dark:border-zinc-800">
            <p className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              Download report
            </p>
            <ReportDownloads assessmentId={id} />
          </div>
        )}
      </header>

      <nav className="flex gap-1 border-b border-zinc-200 dark:border-zinc-800">
        {TABS.map((tab) => (
          <Link
            key={tab.slug}
            href={`/assessments/${id}${tab.slug ? `/${tab.slug}` : ""}`}
            className="rounded-t-md px-4 py-2 text-sm text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
          >
            {tab.label}
          </Link>
        ))}
      </nav>

      {children}
    </div>
  );
}
