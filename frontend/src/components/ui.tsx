/** Small shared presentation pieces. Kept deliberately plain. */

import type { Rating, Severity } from "@/lib/types";

export function Card({
  title,
  children,
  className = "",
}: {
  title?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-lg border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-zinc-900 ${className}`}
    >
      {title && (
        <h2 className="mb-3 text-sm font-semibold tracking-tight text-zinc-700 dark:text-zinc-300">
          {title}
        </h2>
      )}
      {children}
    </section>
  );
}

const SEVERITY_TONE: Record<Severity, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  low: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300",
  informational: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${SEVERITY_TONE[severity]}`}
    >
      {severity}
    </span>
  );
}

const RATING_TONE: Record<Rating, string> = {
  critical: "text-red-600 dark:text-red-400",
  poor: "text-orange-600 dark:text-orange-400",
  fair: "text-amber-600 dark:text-amber-400",
  good: "text-lime-600 dark:text-lime-400",
  strong: "text-emerald-600 dark:text-emerald-400",
};

export function ScoreDial({ total, rating }: { total: number; rating: Rating }) {
  return (
    <div className="flex items-baseline gap-3">
      <span className={`text-5xl font-semibold tabular-nums ${RATING_TONE[rating]}`}>{total}</span>
      <div className="flex flex-col">
        <span className="text-xs text-zinc-500 dark:text-zinc-400">out of 100</span>
        <span className={`text-sm font-semibold capitalize ${RATING_TONE[rating]}`}>{rating}</span>
      </div>
    </div>
  );
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="rounded-lg border border-dashed border-zinc-300 p-10 text-center dark:border-zinc-700">
      <p className="font-medium text-zinc-700 dark:text-zinc-300">{title}</p>
      <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">{detail}</p>
    </div>
  );
}
