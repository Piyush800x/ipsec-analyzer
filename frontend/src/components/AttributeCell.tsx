/**
 * The provenance component. Step 7.4, LLD section 11.3.
 *
 * The single most important element in the product, because it is the visual
 * expression of the whole thesis: an analyst acting on this report must always
 * be able to tell a parsed fact from a statistical estimate from an honest gap.
 *
 * Three renderings, three visual weights:
 *
 *   observed     plain, confident, no decoration -- it is simply true
 *   inferred     the value, a confidence bar, and what produced it
 *   unavailable  the *reason*, in words. Never a blank cell, never a dash.
 *
 * That last one is the one that gets cut under time pressure and the one that
 * matters most. "AES key length cannot be determined from ESP alone" is a
 * finding the tool is making, not an absence of data (FR-4.9), and rendering
 * it as "—" throws away the product's most defensible claim.
 */

import type { Attribute, Evidence } from "@/lib/types";

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return String(value);
  return String(value);
}

function confidenceTone(confidence: number): string {
  if (confidence >= 0.9) return "bg-emerald-500";
  if (confidence >= 0.7) return "bg-amber-500";
  return "bg-orange-600";
}

function EvidenceLine({ evidence }: { evidence: Evidence }) {
  const measured = Object.entries(evidence.measured ?? {});
  return (
    <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
      <span className="font-mono">{evidence.method}</span>
      {evidence.packet_indices?.length > 0 && (
        <span>
          {" · packets "}
          {evidence.packet_indices.slice(0, 5).join(", ")}
          {evidence.total_matching ? ` of ${evidence.total_matching.toLocaleString()}` : ""}
        </span>
      )}
      {measured.length > 0 && (
        <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
          {measured.map(([key, value]) => (
            <div key={key} className="contents">
              <dt className="font-mono text-zinc-400">{key}</dt>
              <dd className="font-mono text-zinc-500 dark:text-zinc-400">{String(value)}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function Observed<T>({ attr }: { attr: Attribute<T> }) {
  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="font-medium text-zinc-900 dark:text-zinc-50">
          {formatValue(attr.value)}
        </span>
        <span
          className="rounded bg-sky-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-sky-800 dark:bg-sky-950 dark:text-sky-300"
          title="Parsed from cleartext IKE. This is a fact, not an estimate."
        >
          Observed
        </span>
      </div>
      {attr.evidence && <EvidenceLine evidence={attr.evidence} />}
    </div>
  );
}

function Inferred<T>({ attr }: { attr: Attribute<T> }) {
  const confidence = attr.confidence ?? 0;
  const percent = Math.round(confidence * 100);
  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="font-medium text-zinc-900 dark:text-zinc-50">
          {formatValue(attr.value)}
        </span>
        <span
          className="rounded bg-violet-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-violet-800 dark:bg-violet-950 dark:text-violet-300"
          title="Statistically inferred. Carries a calibrated confidence."
        >
          Inferred
        </span>
      </div>
      <div className="mt-1 flex items-center gap-2">
        <div
          className="h-1.5 w-24 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800"
          role="meter"
          aria-valuenow={percent}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Confidence"
        >
          <div
            className={`h-full rounded-full ${confidenceTone(confidence)}`}
            style={{ width: `${percent}%` }}
          />
        </div>
        <span className="text-xs tabular-nums text-zinc-600 dark:text-zinc-400">
          {percent}% confident
        </span>
      </div>
      {attr.note && (
        <p className="mt-1 text-xs leading-snug text-zinc-500 dark:text-zinc-400">{attr.note}</p>
      )}
      {attr.evidence && <EvidenceLine evidence={attr.evidence} />}
    </div>
  );
}

function Unavailable({ note }: { note?: string | null }) {
  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="text-zinc-500 italic dark:text-zinc-400">Not determinable</span>
        <span
          className="rounded bg-zinc-200 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
          title="This capture cannot support this claim. The reason is stated."
        >
          Unavailable
        </span>
      </div>
      {/* The reason is the content here, not a footnote to it. */}
      <p className="mt-1 max-w-prose text-xs leading-snug text-zinc-600 dark:text-zinc-400">
        {note ?? "No reason was recorded, which is itself a defect."}
      </p>
    </div>
  );
}

export function AttributeCell<T>({ attr }: { attr: Attribute<T> }) {
  if (attr.provenance === "unavailable") return <Unavailable note={attr.note} />;
  if (attr.provenance === "observed") return <Observed attr={attr} />;
  return <Inferred attr={attr} />;
}
