"use client";

/**
 * Starts a run and hands over to the live progress view. Steps 7.5, 7.6.
 *
 * The optional address is sent with the request that starts the run, not
 * after it: the backend emails both PDFs itself when the run completes, so
 * the reports arrive even if this tab is closed long before then. A server
 * with no SMTP configured refuses the address with a 503 before any run
 * starts, and that `detail` is shown here as-is.
 */

import { type FormEvent, useState } from "react";

import type { components } from "@/types/generated";

import { RunProgress } from "./RunProgress";

type AnalyzeRequest = components["schemas"]["AnalyzeRequest"];

export function AnalyzeButton({ captureId }: { captureId: string }) {
  const [runId, setRunId] = useState<string | null>(null);
  const [notifyEmail, setNotifyEmail] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    // Read from the form, not from state. Text typed before React hydrated
    // the input is in the DOM but never reached an onChange handler, so a
    // controlled input would start the run without the address and say
    // nothing. Found by driving this page in a real browser.
    const address = String(new FormData(event.currentTarget).get("email") ?? "").trim() || null;
    setStarting(true);
    setError(null);
    const request: AnalyzeRequest = address ? { notifyEmail: address } : {};
    try {
      const response = await fetch(`/api/captures/${captureId}/analyze`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      });
      const body = await response.json();
      if (!response.ok) {
        setError(body.detail ?? "Could not start the analysis");
        return;
      }
      setNotifyEmail(address);
      setRunId(body.runId);
    } catch {
      setError("Could not reach the API");
    } finally {
      setStarting(false);
    }
  }

  if (runId) return <RunProgress runId={runId} notifyEmail={notifyEmail} />;

  return (
    <form onSubmit={start} className="flex flex-col gap-3">
      <label className="flex max-w-sm flex-col gap-1 text-sm">
        <span className="text-zinc-600 dark:text-zinc-400">
          Email the PDF reports when it finishes{" "}
          <span className="text-zinc-400 dark:text-zinc-500">(optional)</span>
        </span>
        <input
          type="email"
          name="email"
          autoComplete="email"
          placeholder="you@example.com"
          className="rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm placeholder:text-zinc-400 focus:border-sky-500 focus:outline-none dark:border-zinc-700 dark:bg-zinc-950"
        />
      </label>
      <div>
        <button
          type="submit"
          disabled={starting}
          className="rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-60"
        >
          {starting ? "Starting…" : "Analyse this capture"}
        </button>
      </div>
      {error && <p className="text-sm text-red-700 dark:text-red-400">{error}</p>}
    </form>
  );
}
