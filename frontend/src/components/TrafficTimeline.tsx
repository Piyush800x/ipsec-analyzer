"use client";

/**
 * Inferred traffic classes over time, with confidence bands. Step 7.10.
 *
 * Overlapping prediction windows are the thing to get right: the classifier
 * scores 10-second windows with 50% overlap (LLD section 7.6), so windows
 * genuinely do overlap and stacking them naively produces a pile of
 * unreadable bars. Each label gets its own lane, so overlap is visible rather
 * than collided.
 */

import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { TrafficPrediction } from "@/lib/types";

/** Brand-neutral, colour-blind-safe, and distinguishable in both themes. */
const LABEL_COLOURS: Record<string, string> = {
  icmp: "#0ea5e9",
  web: "#8b5cf6",
  voip: "#10b981",
  video: "#f59e0b",
  email: "#ec4899",
  file_transfer: "#14b8a6",
  messaging: "#f43f5e",
};

export function TrafficTimeline({ predictions }: { predictions: TrafficPrediction[] }) {
  if (predictions.length === 0) {
    return (
      <p className="text-sm text-zinc-600 dark:text-zinc-400">
        No inner traffic was classified for this capture. That is an absence of evidence, not
        evidence that the tunnel leaks nothing.
      </p>
    );
  }

  const start = new Date(predictions[0].window_start).getTime();
  const labels = [...new Set(predictions.map((p) => p.label))];

  // One row per window midpoint, one column per label, so overlapping windows
  // land in separate series instead of on top of each other.
  const rows = predictions.map((prediction) => {
    const from = new Date(prediction.window_start).getTime();
    const to = new Date(prediction.window_end).getTime();
    const row: Record<string, number | null> = {
      t: Math.round((from + (to - from) / 2 - start) / 1000),
    };
    for (const label of labels) {
      row[label] = label === prediction.label ? prediction.probability : null;
    }
    return row;
  });

  return (
    <div>
      <div className="h-72 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={rows} margin={{ top: 8, right: 16, bottom: 24, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="currentColor" className="text-zinc-200 dark:text-zinc-800" />
            <XAxis
              dataKey="t"
              type="number"
              domain={["dataMin", "dataMax"]}
              tick={{ fontSize: 11 }}
              label={{ value: "seconds into capture", position: "insideBottom", offset: -14, fontSize: 11 }}
            />
            <YAxis
              domain={[0, 1]}
              tick={{ fontSize: 11 }}
              tickFormatter={(value: number) => `${Math.round(value * 100)}%`}
              label={{ value: "confidence", angle: -90, position: "insideLeft", fontSize: 11 }}
            />
            <Tooltip
              formatter={(value, name) => [
                typeof value === "number" ? `${Math.round(value * 100)}%` : String(value ?? ""),
                String(name ?? ""),
              ]}
              labelFormatter={(label) => `t+${String(label)}s`}
            />
            <Legend verticalAlign="top" height={28} />
            {labels.map((label) => (
              <Line
                key={label}
                type="monotone"
                dataKey={label}
                stroke={LABEL_COLOURS[label] ?? "#64748b"}
                strokeWidth={2}
                dot={{ r: 3 }}
                connectNulls
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>

      <p className="mt-3 max-w-prose text-xs leading-relaxed text-zinc-500 dark:text-zinc-400">
        This confidence <em>is</em> the leakage measurement. A well-padded tunnel would leave these
        lines near the 1-in-7 chance level, and that uncertainty would be a good security outcome.
      </p>
    </div>
  );
}
