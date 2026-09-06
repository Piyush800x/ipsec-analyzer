"use client";

/**
 * Drag-and-drop capture upload with a real progress bar. Step 7.5.
 *
 * `XMLHttpRequest` rather than `fetch`, deliberately: `fetch` has no upload
 * progress event, and a 2 GB PCAP uploading behind a spinner that never moves
 * is indistinguishable from a hang (LLD section 11.2 makes the same call).
 */

import { useCallback, useRef, useState } from "react";
import { useRouter } from "next/navigation";

type Status = "idle" | "uploading" | "done" | "error";

export function UploadWidget() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<Status>("idle");
  const [percent, setPercent] = useState(0);
  const [message, setMessage] = useState<string>("");
  const [dragging, setDragging] = useState(false);

  const upload = useCallback(
    (file: File) => {
      setStatus("uploading");
      setPercent(0);
      setMessage(file.name);

      const body = new FormData();
      body.append("file", file);

      const request = new XMLHttpRequest();
      request.open("POST", "/api/captures");

      request.upload.addEventListener("progress", (event) => {
        if (event.lengthComputable) {
          setPercent(Math.round((event.loaded / event.total) * 100));
        }
      });

      request.addEventListener("load", () => {
        if (request.status >= 200 && request.status < 300) {
          setStatus("done");
          setPercent(100);
          router.refresh();
        } else {
          setStatus("error");
          try {
            // RFC 9457 Problem Details -- `detail` is the human-readable part.
            setMessage(JSON.parse(request.responseText).detail ?? "Upload failed");
          } catch {
            setMessage(`Upload failed (HTTP ${request.status})`);
          }
        }
      });

      request.addEventListener("error", () => {
        setStatus("error");
        setMessage("Upload failed: the API could not be reached");
      });

      request.send(body);
    },
    [router],
  );

  return (
    <div
      onDragOver={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        const file = event.dataTransfer.files?.[0];
        if (file) upload(file);
      }}
      className={`rounded-lg border-2 border-dashed p-8 text-center transition-colors ${
        dragging
          ? "border-sky-500 bg-sky-50 dark:bg-sky-950/40"
          : "border-zinc-300 dark:border-zinc-700"
      }`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
        className="hidden"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) upload(file);
        }}
      />

      <p className="text-sm text-zinc-600 dark:text-zinc-400">
        Drop a <code className="font-mono">.pcap</code> or{" "}
        <code className="font-mono">.pcapng</code> here, or{" "}
        <button
          type="button"
          className="font-medium text-sky-700 underline underline-offset-2 dark:text-sky-400"
          onClick={() => inputRef.current?.click()}
        >
          choose a file
        </button>
        .
      </p>

      {status === "uploading" && (
        <div className="mx-auto mt-4 max-w-sm">
          <div className="h-2 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800">
            <div
              className="h-full rounded-full bg-sky-600 transition-[width]"
              style={{ width: `${percent}%` }}
            />
          </div>
          <p className="mt-2 text-xs tabular-nums text-zinc-500 dark:text-zinc-400">
            {message} — {percent}%
          </p>
        </div>
      )}

      {status === "done" && (
        <p className="mt-3 text-sm text-emerald-700 dark:text-emerald-400">
          Uploaded {message}. It is in the list below.
        </p>
      )}

      {status === "error" && (
        <p className="mx-auto mt-3 max-w-md text-sm text-red-700 dark:text-red-400">{message}</p>
      )}
    </div>
  );
}
