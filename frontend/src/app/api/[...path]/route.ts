/**
 * Proxy to the FastAPI backend. Step 7.2, LLD section 11.2.
 *
 * The browser never calls the API directly -- it calls this route, which
 * forwards to `API_BASE_URL`. That keeps the backend off the public network in
 * a compose deployment and gives one place to add auth later.
 *
 * SSE passthrough is the delicate part. The upstream body is handed back as a
 * `ReadableStream` untouched, with `runtime = "nodejs"` and the caching and
 * buffering headers a proxy needs to see, because anything that buffers turns
 * a live progress bar into a jump from 0 to 100 at the end.
 */

import type { NextRequest } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
// On Vercel, this route's own duration bounds how long the /runs/{id}/events
// SSE passthrough can stay open before the platform cuts the function off
// mid-stream. Raise per plan: Hobby caps at 60s regardless of this value: Pro
// or higher is required for a real analysis to run to completion.
export const maxDuration = 300;

const API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:8000";

/** Hop-by-hop headers must not be forwarded (RFC 9110 section 7.6.1). */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "content-length",
  "host",
]);

function forwardHeaders(source: Headers): Headers {
  const headers = new Headers();
  source.forEach((value, key) => {
    if (!HOP_BY_HOP.has(key.toLowerCase())) headers.set(key, value);
  });
  return headers;
}

async function proxy(request: NextRequest, segments: string[]): Promise<Response> {
  const search = request.nextUrl.search;
  const target = `${API_BASE_URL}/api/v1/${segments.join("/")}${search}`;

  const upstream = await fetch(target, {
    method: request.method,
    headers: forwardHeaders(request.headers),
    body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    // Required by undici whenever a stream is used as a request body.
    duplex: "half",
    redirect: "manual",
    cache: "no-store",
  } as RequestInit & { duplex: "half" });

  const headers = forwardHeaders(upstream.headers);
  if (upstream.headers.get("content-type")?.includes("text/event-stream")) {
    headers.set("cache-control", "no-cache, no-transform");
    headers.set("x-accel-buffering", "no");
  }

  return new Response(upstream.body, { status: upstream.status, headers });
}

export async function GET(request: NextRequest, ctx: RouteContext<"/api/[...path]">) {
  const { path } = await ctx.params;
  return proxy(request, path);
}

export async function POST(request: NextRequest, ctx: RouteContext<"/api/[...path]">) {
  const { path } = await ctx.params;
  return proxy(request, path);
}

export async function DELETE(request: NextRequest, ctx: RouteContext<"/api/[...path]">) {
  const { path } = await ctx.params;
  return proxy(request, path);
}
