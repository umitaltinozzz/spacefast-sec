/**
 * Node.js entry point (Railway / any container host).
 *
 * Reuses the exact same request handler as the Cloudflare Worker (`src/index.ts`), so both
 * deployments behave identically. Differences handled here:
 * - env comes from process.env
 * - rate limiting uses an in-memory fixed window instead of the Workers binding
 * - the trusted client IP is the RIGHTMOST X-Forwarded-For value (appended by Railway's proxy;
 *   left-hand values, X-Real-IP and CF-Connecting-IP can be forged by the client)
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import worker, { type Env } from "./index.js";

const PORT = Number(process.env.PORT ?? 3000);
const RATE_LIMIT = Number(process.env.RATE_LIMIT_PER_MINUTE ?? 30);
const WINDOW_MS = 60_000;
const MAX_BODY_BYTES = 30 * 1024 * 1024;

function createMemoryRateLimiter(limit: number, windowMs: number): NonNullable<Env["RATE_LIMITER"]> {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  setInterval(() => {
    const now = Date.now();
    for (const [key, b] of buckets) if (b.resetAt <= now) buckets.delete(key);
  }, windowMs).unref();
  return {
    async limit({ key }) {
      const now = Date.now();
      const bucket = buckets.get(key);
      if (!bucket || bucket.resetAt <= now) {
        buckets.set(key, { count: 1, resetAt: now + windowMs });
        return { success: true };
      }
      bucket.count += 1;
      return { success: bucket.count <= limit };
    },
  };
}

export function rightmostForwardedFor(header: string | null): string | null {
  if (!header) return null;
  const parts = header.split(",").map((p) => p.trim()).filter(Boolean);
  return parts.at(-1) ?? null;
}

const env: Env = {
  CVE_NOW_URL: process.env.CVE_NOW_URL,
  OSV_BATCH_URL: process.env.OSV_BATCH_URL,
  OSV_VULN_URL: process.env.OSV_VULN_URL,
  CISA_KEV_URL: process.env.CISA_KEV_URL,
  FIRST_EPSS_URL: process.env.FIRST_EPSS_URL,
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS ?? "https://claude.ai,https://chatgpt.com",
  PROBE_ALLOWED_SUFFIXES: process.env.PROBE_ALLOWED_SUFFIXES,
  PROBE_ALLOW_CUSTOM_DOMAINS: process.env.PROBE_ALLOW_CUSTOM_DOMAINS,
  RATE_LIMITER: RATE_LIMIT > 0 ? createMemoryRateLimiter(RATE_LIMIT, WINDOW_MS) : undefined,
  GET_CLIENT_IP: (request) => rightmostForwardedFor(request.headers.get("x-forwarded-for")),
};

function toRequest(req: IncomingMessage): Request {
  const host = req.headers.host ?? `localhost:${PORT}`;
  const url = new URL(req.url ?? "/", `http://${host}`);
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) value.forEach((v) => headers.append(name, v));
    else headers.set(name, value);
  }
  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  return new Request(url, {
    method: req.method,
    headers,
    body: hasBody ? (Readable.toWeb(req) as ReadableStream) : undefined,
    // Required by Node's fetch implementation when streaming a request body.
    ...(hasBody ? { duplex: "half" } : {}),
  } as RequestInit);
}

async function send(res: ServerResponse, response: Response) {
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });
  res.writeHead(response.status, headers);
  if (response.body) {
    res.end(Buffer.from(await response.arrayBuffer()));
  } else {
    res.end();
  }
}

const server = createServer(async (req, res) => {
  try {
    const declared = Number(req.headers["content-length"] ?? "0");
    if (declared > MAX_BODY_BYTES) {
      res.writeHead(413, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Request body too large" } }));
      req.destroy();
      return;
    }
    const response = await worker.fetch(toRequest(req), env);
    await send(res, response);
  } catch (err) {
    console.error("request failed", err);
    if (!res.headersSent) res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32603, message: "Internal error" } }));
  }
});

// Long tool calls (OSV + KEV + EPSS + cve.now) can take a while; keep sockets open.
server.requestTimeout = 120_000;
server.headersTimeout = 30_000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`spacefast-sec-mcp listening on :${PORT} (rate limit ${RATE_LIMIT}/min per client IP)`);
});

const shutdown = () => server.close(() => process.exit(0));
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
