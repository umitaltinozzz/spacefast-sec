import { handleMcpRequest, MCP_TOOLS, type ServerOptions } from "./mcp/server.js";
import { DEFAULT_ALLOWED_SUFFIXES } from "./engine/exposure.js";

export interface Env {
  CVE_NOW_URL?: string;
  CVE_NOW_FEED_URL?: string;
  OSV_BATCH_URL?: string;
  OSV_VULN_URL?: string;
  CISA_KEV_URL?: string;
  FIRST_EPSS_URL?: string;
  /** Comma-separated browser origins allowed to call /mcp (non-browser MCP clients send no Origin). */
  ALLOWED_ORIGINS?: string;
  /** Comma-separated host suffixes the live probe may target (default: space.fast,drop.fast). */
  PROBE_ALLOWED_SUFFIXES?: string;
  /** "true" to allow probing custom domains (DNS-checked for private IPs). */
  PROBE_ALLOW_CUSTOM_DOMAINS?: string;
  /** Optional Workers Rate Limiting binding (see wrangler.toml), or the in-memory limiter on Node. */
  RATE_LIMITER?: { limit(options: { key: string }): Promise<{ success: boolean }> };
  /**
   * Host-specific trusted client IP (Node/Railway adapter). Workers falls back to CF-Connecting-IP,
   * which Cloudflare sets and clients cannot spoof there.
   */
  GET_CLIENT_IP?: (request: Request) => string | null;
}

const MAX_BODY_BYTES = 30 * 1024 * 1024;

function splitList(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function corsHeaders(origin: string | null, allowed: string[]): Record<string, string> {
  if (!origin || !allowed.includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Mcp-Session-Id, Mcp-Protocol-Version",
    Vary: "Origin",
  };
}

function json(body: unknown, status: number, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...extra, "Content-Type": "application/json" },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");
    const allowedOrigins = splitList(env.ALLOWED_ORIGINS);
    const cors = corsHeaders(origin, allowedOrigins);

    // Streamable HTTP spec: servers MUST validate Origin to prevent DNS-rebinding attacks.
    if (origin && !allowedOrigins.includes(origin)) {
      return json({ error: "Forbidden origin" }, 403);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    if (request.method === "GET" && url.pathname === "/health") {
      return json(
        { status: "ok", service: "spacefast-sec-mcp", version: "0.2.0", tools: MCP_TOOLS.map((t) => t.name) },
        200,
        cors,
      );
    }

    if (request.method === "GET" && url.pathname === "/") {
      return json(
        {
          name: "spacefast-sec-mcp",
          version: "0.2.0",
          protocol: "Streamable HTTP MCP (JSON-RPC 2.0 over POST /mcp, JSON responses, no SSE stream)",
          companionMcp: "https://mcp.spacefast.com",
          tools: MCP_TOOLS.map((t) => ({ name: t.name, description: t.description })),
        },
        200,
        cors,
      );
    }

    // This server never pushes server-initiated messages, so the optional GET SSE stream is not offered.
    if ((request.method === "GET" || request.method === "DELETE") && url.pathname === "/mcp") {
      return new Response(null, { status: 405, headers: { ...cors, Allow: "POST" } });
    }

    if (request.method === "POST" && (url.pathname === "/mcp" || url.pathname === "/")) {
      if (env.RATE_LIMITER) {
        const key = env.GET_CLIENT_IP?.(request) ?? request.headers.get("CF-Connecting-IP") ?? "unknown";
        const { success } = await env.RATE_LIMITER.limit({ key });
        if (!success) {
          return json({ jsonrpc: "2.0", id: null, error: { code: -32000, message: "Rate limit exceeded" } }, 429, {
            ...cors,
            "Retry-After": "60",
          });
        }
      }

      const declaredLength = Number(request.headers.get("Content-Length") ?? "0");
      if (declaredLength > MAX_BODY_BYTES) {
        return json({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Request body too large" } }, 413, cors);
      }

      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error: invalid JSON body" } }, 400, cors);
      }

      const options: ServerOptions = {
        cveNowUrl: env.CVE_NOW_URL ?? env.CVE_NOW_FEED_URL,
        osvBatchUrl: env.OSV_BATCH_URL,
        osvVulnUrl: env.OSV_VULN_URL,
        epssUrl: env.FIRST_EPSS_URL,
        cisaKevUrl: env.CISA_KEV_URL,
        probe: {
          allowedHostSuffixes: splitList(env.PROBE_ALLOWED_SUFFIXES).length
            ? splitList(env.PROBE_ALLOWED_SUFFIXES)
            : DEFAULT_ALLOWED_SUFFIXES,
          allowCustomDomains: env.PROBE_ALLOW_CUSTOM_DOMAINS === "true",
        },
      };

      if (Array.isArray(body)) {
        if (body.length === 0) {
          return json({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request: empty batch" } }, 400, cors);
        }
        const responses = (await Promise.all(body.map((req) => handleMcpRequest(req, options)))).filter(
          (r) => r !== null,
        );
        if (responses.length === 0) return new Response(null, { status: 202, headers: cors });
        return json(responses, 200, cors);
      }

      const rpcResponse = await handleMcpRequest(body, options);
      if (rpcResponse === null) {
        return new Response(null, { status: 202, headers: cors });
      }
      return json(rpcResponse, 200, cors);
    }

    return json({ error: "Not Found" }, 404, cors);
  },
};
