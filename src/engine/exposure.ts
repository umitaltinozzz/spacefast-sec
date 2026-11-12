import type {
  LivePathProbe,
  LiveProbeReport,
  SecurityHeaderAudit,
  Severity,
} from "../types.js";

export interface ProbeOptions {
  fetchImpl?: typeof fetch;
  /** Per-request timeout (default 8000 ms). */
  timeoutMs?: number;
  /** Host suffixes that may be probed without DNS checks (default: space.fast, drop.fast). */
  allowedHostSuffixes?: string[];
  /** Allow custom domains (outside the suffix allowlist). Their DNS answers are checked for private IPs. */
  allowCustomDomains?: boolean;
  /** DNS resolver override (tests). Default: Cloudflare DNS-over-HTTPS. */
  resolveDns?: (host: string) => Promise<string[]>;
}

export const DEFAULT_ALLOWED_SUFFIXES = ["space.fast", "drop.fast"];
const USER_AGENT = "Spacefast-Sec-Auditor/0.2";
const MAX_REDIRECTS = 3;

interface ProbeTarget {
  path: string;
  severity: Severity;
  description: string;
  /**
   * Verifies that a 200 OK response is genuinely the exposed sensitive file and NOT
   * a Single-Page Application (SPA) catch-all `index.html` fallback
   * (Trail of Bits `fp-check` anti-false-positive gate).
   */
  verifyContent: (body: string, contentType: string) => boolean;
}

const looksLikeHtml = (body: string, contentType: string) =>
  contentType.includes("text/html") || /^\s*<(!doctype html|html|head|body)/i.test(body);

const PROBE_TARGETS: ProbeTarget[] = [
  {
    path: "/.env",
    severity: "critical",
    description: "Environment variable file (/.env) publicly downloadable over HTTPS",
    verifyContent: (body, ct) => !looksLikeHtml(body, ct) && /^[A-Z_][A-Z0-9_]*\s*=/m.test(body),
  },
  {
    path: "/.env.local",
    severity: "critical",
    description: "Local environment variable file (/.env.local) publicly downloadable over HTTPS",
    verifyContent: (body, ct) => !looksLikeHtml(body, ct) && /^[A-Z_][A-Z0-9_]*\s*=/m.test(body),
  },
  {
    path: "/.env.production",
    severity: "critical",
    description: "Production environment file (/.env.production) publicly downloadable over HTTPS",
    verifyContent: (body, ct) => !looksLikeHtml(body, ct) && /^[A-Z_][A-Z0-9_]*\s*=/m.test(body),
  },
  {
    path: "/.git/HEAD",
    severity: "critical",
    description: "Git repository metadata (/.git/HEAD) publicly exposed over HTTPS",
    verifyContent: (body) => /^ref:\s+refs\/heads\//m.test(body.trim()) || /^[0-9a-f]{40}$/i.test(body.trim()),
  },
  {
    path: "/package.json",
    severity: "medium",
    description: "Raw package.json manifest publicly exposed on live Space URL",
    verifyContent: (body, ct) => {
      if (looksLikeHtml(body, ct)) return false;
      try {
        const parsed = JSON.parse(body) as Record<string, unknown>;
        return typeof parsed === "object" && parsed !== null && ("dependencies" in parsed || "name" in parsed);
      } catch {
        return false;
      }
    },
  },
  {
    path: "/package-lock.json",
    severity: "medium",
    description: "Raw package-lock.json publicly exposed on live Space URL (reveals exact dependency tree to attackers)",
    verifyContent: (body, ct) => {
      if (looksLikeHtml(body, ct)) return false;
      try {
        const parsed = JSON.parse(body) as Record<string, unknown>;
        return typeof parsed === "object" && parsed !== null && ("lockfileVersion" in parsed || "packages" in parsed);
      } catch {
        return false;
      }
    },
  },
];

// ---------------------------------------------------------------------------
// SSRF guard
// ---------------------------------------------------------------------------

function parseIpv4(host: string): number[] | null {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((n) => n >= 0 && n <= 255) ? parts : null;
}

function isPrivateIpv4(p: number[]): boolean {
  const [a = 0, b = 0, c = 0] = p;
  return (
    a === 0 || // 0.0.0.0/8
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224 // multicast + reserved + broadcast
  );
}

function expandIpv6(ip: string): number[] | null {
  let addr = ip.toLowerCase();
  // Embedded IPv4 tail (::ffff:1.2.3.4)
  const v4Tail = addr.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Tail?.[1]) {
    const v4 = parseIpv4(v4Tail[1]);
    if (!v4) return null;
    addr = addr.slice(0, -v4Tail[1].length) + `${((v4[0]! << 8) | v4[1]!).toString(16)}:${((v4[2]! << 8) | v4[3]!).toString(16)}`;
  }
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0) return null;
  const groups = [...head, ...Array(fill).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => Number.parseInt(g, 16));
  return nums.every((n) => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? nums : null;
}

export function isPrivateIp(ip: string): boolean {
  const clean = ip.replace(/^\[|\]$/g, "");
  const v4 = parseIpv4(clean);
  if (v4) return isPrivateIpv4(v4);
  const g = expandIpv6(clean);
  if (!g) return true; // unparseable -> treat as unsafe
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = g;
  if (g.every((x) => x === 0)) return true; // ::
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 1) return true; // ::1
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && (g5 === 0xffff || g5 === 0)) {
    return isPrivateIpv4([g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff]); // v4-mapped / v4-compatible
  }
  if (g0 === 0x64 && g1 === 0xff9b) return isPrivateIpv4([g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff]); // NAT64
  if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA
  if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g0 & 0xff00) === 0xff00) return true; // multicast
  if (g0 === 0x2001 && g1 === 0x0db8) return true; // documentation
  if (g0 === 0x2002) return true; // 6to4 can embed private v4
  return false;
}

/**
 * Validates and normalizes a live Space URL, blocking SSRF attempts.
 *
 * - https only, default port only, no embedded credentials
 * - IP literals are always refused (a Space is always addressed by hostname)
 * - loopback / internal / single-label hostnames refused (trailing dot normalized)
 * - by default only `*.space.fast` / `*.drop.fast` are allowed; custom domains require
 *   `allowCustomDomains` and are additionally DNS-checked in `probeLiveSpace`.
 */
export function validateSafeProbeUrl(rawUrl: string, options: ProbeOptions = {}): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid Space URL: ${rawUrl}`);
  }

  if (parsed.protocol !== "https:") {
    throw new Error(`Only https:// Space URLs are allowed for live probing (received ${parsed.protocol})`);
  }
  if (parsed.username || parsed.password) {
    throw new Error("Space URL must not contain embedded credentials");
  }
  if (parsed.port && parsed.port !== "443") {
    throw new Error(`Only the default HTTPS port is allowed (received :${parsed.port})`);
  }

  const host = parsed.hostname.toLowerCase().replace(/\.+$/, "");
  const isIpLiteral = host.startsWith("[") || parseIpv4(host) !== null || /^[0-9.]+$/.test(host) || /^0x/i.test(host);
  if (isIpLiteral) {
    throw new Error(`Refusing to probe an IP literal (${host}); use the Space hostname`);
  }
  if (
    !host.includes(".") ||
    host === "localhost" ||
    /\.(localhost|local|internal|lan|home\.arpa|intranet|corp)$/.test(host)
  ) {
    throw new Error(`Refusing to probe private/loopback host: ${host}`);
  }

  const suffixes = options.allowedHostSuffixes ?? DEFAULT_ALLOWED_SUFFIXES;
  const allowlisted = suffixes.some((s) => host === s || host.endsWith(`.${s}`));
  if (!allowlisted && !options.allowCustomDomains) {
    throw new Error(
      `Host ${host} is not a Spacefast host (${suffixes.map((s) => `*.${s}`).join(", ")}). Custom domains are disabled on this server.`,
    );
  }

  parsed.hostname = host;
  return parsed;
}

function isAllowlisted(host: string, options: ProbeOptions): boolean {
  const suffixes = options.allowedHostSuffixes ?? DEFAULT_ALLOWED_SUFFIXES;
  return suffixes.some((s) => host === s || host.endsWith(`.${s}`));
}

async function dohResolve(fetchFn: typeof fetch, host: string, timeoutMs: number): Promise<string[]> {
  const out: string[] = [];
  for (const type of ["A", "AAAA"]) {
    const res = await fetchWithTimeout(
      fetchFn,
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`,
      { headers: { accept: "application/dns-json" } },
      timeoutMs,
    );
    if (!res.ok) throw new Error(`DNS lookup failed for ${host} (${res.status})`);
    const data = (await res.json()) as { Answer?: { type: number; data: string }[] };
    for (const ans of data.Answer ?? []) {
      if (ans.type === 1 || ans.type === 28) out.push(ans.data);
    }
  }
  return out;
}

/** Custom domains: refuse when any A/AAAA answer is private (DNS-rebinding style targets). */
async function assertPublicDns(url: URL, fetchFn: typeof fetch, options: ProbeOptions, timeoutMs: number) {
  if (isAllowlisted(url.hostname, options)) return;
  const resolver = options.resolveDns ?? ((h: string) => dohResolve(fetchFn, h, timeoutMs));
  const ips = await resolver(url.hostname);
  if (ips.length === 0) throw new Error(`Host ${url.hostname} does not resolve`);
  const bad = ips.find((ip) => isPrivateIp(ip));
  if (bad) throw new Error(`Refusing to probe ${url.hostname}: resolves to private address ${bad}`);
}

async function fetchWithTimeout(
  fetchFn: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchFn(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function readLimited(res: Response, maxBytes = 256 * 1024): Promise<string> {
  const text = await res.text();
  return text.length > maxBytes ? text.slice(0, maxBytes) : text;
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

/**
 * Probes a live `https://<name>.space.fast` deployment for:
 * 1. Exposed sensitive static files with strict SPA-fallback false-positive filtering.
 * 2. Referenced JavaScript source maps (*.js.map).
 * 3. Missing HTTP security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).
 *
 * Fail-closed: any inconclusive probe (timeout, 429, 5xx, network error) is listed in
 * `unverifiedPaths` and the overall status becomes `needs_validation`, never `clean`.
 */
export async function probeLiveSpace(
  rawSpaceUrl: string,
  options: ProbeOptions = {},
): Promise<LiveProbeReport> {
  const fetchFn = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 8000;
  let current = validateSafeProbeUrl(rawSpaceUrl, options);
  const init: RequestInit = { method: "GET", redirect: "manual", headers: { "User-Agent": USER_AGENT } };

  const exposedPaths: LivePathProbe[] = [];
  const unverifiedPaths: LiveProbeReport["unverifiedPaths"] = [];
  const headersList: SecurityHeaderAudit[] = [];

  const unreachable = (reason: string): LiveProbeReport => ({
    targetUrl: current.origin,
    reachable: false,
    exposedPaths: [],
    unverifiedPaths: [{ path: "/", status: null, reason }],
    headers: [],
    overallStatus: "needs_validation",
  });

  // Root request with manually validated redirects (every hop goes through the SSRF guard).
  let rootRes: Response | null = null;
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      await assertPublicDns(current, fetchFn, options, timeoutMs);
      const target = hop === 0 || current.pathname === "/" ? current.origin : current.href;
      const res = await fetchWithTimeout(fetchFn, target, init, timeoutMs);
      const location = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && location) {
        if (hop === MAX_REDIRECTS) return unreachable(`Too many redirects (> ${MAX_REDIRECTS})`);
        current = validateSafeProbeUrl(new URL(location, current).toString(), options);
        continue;
      }
      rootRes = res;
      break;
    }
  } catch (err) {
    return unreachable(err instanceof Error ? err.message : String(err));
  }
  if (!rootRes) return unreachable("No response");
  if (rootRes.status >= 500 || rootRes.status === 429) {
    return unreachable(`Root responded with HTTP ${rootRes.status}`);
  }

  const origin = current.origin;
  const rootHtml = await readLimited(rootRes);
  const headers = rootRes.headers;

  const csp = headers.get("content-security-policy");
  headersList.push({
    header: "Content-Security-Policy",
    present: Boolean(csp),
    value: csp,
    status: csp ? (/unsafe-inline|unsafe-eval/.test(csp) ? "misconfigured" : "ok") : "missing",
    recommendation: csp
      ? "Tighten Content-Security-Policy by removing 'unsafe-inline'/'unsafe-eval' and restricting script-src to trusted origins."
      : "Configure a Content-Security-Policy header or <meta http-equiv=\"Content-Security-Policy\"> tag to mitigate XSS.",
  });
  const hsts = headers.get("strict-transport-security");
  headersList.push({
    header: "Strict-Transport-Security",
    present: Boolean(hsts),
    value: hsts,
    status: hsts ? (/max-age=\s*0\b/i.test(hsts) ? "misconfigured" : "ok") : "missing",
    recommendation: "Enable Strict-Transport-Security (max-age=31536000; includeSubDomains) to enforce HTTPS.",
  });
  const xcto = headers.get("x-content-type-options");
  headersList.push({
    header: "X-Content-Type-Options",
    present: Boolean(xcto),
    value: xcto,
    status: xcto?.toLowerCase().trim() === "nosniff" ? "ok" : xcto ? "misconfigured" : "missing",
    recommendation: "Set X-Content-Type-Options: nosniff to prevent MIME-sniffing attacks.",
  });
  const xfo = headers.get("x-frame-options");
  const hasFrameAncestors = csp?.toLowerCase().includes("frame-ancestors") ?? false;
  headersList.push({
    header: "X-Frame-Options",
    present: Boolean(xfo || hasFrameAncestors),
    value: xfo,
    status: xfo || hasFrameAncestors ? "ok" : "missing",
    recommendation: "Set X-Frame-Options: DENY (or CSP frame-ancestors 'none') to prevent clickjacking.",
  });

  const probePath = async (
    path: string,
    onOk: (body: string, contentType: string) => LivePathProbe | null,
  ) => {
    try {
      const res = await fetchWithTimeout(fetchFn, `${origin}${path}`, init, timeoutMs);
      if (res.status === 200) {
        const contentType = (res.headers.get("content-type") ?? "").toLowerCase();
        const found = onOk(await readLimited(res), contentType);
        if (found) exposedPaths.push(found);
        return;
      }
      // Definitive "not downloadable": not found, gone, auth/forbidden, redirected away.
      if ([401, 403, 404, 410].includes(res.status) || (res.status >= 300 && res.status < 400)) return;
      unverifiedPaths.push({ path, status: res.status, reason: `Inconclusive HTTP ${res.status}` });
    } catch (err) {
      unverifiedPaths.push({
        path,
        status: null,
        reason: err instanceof Error && err.name === "AbortError" ? `Timeout after ${timeoutMs} ms` : "Network error",
      });
    }
  };

  for (const target of PROBE_TARGETS) {
    await probePath(target.path, (body, ct) =>
      target.verifyContent(body, ct)
        ? {
            path: target.path,
            status: 200,
            exposed: true,
            severity: target.severity,
            evidence: target.path.startsWith("/.env")
              ? `${target.description} (key=value lines verified; values redacted)`
              : `${target.description}: ${body.slice(0, 120).replace(/\s+/g, " ")}`,
          }
        : null,
    );
  }

  // Same-origin script source maps
  const scriptMatches = [...rootHtml.matchAll(/<script\b[^>]*\bsrc=["']([^"'?#]+\.m?js)(?:[?#][^"']*)?["']/gi)];
  for (const match of scriptMatches.slice(0, 5)) {
    const src = match[1];
    if (!src) continue;
    let scriptUrl: URL;
    try {
      scriptUrl = new URL(src, current);
    } catch {
      continue;
    }
    if (scriptUrl.origin !== origin) continue;
    const mapPath = `${scriptUrl.pathname}.map`;
    await probePath(mapPath, (body) =>
      body.includes('"version"') && body.includes('"sources"')
        ? {
            path: mapPath,
            status: 200,
            exposed: true,
            severity: "low",
            evidence: `Source map JSON ("version", "sources") exposed at ${mapPath}`,
          }
        : null,
    );
  }

  const overallStatus: LiveProbeReport["overallStatus"] =
    // Only critical/high exposures (/.env, /.git) earn critical_exposure; a public manifest or
    // source map is real but lower impact, so it is reported as hardening.
    exposedPaths.some((p) => p.severity === "critical" || p.severity === "high")
      ? "critical_exposure"
      : unverifiedPaths.length > 0
        ? "needs_validation"
        : exposedPaths.length > 0 || headersList.some((h) => h.status !== "ok")
          ? "needs_hardening"
          : "clean";

  return {
    targetUrl: origin,
    reachable: true,
    exposedPaths,
    unverifiedPaths,
    headers: headersList,
    overallStatus,
  };
}
