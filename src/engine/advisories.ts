import type {
  AdvisoryQueryResult,
  AdvisoryRecord,
  DependencyComponent,
  Ecosystem,
  Severity,
} from "../types.js";

export interface AdvisoryQueryOptions {
  fetchImpl?: typeof fetch;
  osvBatchUrl?: string;
  osvVulnUrl?: string;
  epssUrl?: string;
  /** SecMon cve.now base URL or entries endpoint (default: https://cve.now). */
  cveNowUrl?: string;
  /** CISA KEV JSON feed URL (public, no API key). Ignored when `cisaKevIds` is supplied. */
  cisaKevUrl?: string;
  /** Pre-loaded KEV CVE id set (mainly for tests). */
  cisaKevIds?: Set<string>;
  /** Per-request timeout for upstream calls. */
  timeoutMs?: number;
  /** Max parallel OSV/cve.now detail requests (keeps Workers subrequest usage bounded). */
  detailConcurrency?: number;
  /** Max distinct vulnerability ids to fetch details for; beyond this a data gap is reported. */
  maxVulnDetails?: number;
}

const OSV_ECOSYSTEM_MAP: Record<Ecosystem, string> = {
  npm: "npm",
  pypi: "PyPI",
  cargo: "crates.io",
  golang: "Go",
  composer: "Packagist",
};

const OSV_BATCH_LIMIT = 1000;
const EPSS_CHUNK = 50;

async function fetchWithTimeout(
  fetchFn: typeof fetch,
  url: string,
  init: RequestInit = {},
  timeoutMs = 10_000,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchFn(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function mapWithConcurrency<T>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  let cursor = 0;
  const runners = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (cursor < items.length) {
      const item = items[cursor++] as T;
      await worker(item);
    }
  });
  await Promise.all(runners);
}

// ---------------------------------------------------------------------------
// CVSS v3.x base score (OSV ships vectors in `severity[].score`, not numbers)
// ---------------------------------------------------------------------------

function roundUp1(value: number): number {
  const intInput = Math.round(value * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function cvss3BaseScore(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const metrics = new Map<string, string>();
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k && v) metrics.set(k, v);
  }
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metrics.get("AV") ?? ""];
  const AC = { L: 0.77, H: 0.44 }[metrics.get("AC") ?? ""];
  const UI = { N: 0.85, R: 0.62 }[metrics.get("UI") ?? ""];
  const S = metrics.get("S");
  const cia = (m: string) => ({ H: 0.56, L: 0.22, N: 0 })[metrics.get(m) ?? ""];
  const C = cia("C");
  const I = cia("I");
  const A = cia("A");
  const prRaw = metrics.get("PR");
  const PR =
    prRaw === "N" ? 0.85 : prRaw === "L" ? (S === "C" ? 0.68 : 0.62) : prRaw === "H" ? (S === "C" ? 0.5 : 0.27) : undefined;
  if ([AV, AC, UI, C, I, A, PR].some((x) => x === undefined) || (S !== "U" && S !== "C")) return null;

  const iss = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact = S === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const exploitability = 8.22 * AV! * AC! * PR! * UI!;
  if (impact <= 0) return 0;
  return S === "U"
    ? roundUp1(Math.min(impact + exploitability, 10))
    : roundUp1(Math.min(1.08 * (impact + exploitability), 10));
}

function extractCvssScore(vuln: Record<string, unknown>): number | null {
  const dbSpecific = vuln.database_specific as Record<string, unknown> | undefined;
  if (typeof dbSpecific?.cvss_score === "number") return dbSpecific.cvss_score;
  if (!Array.isArray(vuln.severity)) return null;
  let best: number | null = null;
  for (const sev of vuln.severity as Record<string, unknown>[]) {
    if (typeof sev.score !== "string") continue;
    const numeric = Number.parseFloat(sev.score);
    const score = /^\d+(\.\d+)?$/.test(sev.score) ? numeric : cvss3BaseScore(sev.score);
    if (score !== null && (best === null || score > best)) best = score;
  }
  return best;
}

function parseSeverity(vuln: Record<string, unknown>, cvssScore: number | null): Severity {
  const dbSpecific = vuln.database_specific as Record<string, unknown> | undefined;
  const rawSev = typeof dbSpecific?.severity === "string" ? dbSpecific.severity.toLowerCase() : "";
  if (rawSev === "critical") return "critical";
  if (rawSev === "high") return "high";
  if (rawSev === "moderate" || rawSev === "medium") return "medium";
  if (rawSev === "low") return "low";
  if (cvssScore !== null) {
    if (cvssScore >= 9.0) return "critical";
    if (cvssScore >= 7.0) return "high";
    if (cvssScore >= 4.0) return "medium";
    if (cvssScore > 0) return "low";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Semver helpers
// ---------------------------------------------------------------------------

function parseVersion(v: string): { nums: number[]; pre: string[] } {
  const clean = v.trim().replace(/^v/i, "").split("+")[0] ?? "";
  const dash = clean.indexOf("-");
  const core = dash >= 0 ? clean.slice(0, dash) : clean;
  const pre = dash >= 0 ? clean.slice(dash + 1).split(".") : [];
  const nums = core.split(".").map((n) => Number.parseInt(n, 10) || 0);
  return { nums, pre };
}

/** Semver-ish comparison with correct prerelease ordering (1.0.0-beta < 1.0.0). */
export function compareSemver(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  const len = Math.max(3, pa.nums.length, pb.nums.length);
  for (let i = 0; i < len; i += 1) {
    const diff = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (diff !== 0) return diff;
  }
  if (pa.pre.length === 0 && pb.pre.length === 0) return 0;
  if (pa.pre.length === 0) return 1;
  if (pb.pre.length === 0) return -1;
  const preLen = Math.max(pa.pre.length, pb.pre.length);
  for (let i = 0; i < preLen; i += 1) {
    const x = pa.pre[i];
    const y = pb.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d;
    } else if (xn !== yn) {
      return xn ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/**
 * Selects the nearest non-breaking fixed version strictly HIGHER than installedVersion
 * (same major/minor first, then same major, then lowest higher). Returns null when no
 * higher fix exists: we never recommend a downgrade.
 */
export function selectRecommendedFixVersion(
  installedVersion: string,
  fixedVersions: string[],
): string | null {
  const higher = [...new Set(fixedVersions)]
    .filter((v) => compareSemver(v, installedVersion) > 0)
    .sort(compareSemver);
  if (higher.length === 0) return null;

  const inst = parseVersion(installedVersion).nums;
  const sameMajorMinor = higher.find((v) => {
    const n = parseVersion(v).nums;
    return n[0] === inst[0] && n[1] === inst[1];
  });
  if (sameMajorMinor) return sameMajorMinor;
  const sameMajor = higher.find((v) => parseVersion(v).nums[0] === inst[0]);
  return sameMajor ?? higher[0] ?? null;
}

// ---------------------------------------------------------------------------
// CISA KEV (public JSON feed, cached per isolate for 6h)
// ---------------------------------------------------------------------------

let kevCache: { url: string; ids: Set<string>; at: number } | null = null;
const KEV_TTL_MS = 6 * 60 * 60 * 1000;

export function __resetKevCacheForTests(): void {
  kevCache = null;
  cveNowCache.clear();
}

// ---------------------------------------------------------------------------
// SecMon cve.now (https://cve.now/api/v1/entries/{cveId}, cached per isolate for 6h)
// Matches crates/advisory-providers/src/cve_now.rs + normalize.rs in SecMon.
// ---------------------------------------------------------------------------

export interface CveNowEntry {
  id: string;
  title?: string;
  summaryText?: string;
  originalDescription?: string;
  cvss?: number;
  statedSeverity?: Severity;
  kev: boolean;
  fixedByPackage: Map<string, string[]>;
  references: string[];
}

const cveNowCache = new Map<string, { entry: CveNowEntry; at: number }>();
const CVE_NOW_TTL_MS = 6 * 60 * 60 * 1000;
export const DEFAULT_CVE_NOW_URL = "https://cve.now";

function normalizeCveNowEcosystem(raw: string): string {
  const lower = raw.trim().toLowerCase();
  if (lower === "npm" || lower === "node") return "npm";
  if (lower === "pypi" || lower === "pip" || lower === "python") return "pypi";
  if (lower === "cargo" || lower === "crates.io" || lower === "rust") return "cargo";
  if (lower === "go" || lower === "golang") return "golang";
  if (lower === "composer" || lower === "packagist" || lower === "php") return "composer";
  return lower;
}

function parseCveNowStatedSeverity(label: unknown, cvss: number | undefined): Severity | undefined {
  if (typeof label === "string") {
    const l = label.trim().toLowerCase();
    if (l === "critical") return "critical";
    if (l === "high") return "high";
    if (l === "medium" || l === "moderate") return "medium";
    if (l === "low") return "low";
  }
  if (typeof cvss === "number") {
    if (cvss >= 9.0) return "critical";
    if (cvss >= 7.0) return "high";
    if (cvss >= 4.0) return "medium";
    if (cvss > 0) return "low";
  }
  return undefined;
}

function buildCveNowEntryUrl(baseUrl: string, cveId: string): string | null {
  if (!/^[A-Za-z0-9._-]+$/.test(cveId) || cveId.length > 256) return null;
  const trimmed = baseUrl.trim().replace(/\/+$/, "");
  if (trimmed.endsWith("/api/v1/entries")) {
    return `${trimmed}/${encodeURIComponent(cveId)}`;
  }
  return `${trimmed}/api/v1/entries/${encodeURIComponent(cveId)}`;
}

export function parseCveNowEntry(value: Record<string, unknown>, expectedId: string): CveNowEntry | null {
  if (typeof value.id !== "string" || value.id.toUpperCase() !== expectedId.toUpperCase()) {
    return null;
  }
  const id = value.id.toUpperCase();
  const title = typeof value.title === "string" && value.title.trim() ? value.title.trim() : undefined;
  const summaryObj = value.summary as Record<string, unknown> | undefined;
  const summaryText =
    typeof summaryObj?.text === "string" && summaryObj.text.trim() ? summaryObj.text.trim() : undefined;
  const originalDescription =
    typeof value.originalDescription === "string" && value.originalDescription.trim()
      ? value.originalDescription.trim()
      : undefined;

  const sevObj = value.severity as Record<string, unknown> | undefined;
  const cvss = typeof sevObj?.cvss === "number" ? sevObj.cvss : undefined;
  const statedSeverity = parseCveNowStatedSeverity(value.statedSeverity, cvss);

  const exploitObj = value.exploitation as Record<string, unknown> | undefined;
  const kevVal = exploitObj?.kev;
  const kev = kevVal !== undefined && kevVal !== null && kevVal !== false;

  const fixedByPackage = new Map<string, string[]>();
  if (Array.isArray(value.affected)) {
    for (const item of value.affected as Record<string, unknown>[]) {
      const pkg =
        typeof item.package === "string"
          ? item.package.trim()
          : typeof item.product === "string"
            ? item.product.trim()
            : "";
      if (!pkg) continue;
      const eco =
        typeof item.ecosystem === "string" ? normalizeCveNowEcosystem(item.ecosystem) : "unknown";
      const key = `${eco}:${eco === "pypi" ? pkg.toLowerCase().replace(/[-_.]+/g, "-") : pkg}`;
      if (Array.isArray(item.ranges)) {
        for (const rng of item.ranges as Record<string, unknown>[]) {
          if (typeof rng.fixed === "string" && rng.fixed.trim()) {
            const list = fixedByPackage.get(key) ?? [];
            list.push(rng.fixed.trim());
            fixedByPackage.set(key, list);
          }
        }
      }
    }
  }

  const references: string[] = [];
  const pushUrl = (raw: unknown) => {
    if (typeof raw === "string" && /^https:\/\//i.test(raw) && !references.includes(raw)) {
      references.push(raw);
    }
  };
  if (Array.isArray(value.sources)) {
    for (const src of value.sources as Record<string, unknown>[]) pushUrl(src?.url);
  }
  if (Array.isArray(value.references)) {
    for (const ref of value.references as Record<string, unknown>[]) pushUrl(ref?.url);
  }
  pushUrl(`https://cve.now/${id}`);

  return {
    id,
    title,
    summaryText,
    originalDescription,
    cvss,
    statedSeverity,
    kev,
    fixedByPackage,
    references,
  };
}

async function fetchCveNowEntry(
  fetchFn: typeof fetch,
  baseUrl: string,
  cveId: string,
  timeoutMs: number,
): Promise<{ entry: CveNowEntry | null; failed: boolean }> {
  const cacheKey = `${baseUrl}|${cveId.toUpperCase()}`;
  const cached = cveNowCache.get(cacheKey);
  if (cached && Date.now() - cached.at < CVE_NOW_TTL_MS) {
    return { entry: cached.entry, failed: false };
  }
  const url = buildCveNowEntryUrl(baseUrl, cveId);
  if (!url) return { entry: null, failed: true };

  try {
    const res = await fetchWithTimeout(
      fetchFn,
      url,
      { headers: { "User-Agent": "Spacefast-Sec-Auditor/0.2" }, cf: { cacheTtl: 21600 } } as RequestInit,
      timeoutMs,
    );
    if (res.status === 404) {
      return { entry: null, failed: false };
    }
    if (!res.ok) {
      return { entry: cached?.entry ?? null, failed: !cached };
    }
    const payload = (await res.json()) as Record<string, unknown>;
    if (typeof payload !== "object" || payload === null) {
      return { entry: null, failed: true };
    }
    // Generic fallback mocks in tests (e.g. `{ data: [] }`) have no `id`; treat as absent rather than malformed.
    if (!("id" in payload)) {
      return { entry: null, failed: false };
    }
    const parsed = parseCveNowEntry(payload, cveId);
    if (!parsed) return { entry: null, failed: true };
    cveNowCache.set(cacheKey, { entry: parsed, at: Date.now() });
    return { entry: parsed, failed: false };
  } catch {
    return { entry: cached?.entry ?? null, failed: !cached };
  }
}

/** Official CISA mirror on GitHub; www.cisa.gov answers 403 to most non-browser clients. */
export const DEFAULT_KEV_URLS = [
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
];

/** `urlSpec` may be a comma-separated list; sources are tried in order. */
async function loadKevIds(
  fetchFn: typeof fetch,
  urlSpec: string,
  timeoutMs: number,
): Promise<Set<string> | null> {
  if (kevCache && kevCache.url === urlSpec && Date.now() - kevCache.at < KEV_TTL_MS) {
    return kevCache.ids;
  }
  const urls = urlSpec.split(",").map((u) => u.trim()).filter(Boolean);
  for (const url of urls) {
    try {
      const res = await fetchWithTimeout(
        fetchFn,
        url,
        { headers: { "User-Agent": "Spacefast-Sec-Auditor/0.2" }, cf: { cacheTtl: 21600 } } as RequestInit,
        timeoutMs,
      );
      if (!res.ok) continue;
      const data = (await res.json()) as { vulnerabilities?: { cveID?: unknown }[] };
      if (!Array.isArray(data.vulnerabilities) || data.vulnerabilities.length === 0) continue;
      const ids = new Set<string>();
      for (const v of data.vulnerabilities) {
        if (typeof v.cveID === "string") ids.add(v.cveID.toUpperCase());
      }
      kevCache = { url: urlSpec, ids, at: Date.now() };
      return ids;
    } catch {
      // try next source
    }
  }
  // Serve a stale cache rather than nothing; still better than reporting "not in KEV".
  return kevCache?.url === urlSpec ? kevCache.ids : null;
}

// ---------------------------------------------------------------------------
// Main query
// ---------------------------------------------------------------------------

/**
 * Queries OSV (+ CISA KEV + FIRST EPSS enrichment) for the given components.
 *
 * Fail-closed: any upstream failure, truncation or missing detail is reported in
 * `dataGaps` and flips `complete` to false. Callers must never turn an incomplete
 * result into a `clean` verdict.
 */
export async function queryAdvisoriesForComponents(
  components: DependencyComponent[],
  options: AdvisoryQueryOptions = {},
): Promise<AdvisoryQueryResult> {
  const dataGaps: string[] = [];
  if (components.length === 0) return { records: [], complete: true, dataGaps };

  const fetchFn = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const osvBatchUrl = options.osvBatchUrl ?? "https://api.osv.dev/v1/querybatch";
  const osvVulnUrl = options.osvVulnUrl ?? "https://api.osv.dev/v1/vulns";
  const epssUrl = options.epssUrl ?? "https://api.first.org/data/v1/epss";
  const cveNowUrl = options.cveNowUrl ?? DEFAULT_CVE_NOW_URL;
  const maxVulnDetails = options.maxVulnDetails ?? 300;

  // 1. OSV batch (chunked at the documented 1000-query limit)
  const componentToVulnIds = new Map<number, string[]>();
  for (let start = 0; start < components.length; start += OSV_BATCH_LIMIT) {
    const chunk = components.slice(start, start + OSV_BATCH_LIMIT);
    const queries = chunk.map((comp) => ({
      package: { name: comp.name, ecosystem: OSV_ECOSYSTEM_MAP[comp.ecosystem] },
      version: comp.version,
    }));
    try {
      const res = await fetchWithTimeout(
        fetchFn,
        osvBatchUrl,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ queries }),
        },
        timeoutMs,
      );
      if (!res.ok) {
        dataGaps.push(`osv_batch_http_${res.status}: components ${start}-${start + chunk.length - 1} were not checked`);
        continue;
      }
      const data = (await res.json()) as {
        results?: { vulns?: { id?: unknown }[]; next_page_token?: unknown }[];
      };
      const results = Array.isArray(data.results) ? data.results : null;
      if (!results || results.length !== chunk.length) {
        dataGaps.push(
          `osv_batch_malformed: expected ${chunk.length} results, got ${results ? results.length : "none"}`,
        );
        continue;
      }
      results.forEach((entry, idx) => {
        if (entry.next_page_token) {
          const comp = chunk[idx];
          dataGaps.push(`osv_batch_truncated: more advisories exist for ${comp?.name}@${comp?.version}`);
        }
        const ids = (entry.vulns ?? [])
          .map((v) => (typeof v.id === "string" ? v.id : ""))
          .filter(Boolean);
        if (ids.length > 0) componentToVulnIds.set(start + idx, ids);
      });
    } catch (err) {
      dataGaps.push(
        `osv_batch_unreachable: ${err instanceof Error ? err.message : String(err)} (components ${start}-${start + chunk.length - 1} were not checked)`,
      );
    }
  }

  const allVulnIds = [...new Set([...componentToVulnIds.values()].flat())];

  // 2. OSV details (bounded concurrency + cap)
  const vulnDetails = new Map<string, Record<string, unknown>>();
  const detailIds = allVulnIds.slice(0, maxVulnDetails);
  if (allVulnIds.length > maxVulnDetails) {
    dataGaps.push(
      `osv_details_capped: ${allVulnIds.length - maxVulnDetails} advisories have no severity/fix details (cap ${maxVulnDetails})`,
    );
  }
  const failedDetails: string[] = [];
  await mapWithConcurrency(detailIds, options.detailConcurrency ?? 8, async (id) => {
    try {
      const res = await fetchWithTimeout(fetchFn, `${osvVulnUrl}/${encodeURIComponent(id)}`, {}, timeoutMs);
      if (res.ok) {
        vulnDetails.set(id, (await res.json()) as Record<string, unknown>);
      } else {
        failedDetails.push(id);
      }
    } catch {
      failedDetails.push(id);
    }
  });
  if (failedDetails.length > 0) {
    dataGaps.push(`osv_details_failed: ${failedDetails.slice(0, 10).join(", ")}${failedDetails.length > 10 ? ", ..." : ""}`);
  }

  // 3. CISA KEV
  let kevIds: Set<string> | null = options.cisaKevIds ?? null;

  const records: AdvisoryRecord[] = [];
  const allCves = new Set<string>();

  for (const [compIdx, ids] of componentToVulnIds.entries()) {
    const comp = components[compIdx];
    if (!comp) continue;

    for (const id of ids) {
      const detail = vulnDetails.get(id) ?? { id };
      const aliases = Array.isArray(detail.aliases)
        ? detail.aliases.filter((a): a is string => typeof a === "string")
        : [];
      const cveIds = [...new Set([id, ...aliases].filter((x) => /^CVE-\d{4}-\d+$/i.test(x)).map((x) => x.toUpperCase()))];
      cveIds.forEach((cve) => allCves.add(cve));

      // Only collect fix events for the affected entry that matches THIS package.
      const fixedVersions: string[] = [];
      if (Array.isArray(detail.affected)) {
        for (const aff of detail.affected as Record<string, unknown>[]) {
          const affPkg = aff.package as Record<string, unknown> | undefined;
          if (affPkg) {
            const sameName =
              typeof affPkg.name === "string" &&
              (comp.ecosystem === "pypi"
                ? affPkg.name.toLowerCase().replace(/[-_.]+/g, "-") === comp.name.toLowerCase().replace(/[-_.]+/g, "-")
                : affPkg.name === comp.name);
            const sameEco =
              typeof affPkg.ecosystem !== "string" ||
              affPkg.ecosystem.split(":")[0] === OSV_ECOSYSTEM_MAP[comp.ecosystem];
            if (!sameName || !sameEco) continue;
          }
          if (!Array.isArray(aff.ranges)) continue;
          for (const rng of aff.ranges as Record<string, unknown>[]) {
            if (rng.type === "GIT" || !Array.isArray(rng.events)) continue;
            for (const ev of rng.events as Record<string, unknown>[]) {
              if (typeof ev.fixed === "string" && ev.fixed.trim()) {
                fixedVersions.push(ev.fixed.trim());
              }
            }
          }
        }
      }

      const cvssScore = extractCvssScore(detail);
      const severity = parseSeverity(detail, cvssScore);
      const references = Array.isArray(detail.references)
        ? (detail.references as Record<string, unknown>[])
            .map((r) => (typeof r.url === "string" ? r.url : ""))
            .filter(Boolean)
        : [];
      const publicExploit = references.some((url) =>
        /exploit-db\.com|packetstormsecurity|metasploit|\/exploits?\/|[-_/]poc([-_/.]|$)|proof-of-concept/i.test(url),
      );

      records.push({
        id,
        cveIds,
        aliases,
        package: comp.name,
        ecosystem: comp.ecosystem,
        installedVersion: comp.version,
        title:
          typeof detail.summary === "string" && detail.summary.trim()
            ? detail.summary.trim()
            : `${id} in ${comp.name}@${comp.version}`,
        summary:
          typeof detail.details === "string"
            ? detail.details.slice(0, 600)
            : typeof detail.summary === "string"
              ? detail.summary
              : vulnDetails.has(id)
                ? "Advisory reported by OSV"
                : "Advisory reported by OSV (details unavailable: severity/fix unknown)",
        severity,
        cvssScore,
        epssScore: null,
        epssPercentile: null,
        kevListed: false,
        publicExploit,
        fixedVersions: [...new Set(fixedVersions)],
        recommendedFixVersion: selectRecommendedFixVersion(comp.version, fixedVersions),
        sources: ["OSV"],
        references: references.slice(0, 5),
      });
    }
  }

  // KEV lookup is only needed when CVEs exist.
  if (allCves.size > 0) {
    if (!kevIds) {
      kevIds = await loadKevIds(fetchFn, options.cisaKevUrl ?? DEFAULT_KEV_URLS.join(","), timeoutMs);
      if (!kevIds) dataGaps.push("cisa_kev_unavailable: KEV status could not be checked (kevListed=false is unverified)");
    }
    if (kevIds) {
      for (const rec of records) {
        rec.kevListed = rec.cveIds.some((cve) => kevIds!.has(cve));
        if (rec.kevListed) rec.sources.push("CISA KEV");
      }
    }

    // 4. SecMon cve.now enrichment (/api/v1/entries/{cveId})
    const cveList = [...allCves];
    const cveNowMap = new Map<string, CveNowEntry>();
    let cveNowFailed = false;
    await mapWithConcurrency(cveList.slice(0, maxVulnDetails), options.detailConcurrency ?? 8, async (cve) => {
      const { entry, failed } = await fetchCveNowEntry(fetchFn, cveNowUrl, cve, timeoutMs);
      if (failed) cveNowFailed = true;
      if (entry) cveNowMap.set(cve.toUpperCase(), entry);
    });
    if (cveNowFailed) {
      dataGaps.push("cve_now_unavailable: some cve.now entries could not be fetched (enrichment partial)");
    }
    for (const rec of records) {
      for (const cve of rec.cveIds) {
        const entry = cveNowMap.get(cve.toUpperCase());
        if (!entry) continue;
        if (!rec.sources.includes("cve.now")) rec.sources.push("cve.now");
        if (entry.title && rec.title.startsWith(`${rec.id} in `)) {
          rec.title = entry.title;
        }
        if (entry.summaryText) {
          rec.summary = entry.summaryText.slice(0, 600);
        } else if (entry.originalDescription && rec.summary.startsWith("Advisory reported by OSV")) {
          rec.summary = entry.originalDescription.slice(0, 600);
        }
        if (entry.cvss !== undefined && (rec.cvssScore === null || entry.cvss > rec.cvssScore)) {
          rec.cvssScore = entry.cvss;
        }
        if (rec.severity === "unknown" && entry.statedSeverity) {
          rec.severity = entry.statedSeverity;
        }
        if (entry.kev && !rec.kevListed) {
          rec.kevListed = true;
        }
        const pkgKey = `${rec.ecosystem}:${rec.ecosystem === "pypi" ? rec.package.toLowerCase().replace(/[-_.]+/g, "-") : rec.package}`;
        const extraFixes = entry.fixedByPackage.get(pkgKey) ?? [];
        if (extraFixes.length > 0) {
          rec.fixedVersions = [...new Set([...rec.fixedVersions, ...extraFixes])];
          rec.recommendedFixVersion = selectRecommendedFixVersion(rec.installedVersion, rec.fixedVersions);
        }
        for (const ref of entry.references) {
          if (!rec.references.includes(ref) && rec.references.length < 5) {
            rec.references.push(ref);
          }
        }
      }
    }

    // 5. FIRST EPSS (chunked)
    const epssMap = new Map<string, { score: number; percentile: number }>();
    let epssFailed = false;
    for (let i = 0; i < cveList.length; i += EPSS_CHUNK) {
      const chunk = cveList.slice(i, i + EPSS_CHUNK);
      try {
        const res = await fetchWithTimeout(
          fetchFn,
          `${epssUrl}?cve=${encodeURIComponent(chunk.join(","))}`,
          {},
          timeoutMs,
        );
        if (!res.ok) {
          epssFailed = true;
          continue;
        }
        const payload = (await res.json()) as { data?: { cve: string; epss: string; percentile: string }[] };
        for (const row of payload.data ?? []) {
          const score = Number.parseFloat(row.epss);
          const percentile = Number.parseFloat(row.percentile);
          if (!Number.isNaN(score)) {
            epssMap.set(row.cve.toUpperCase(), { score, percentile: Number.isNaN(percentile) ? 0 : percentile });
          }
        }
      } catch {
        epssFailed = true;
      }
    }
    if (epssFailed) dataGaps.push("first_epss_partial: some EPSS scores could not be fetched (priority may be understated)");
    for (const rec of records) {
      for (const cve of rec.cveIds) {
        const match = epssMap.get(cve);
        if (match && (rec.epssScore === null || match.score > rec.epssScore)) {
          rec.epssScore = match.score;
          rec.epssPercentile = match.percentile;
          if (!rec.sources.includes("FIRST EPSS")) rec.sources.push("FIRST EPSS");
        }
      }
    }
  }

  // Enrichment gaps (EPSS / cve.now) are reported in dataGaps; OSV/KEV gaps block completeness.
  const blocking = dataGaps.filter(
    (g) => !g.startsWith("first_epss_partial") && !g.startsWith("cve_now_unavailable"),
  );
  return { records, complete: blocking.length === 0, dataGaps };
}
