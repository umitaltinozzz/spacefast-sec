import type {
  CodeAndSecretFinding,
  CoverageLedger,
  InventoryReport,
  LiveProbeReport,
  PrioritizedFinding,
  RemediationPlan,
  SpaceFileInput,
} from "../types.js";
import { queryAdvisoriesForComponents, type AdvisoryQueryOptions } from "../engine/advisories.js";
import { scanCodeAndSecrets } from "../engine/codeAndSecrets.js";
import {
  buildCoverageLedger,
  compareSpaceDrift,
  planSpaceRemediation,
} from "../engine/driftAndRemediation.js";
import { probeLiveSpace, type ProbeOptions } from "../engine/exposure.js";
import { parseSpaceInventory } from "../engine/inventory.js";
import { evaluateAndPrioritizeFindings } from "../engine/priority.js";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface FullSpaceAuditReport {
  overallState: "clean" | "needs_validation" | "vulnerable";
  summary: string;
  coverageLedger: CoverageLedger;
  inventory: InventoryReport;
  dependencyFindings: {
    confirmed: PrioritizedFinding[];
    needsValidation: PrioritizedFinding[];
    rejectedFalsePositives: PrioritizedFinding[];
  };
  codeAndSecretFindings: CodeAndSecretFinding[];
  liveProbe?: LiveProbeReport;
  /** True when live security headers are missing/misconfigured (does not by itself make the Space vulnerable). */
  hardeningRecommended: boolean;
  /** Every reason the result is not fully verified. Empty only when `overallState` is `clean`. */
  validationReasons: string[];
  dataGaps: string[];
  remediationPlan: RemediationPlan;
}

export interface ServerOptions extends AdvisoryQueryOptions {
  probe?: ProbeOptions;
}

export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"] as const;
const SERVER_VERSION = "0.2.0";
const MAX_FILES = 5000;
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES = 25 * 1024 * 1024;

export const MCP_TOOLS = [
  {
    name: "scan_space_full",
    description:
      "Runs the complete 6-Phase Spacefast Security Audit (Cloudflare + Trail of Bits + Semgrep + SecMon cve.now). Parses manifests/lockfiles, queries OSV + cve.now + CISA KEV + FIRST EPSS, traces code reachability, filters false positives into confirmed/needs_validation/rejected buckets, scans source code for secrets and fail-open defaults, optionally probes the live https://<name>.space.fast URL, and returns a CoverageLedger + RemediationPlan.",
    inputSchema: {
      type: "object",
      properties: {
        files: {
          type: "array",
          description:
            "Array of files from the Spacefast Space (fetched via Spacefast MCP or local workspace).",
          items: {
            type: "object",
            properties: {
              path: { type: "string", description: "Relative file path (e.g. package.json, src/App.tsx)" },
              content: { type: "string", description: "UTF-8 file content" },
            },
            required: ["path", "content"],
          },
        },
        spaceUrl: {
          type: "string",
          description:
            "Optional live HTTPS URL of the Space (e.g. https://my-app.space.fast) to probe for exposed .env/package.json files and HTTP security headers.",
        },
      },
      required: ["files"],
    },
  },
  {
    name: "audit_dependencies",
    description:
      "Parses Space dependency manifests/lockfiles (package-lock.json, pnpm-lock.yaml, yarn.lock, package.json, requirements.txt, Cargo.lock, go.mod), enriches vulnerabilities with OSV + cve.now + CISA KEV + FIRST EPSS, and computes 0-100 deterministic priority scores with code reachability.",
    inputSchema: {
      type: "object",
      properties: {
        files: {
          type: "array",
          items: {
            type: "object",
            properties: {
              path: { type: "string" },
              content: { type: "string" },
            },
            required: ["path", "content"],
          },
        },
        isLiveSpace: {
          type: "boolean",
          description:
            "Whether the project is deployed on a public *.space.fast URL (adds internet-facing priority boost). Defaults to false.",
        },
      },
      required: ["files"],
    },
  },
  {
    name: "audit_code_and_secrets",
    description:
      "Scans Space source files for hardcoded API keys/tokens (with automatic redaction), VITE_/NEXT_PUBLIC_ client bundle secret leaks, Trail of Bits insecure-defaults (fail-open secret fallbacks, disabled TLS verification), Semgrep OWASP Top 10 SAST patterns (DOM XSS, eval, SQLi), and sensitive exposed files (.env, .git, .pem, .js.map).",
    inputSchema: {
      type: "object",
      properties: {
        files: {
          type: "array",
          items: {
            type: "object",
            properties: {
              path: { type: "string" },
              content: { type: "string" },
            },
            required: ["path", "content"],
          },
        },
      },
      required: ["files"],
    },
  },
  {
    name: "probe_live_space",
    description:
      "Probes a live https://<name>.space.fast deployment for publicly downloadable sensitive files (/.env, /.git/HEAD, /package.json, /package-lock.json, *.js.map) with SPA catch-all false-positive filtering, and audits HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).",
    inputSchema: {
      type: "object",
      properties: {
        spaceUrl: {
          type: "string",
          description: "Live HTTPS URL of the Space (e.g. https://demo.space.fast).",
        },
      },
      required: ["spaceUrl"],
    },
  },
  {
    name: "compare_space_drift",
    description:
      "Compares local workspace files against live Spacefast Space files to detect dependency version drift, missing lockfiles on the Space, or vulnerabilities fixed locally that have not yet been published to the live Space.",
    inputSchema: {
      type: "object",
      properties: {
        localFiles: {
          type: "array",
          items: {
            type: "object",
            properties: {
              path: { type: "string" },
              content: { type: "string" },
            },
            required: ["path", "content"],
          },
        },
        spaceFiles: {
          type: "array",
          items: {
            type: "object",
            properties: {
              path: { type: "string" },
              content: { type: "string" },
            },
            required: ["path", "content"],
          },
        },
      },
      required: ["localFiles", "spaceFiles"],
    },
  },
  {
    name: "plan_space_remediation",
    description:
      "Generates an exact package.json remediation patch, unified diff, and step-by-step Spacefast MCP publish plan for vulnerable dependencies.",
    inputSchema: {
      type: "object",
      properties: {
        files: {
          type: "array",
          items: {
            type: "object",
            properties: {
              path: { type: "string" },
              content: { type: "string" },
            },
            required: ["path", "content"],
          },
        },
      },
      required: ["files"],
    },
  },
] as const;

class ToolInputError extends Error {}

function parseFilesArg(raw: unknown, argName = "files"): SpaceFileInput[] {
  if (!Array.isArray(raw)) {
    throw new ToolInputError(`Expected '${argName}' argument to be an array of { path, content } objects.`);
  }
  if (raw.length > MAX_FILES) {
    throw new ToolInputError(
      `Too many files in '${argName}' (${raw.length} > ${MAX_FILES}). Send manifests, lockfiles and source files only.`,
    );
  }
  let total = 0;
  return raw.map((item, idx) => {
    if (typeof item !== "object" || item === null) {
      throw new ToolInputError(`Invalid file entry at index ${idx}`);
    }
    const obj = item as Record<string, unknown>;
    if (typeof obj.path !== "string" || typeof obj.content !== "string") {
      throw new ToolInputError(`File entry at index ${idx} must have string 'path' and 'content' properties.`);
    }
    if (obj.content.length > MAX_FILE_BYTES) {
      throw new ToolInputError(`File ${obj.path} is larger than ${MAX_FILE_BYTES} bytes; skip binaries/bundles.`);
    }
    total += obj.content.length;
    if (total > MAX_TOTAL_BYTES) {
      throw new ToolInputError(`Total file content exceeds ${MAX_TOTAL_BYTES} bytes; split the audit into smaller calls.`);
    }
    return { path: obj.path, content: obj.content };
  });
}

/**
 * Runs the complete 6-phase Spacefast security audit workflow.
 */
export async function executeFullSpaceAudit(
  files: SpaceFileInput[],
  spaceUrl?: string,
  options: ServerOptions = {},
): Promise<FullSpaceAuditReport> {
  const inventory = parseSpaceInventory(files);
  const advisoryResult = await queryAdvisoriesForComponents(inventory.components, options);
  const prioritized = evaluateAndPrioritizeFindings(advisoryResult.records, {
    isLivePublicSpace: Boolean(spaceUrl),
    files,
    components: inventory.components,
  });

  const confirmed = prioritized.filter((f) => f.verdict === "confirmed");
  const needsValidation = prioritized.filter((f) => f.verdict === "needs_validation");
  const rejectedFalsePositives = prioritized.filter((f) => f.verdict === "rejected");

  const codeAndSecretFindings = scanCodeAndSecrets(files);
  const liveProbe = spaceUrl
    ? await probeLiveSpace(spaceUrl, { fetchImpl: options.fetchImpl, ...options.probe })
    : undefined;

  const remediationPlan = planSpaceRemediation(files, prioritized);
  const coverageLedger = buildCoverageLedger(files, inventory, Boolean(spaceUrl), advisoryResult.dataGaps);

  const hasConfirmedVuln =
    confirmed.length > 0 ||
    codeAndSecretFindings.some((f) => f.verdict === "confirmed") ||
    liveProbe?.overallStatus === "critical_exposure";

  // SecMon Hard Rule #5: never mark safe by default if unpinned or unverified data exists.
  const validationReasons: string[] = [];
  if (needsValidation.length > 0) validationReasons.push(`${needsValidation.length} dependency finding(s) need validation`);
  if (codeAndSecretFindings.some((f) => f.verdict === "needs_validation")) {
    validationReasons.push("code findings need manual validation");
  }
  if (inventory.unpinnedWarnings.length > 0) {
    validationReasons.push(`${inventory.unpinnedWarnings.length} unpinned/unresolvable dependency specifier(s)`);
  }
  for (const eco of inventory.missingLockfileFor) validationReasons.push(`no lockfile for ${eco}`);
  for (const f of inventory.unparsedLockfiles) validationReasons.push(`unparseable dependency file: ${f}`);
  for (const f of inventory.unsupportedManifests) validationReasons.push(`unsupported manifest: ${f}`);
  if (!advisoryResult.complete) validationReasons.push("vulnerability data incomplete (see dataGaps)");
  if (liveProbe?.overallStatus === "needs_validation") {
    validationReasons.push(liveProbe.reachable ? "some live probes were inconclusive" : "live Space URL unreachable");
  }

  const overallState: FullSpaceAuditReport["overallState"] = hasConfirmedVuln
    ? "vulnerable"
    : validationReasons.length > 0
      ? "needs_validation"
      : "clean";
  const hardeningRecommended =
    liveProbe !== undefined && (liveProbe.headers.some((h) => h.status !== "ok") || liveProbe.exposedPaths.length > 0);

  const summary = [
    `Overall State: ${overallState.toUpperCase()}`,
    `Audited ${coverageLedger.totalFilesProvided} file(s) across ${inventory.components.length} dependency component(s).`,
    `Dependencies: ${confirmed.length} confirmed, ${needsValidation.length} needs_validation, ${rejectedFalsePositives.length} rejected (false-positive filtered).`,
    `Code & Secrets: ${codeAndSecretFindings.length} finding(s).`,
    liveProbe
      ? `Live Space Probe (${liveProbe.targetUrl}): ${liveProbe.overallStatus}, ${liveProbe.exposedPaths.length} exposed file(s).`
      : undefined,
    validationReasons.length > 0 ? `Not verified because: ${validationReasons.join("; ")}.` : undefined,
  ]
    .filter(Boolean)
    .join(" ");

  return {
    overallState,
    summary,
    coverageLedger,
    inventory,
    dependencyFindings: { confirmed, needsValidation, rejectedFalsePositives },
    codeAndSecretFindings,
    liveProbe,
    hardeningRecommended,
    validationReasons,
    dataGaps: advisoryResult.dataGaps,
    remediationPlan,
  };
}

function isJsonRpcRequestShape(value: unknown): value is JsonRpcRequest {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  if (v.jsonrpc !== "2.0" || typeof v.method !== "string") return false;
  if ("id" in v && v.id !== null && typeof v.id !== "string" && typeof v.id !== "number") return false;
  if ("params" in v && v.params !== undefined && (typeof v.params !== "object" || v.params === null)) return false;
  return true;
}

function toolResult(payload: unknown, isError = false) {
  return {
    content: [{ type: "text", text: typeof payload === "string" ? payload : JSON.stringify(payload, null, 2) }],
    ...(isError ? {} : { structuredContent: payload }),
    isError,
  };
}

/**
 * Handles a single MCP JSON-RPC 2.0 message. Returns null for notifications (no response allowed).
 */
export async function handleMcpRequest(
  rawRequest: unknown,
  options: ServerOptions = {},
): Promise<JsonRpcResponse | null> {
  if (!isJsonRpcRequestShape(rawRequest)) {
    const maybeId =
      typeof rawRequest === "object" && rawRequest !== null ? (rawRequest as { id?: unknown }).id : undefined;
    return {
      jsonrpc: "2.0",
      id: typeof maybeId === "string" || typeof maybeId === "number" ? maybeId : null,
      error: { code: -32600, message: "Invalid Request: expected a JSON-RPC 2.0 object with a string 'method'." },
    };
  }
  const request = rawRequest;

  // Any message without an id is a notification: never respond.
  if (!("id" in request) || request.id === undefined) return null;
  const id = request.id ?? null;

  switch (request.method) {
    case "initialize": {
      const requested = (request.params as { protocolVersion?: unknown } | undefined)?.protocolVersion;
      const protocolVersion =
        typeof requested === "string" && (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
          ? requested
          : SUPPORTED_PROTOCOL_VERSIONS[0];
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion,
          serverInfo: { name: "spacefast-sec-mcp", version: SERVER_VERSION },
          capabilities: { tools: { listChanged: false } },
          instructions:
            "Security auditor for Spacefast Spaces. Use together with the official Spacefast MCP (https://mcp.spacefast.com). Never report a Space as safe unless overallState is 'clean'.",
        },
      };
    }

    case "ping":
      return { jsonrpc: "2.0", id, result: {} };

    case "tools/list":
      return { jsonrpc: "2.0", id, result: { tools: MCP_TOOLS } };

    case "tools/call": {
      const params = request.params ?? {};
      const toolName = params.name;
      const args = (
        typeof params.arguments === "object" && params.arguments !== null ? params.arguments : {}
      ) as Record<string, unknown>;

      if (typeof toolName !== "string" || !MCP_TOOLS.some((t) => t.name === toolName)) {
        return { jsonrpc: "2.0", id, error: { code: -32602, message: `Unknown tool: ${String(toolName)}` } };
      }

      try {
        let payload: unknown;
        switch (toolName) {
          case "scan_space_full": {
            const files = parseFilesArg(args.files);
            const spaceUrl = typeof args.spaceUrl === "string" && args.spaceUrl ? args.spaceUrl : undefined;
            payload = await executeFullSpaceAudit(files, spaceUrl, options);
            break;
          }
          case "audit_dependencies": {
            const files = parseFilesArg(args.files);
            const inventory = parseSpaceInventory(files);
            const advisoryResult = await queryAdvisoriesForComponents(inventory.components, options);
            const findings = evaluateAndPrioritizeFindings(advisoryResult.records, {
              isLivePublicSpace: args.isLiveSpace === true,
              files,
              components: inventory.components,
            });
            payload = {
              inventory,
              findings,
              complete:
                advisoryResult.complete &&
                inventory.missingLockfileFor.length === 0 &&
                inventory.unparsedLockfiles.length === 0 &&
                inventory.unsupportedManifests.length === 0,
              dataGaps: advisoryResult.dataGaps,
            };
            break;
          }
          case "audit_code_and_secrets": {
            const files = parseFilesArg(args.files);
            const findings = scanCodeAndSecrets(files);
            payload = { totalFindings: findings.length, findings };
            break;
          }
          case "probe_live_space": {
            if (typeof args.spaceUrl !== "string") throw new ToolInputError("Missing required string argument 'spaceUrl'.");
            payload = await probeLiveSpace(args.spaceUrl, { fetchImpl: options.fetchImpl, ...options.probe });
            break;
          }
          case "compare_space_drift": {
            const localFiles = parseFilesArg(args.localFiles, "localFiles");
            const spaceFiles = parseFilesArg(args.spaceFiles, "spaceFiles");
            const spaceInv = parseSpaceInventory(spaceFiles);
            const advisoryResult = await queryAdvisoriesForComponents(spaceInv.components, options);
            payload = {
              ...compareSpaceDrift(localFiles, spaceFiles, advisoryResult.records),
              dataGaps: advisoryResult.dataGaps,
            };
            break;
          }
          case "plan_space_remediation": {
            const files = parseFilesArg(args.files);
            const inventory = parseSpaceInventory(files);
            const advisoryResult = await queryAdvisoriesForComponents(inventory.components, options);
            const findings = evaluateAndPrioritizeFindings(advisoryResult.records, {
              isLivePublicSpace: true,
              files,
              components: inventory.components,
            });
            payload = { ...planSpaceRemediation(files, findings), dataGaps: advisoryResult.dataGaps };
            break;
          }
        }
        return { jsonrpc: "2.0", id, result: toolResult(payload) };
      } catch (err) {
        // Tool execution errors go back to the model as isError results (MCP spec), not protocol errors.
        const message = err instanceof Error ? err.message : String(err);
        return { jsonrpc: "2.0", id, result: toolResult(`Error: ${message}`, true) };
      }
    }

    default:
      return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${request.method}` } };
  }
}
