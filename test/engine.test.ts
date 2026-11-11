import { describe, expect, it } from "vitest";
import { parseSpaceInventory } from "../src/engine/inventory.js";
import { scanCodeAndSecrets } from "../src/engine/codeAndSecrets.js";
import { evaluateAndPrioritizeFindings, tracePackageReachability } from "../src/engine/priority.js";
import { probeLiveSpace } from "../src/engine/exposure.js";
import { compareSpaceDrift, planSpaceRemediation } from "../src/engine/driftAndRemediation.js";
import { handleMcpRequest } from "../src/mcp/server.js";
import type { AdvisoryRecord, SpaceFileInput } from "../src/types.js";

describe("Spacefast-Sec Engine & MCP Suite", () => {
  it("parses package.json without lockfile and emits fail-closed unpinned warnings", () => {
    const files: SpaceFileInput[] = [
      {
        path: "package.json",
        content: JSON.stringify({
          name: "my-drop-space",
          dependencies: {
            lodash: "^4.17.15",
            react: "18.2.0",
          },
          devDependencies: {
            vitest: "~1.0.0",
          },
        }),
      },
    ];

    const report = parseSpaceInventory(files);
    expect(report.manifestFiles).toEqual(["package.json"]);
    expect(report.lockfiles).toEqual([]);
    expect(report.hasLockfile).toBe(false);
    expect(report.components).toHaveLength(3);

    const lodash = report.components.find((c) => c.name === "lodash");
    expect(lodash?.pinned).toBe(false);
    expect(lodash?.version).toBe("4.17.15");

    const react = report.components.find((c) => c.name === "react");
    expect(react?.pinned).toBe(true);

    // Fail-closed rule: missing lockfile + unpinned ranges must produce warnings
    expect(report.unpinnedWarnings.length).toBeGreaterThanOrEqual(2);
  });

  it("traces reachability and classifies findings into confirmed, needs_validation, and rejected (fp-check)", () => {
    const files: SpaceFileInput[] = [
      {
        path: "package.json",
        content: JSON.stringify({
          dependencies: {
            lodash: "4.17.15",
            axios: "^0.21.1",
          },
          devDependencies: {
            "esbuild-dev-helper": "0.1.0",
          },
        }),
      },
      {
        path: "src/App.tsx",
        content: `import { template } from "lodash";\nexport const res = template("hello");\n`,
      },
    ];

    const inventory = parseSpaceInventory(files);
    const reachabilityLodash = tracePackageReachability("lodash", files);
    expect(reachabilityLodash.importedInCode).toBe(true);
    expect(reachabilityLodash.importedFiles).toContain("src/App.tsx");
    expect(reachabilityLodash.calledSymbols).toContain("template");

    const advisories: AdvisoryRecord[] = [
      {
        id: "CVE-2021-23337",
        cveIds: ["CVE-2021-23337"],
        aliases: ["GHSA-35jh-r3h4-6jhm"],
        package: "lodash",
        ecosystem: "npm",
        installedVersion: "4.17.15",
        title: "Command Injection in lodash template",
        summary: "Command Injection in lodash template",
        severity: "high",
        cvssScore: 7.2,
        kevListed: true,
        publicExploit: true,
        epssScore: 0.45,
        epssPercentile: 0.97,
        fixedVersions: ["4.17.21"],
        recommendedFixVersion: "4.17.21",
        references: [],
        sources: ["OSV"],
      },
      {
        id: "CVE-2021-3749",
        cveIds: ["CVE-2021-3749"],
        aliases: [],
        package: "axios",
        ecosystem: "npm",
        installedVersion: "0.21.1",
        title: "ReDoS in axios",
        summary: "ReDoS in axios",
        severity: "medium",
        cvssScore: 5.5,
        kevListed: false,
        publicExploit: false,
        epssScore: 0.02,
        epssPercentile: 0.5,
        fixedVersions: ["0.21.2"],
        recommendedFixVersion: "0.21.2",
        references: [],
        sources: ["OSV"],
      },
      {
        id: "GHSA-dev-only-0001",
        cveIds: [],
        aliases: [],
        package: "esbuild-dev-helper",
        ecosystem: "npm",
        installedVersion: "0.1.0",
        title: "Dev server local issue",
        summary: "Dev server local issue",
        severity: "medium",
        cvssScore: 5.0,
        kevListed: false,
        publicExploit: false,
        epssScore: 0.001,
        epssPercentile: 0.1,
        fixedVersions: ["0.1.1"],
        recommendedFixVersion: "0.1.1",
        references: [],
        sources: ["OSV"],
      },
    ];

    const prioritized = evaluateAndPrioritizeFindings(advisories, {
      isLivePublicSpace: true,
      files,
      components: inventory.components,
    });

    const lodashFinding = prioritized.find((f) => f.advisory.package === "lodash");
    const axiosFinding = prioritized.find((f) => f.advisory.package === "axios");
    const devFinding = prioritized.find((f) => f.advisory.package === "esbuild-dev-helper");

    // Lodash is pinned, reachable in src/App.tsx, and KEV -> confirmed with high priority score
    expect(lodashFinding?.verdict).toBe("confirmed");
    expect(lodashFinding?.priorityScore).toBeGreaterThanOrEqual(80);

    // Axios is unpinned (^0.21.1 without lockfile) -> needs_validation (fail-closed)
    expect(axiosFinding?.verdict).toBe("needs_validation");

    // esbuild-dev-helper is dev-only, not imported in runtime code -> rejected (Trail of Bits fp-check)
    expect(devFinding?.verdict).toBe("rejected");
  });

  it("detects secrets (with redaction), VITE_ bundle leaks, Trail of Bits fail-open defaults, and Semgrep SAST patterns", () => {
    const fakeOpenAiKey = ["sk", "proj", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"].join("-");
    const fakeStripeKey = ["sk", "live", "1234567890abcdefghijklmn"].join("_");
    const files: SpaceFileInput[] = [
      {
        path: ".env.local",
        content: `OPENAI_API_KEY=${fakeOpenAiKey}\nVITE_STRIPE_SECRET_KEY=${fakeStripeKey}\n`,
      },
      {
        path: "src/auth.tsx",
        content: [
          `const jwtSecret = process.env.JWT_SECRET || "default-insecure-secret";`,
          `const el = <div dangerouslySetInnerHTML={{ __html: userComment }} />;`,
          `const query = \`SELECT * FROM users WHERE email = '\${userEmail}'\`;`,
        ].join("\n"),
      },
    ];

    const findings = scanCodeAndSecrets(files);

    // 1. Sensitive .env.local file presence
    expect(findings.some((f) => f.ruleId === "SF-FILE-ENV")).toBe(true);

    // 2. OpenAI key detected and properly redacted (never raw in snippet)
    const openAiFinding = findings.find((f) => f.ruleId === "SF-SEC-OPENAI");
    expect(openAiFinding).toBeDefined();
    expect(openAiFinding?.snippetRedacted).not.toContain(fakeOpenAiKey);
    expect(openAiFinding?.snippetRedacted).toContain("****");

    // 3. VITE_ public bundle secret leak
    expect(findings.some((f) => f.ruleId === "SF-BUNDLE-PUBLIC-SECRET")).toBe(true);

    // 4. Trail of Bits insecure-defaults fail-open secret fallback
    expect(findings.some((f) => f.ruleId === "SF-TOB-FAILOPEN-SECRET")).toBe(true);

    // 5. Semgrep DOM XSS & SQLi
    expect(findings.some((f) => f.ruleId === "SF-SAST-DANGEROUS-HTML")).toBe(true);
    expect(findings.some((f) => f.ruleId === "SF-SAST-SQL-INTERPOLATION")).toBe(true);
  });

  it("probes live *.space.fast URL and filters out SPA index.html catch-all false positives", async () => {
    const mockFetch: typeof fetch = async (input) => {
      const url = String(input);
      if (url === "https://demo.space.fast") {
        return new Response('<!doctype html><html><head><script src="/assets/app.js"></script></head></html>', {
          status: 200,
          headers: { "content-type": "text/html" },
        });
      }
      if (url === "https://demo.space.fast/.env") {
        // SPA fallback returning 200 OK with index.html! Must NOT be flagged as an exposed .env!
        return new Response("<!doctype html><html><body>SPA</body></html>", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
      }
      if (url === "https://demo.space.fast/package.json") {
        // Real exposed package.json on a drop.fast static deployment!
        return new Response(JSON.stringify({ name: "demo", dependencies: { react: "18.2.0" } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "https://demo.space.fast/assets/app.js.map") {
        return new Response(JSON.stringify({ version: 3, sources: ["src/App.tsx"] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("Not Found", { status: 404 });
    };

    const report = await probeLiveSpace("https://demo.space.fast", { fetchImpl: mockFetch });
    expect(report.reachable).toBe(true);
    expect(report.overallStatus).toBe("critical_exposure");
    // /.env SPA fallback was rejected; /package.json and /assets/app.js.map were confirmed
    expect(report.exposedPaths.map((p) => p.path)).toEqual(["/package.json", "/assets/app.js.map"]);
  });

  it("detects local-vs-Space security drift and generates a deterministic package.json remediation diff", () => {
    const localFiles: SpaceFileInput[] = [
      {
        path: "package.json",
        content: JSON.stringify({ name: "app", dependencies: { lodash: "4.17.21" } }, null, 2),
      },
      {
        path: "package-lock.json",
        content: JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { dependencies: { lodash: "4.17.21" } },
            "node_modules/lodash": { version: "4.17.21" },
          },
        }),
      },
    ];

    const spaceFiles: SpaceFileInput[] = [
      {
        path: "package.json",
        content: JSON.stringify({ name: "app", dependencies: { lodash: "4.17.15" } }, null, 2),
      },
    ];

    const spaceAdvisories: AdvisoryRecord[] = [
      {
        id: "CVE-2021-23337",
        cveIds: ["CVE-2021-23337"],
        aliases: [],
        package: "lodash",
        ecosystem: "npm",
        installedVersion: "4.17.15",
        title: "Command injection in lodash",
        summary: "Command injection in lodash",
        severity: "high",
        cvssScore: 7.2,
        kevListed: true,
        publicExploit: false,
        epssScore: 0.4,
        epssPercentile: 0.95,
        fixedVersions: ["4.17.21"],
        recommendedFixVersion: "4.17.21",
        references: [],
        sources: ["OSV"],
      },
    ];

    const drift = compareSpaceDrift(localFiles, spaceFiles, spaceAdvisories);
    expect(drift.hasDrift).toBe(true);
    expect(drift.lockfileMissingInSpace).toBe(true);
    expect(drift.items.some((d) => d.status === "fixed_locally_vulnerable_in_space")).toBe(true);

    const spaceInv = parseSpaceInventory(spaceFiles);
    const findings = evaluateAndPrioritizeFindings(spaceAdvisories, {
      isLivePublicSpace: true,
      files: spaceFiles,
      components: spaceInv.components,
    });
    const plan = planSpaceRemediation(spaceFiles, findings);

    expect(plan.actions).toHaveLength(1);
    expect(plan.actions[0]?.toVersion).toBe("4.17.21");
    expect(plan.unifiedDiff).toContain('+    "lodash": "4.17.21"');
  });

  it("handles MCP JSON-RPC tools/list and tools/call (scan_space_full) end-to-end offline", async () => {
    const mockFetch: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("api.osv.dev")) {
        return new Response(JSON.stringify({ results: [{ vulns: [] }] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "https://clean.space.fast") {
        return new Response("<!doctype html><html><body>Clean</body></html>", {
          status: 200,
          headers: {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
          },
        });
      }
      return new Response("Not Found", { status: 404 });
    };

    const listRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
    });
    expect(listRes?.error).toBeUndefined();

    const scanRes = await handleMcpRequest(
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
          name: "scan_space_full",
          arguments: {
            files: [
              {
                path: "package.json",
                content: JSON.stringify({
                  name: "clean-space",
                  dependencies: { react: "18.3.1" },
                }),
              },
              {
                path: "package-lock.json",
                content: JSON.stringify({
                  lockfileVersion: 3,
                  packages: {
                    "": { dependencies: { react: "18.3.1" } },
                    "node_modules/react": { version: "18.3.1" },
                  },
                }),
              },
            ],
            spaceUrl: "https://clean.space.fast",
          },
        },
      },
      { fetchImpl: mockFetch },
    );

    expect(scanRes?.error).toBeUndefined();
    const structured = (scanRes?.result as { structuredContent: { overallState: string } }).structuredContent;
    expect(structured.overallState).toBe("clean");
  });
});
