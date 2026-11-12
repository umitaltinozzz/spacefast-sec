import { beforeEach, describe, expect, it } from "vitest";
import { isPrivateIp, probeLiveSpace, validateSafeProbeUrl } from "../src/engine/exposure.js";
import { redactAllSecrets, scanCodeAndSecrets } from "../src/engine/codeAndSecrets.js";
import { parseSpaceInventory } from "../src/engine/inventory.js";
import {
  __resetKevCacheForTests,
  compareSemver,
  cvss3BaseScore,
  queryAdvisoriesForComponents,
  selectRecommendedFixVersion,
} from "../src/engine/advisories.js";
import { evaluateAndPrioritizeFindings } from "../src/engine/priority.js";
import { compareSpaceDrift, planSpaceRemediation } from "../src/engine/driftAndRemediation.js";
import { executeFullSpaceAudit, handleMcpRequest } from "../src/mcp/server.js";
import worker from "../src/index.js";
import type { AdvisoryRecord, SpaceFileInput } from "../src/types.js";

const lockedLodash: SpaceFileInput[] = [
  { path: "package.json", content: JSON.stringify({ dependencies: { lodash: "4.17.15" } }) },
  {
    path: "package-lock.json",
    content: JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/lodash": { version: "4.17.15" } } }),
  },
];

const osvEmpty: typeof fetch = async (input) => {
  const url = String(input);
  if (url.includes("querybatch")) {
    return new Response(JSON.stringify({ results: [{}] }), { status: 200 });
  }
  return new Response("not found", { status: 404 });
};

function advisory(partial: Partial<AdvisoryRecord>): AdvisoryRecord {
  return {
    id: "GHSA-test",
    cveIds: [],
    aliases: [],
    package: "lodash",
    ecosystem: "npm",
    installedVersion: "4.17.15",
    title: "t",
    summary: "t",
    severity: "high",
    cvssScore: null,
    epssScore: null,
    epssPercentile: null,
    kevListed: false,
    publicExploit: false,
    fixedVersions: [],
    recommendedFixVersion: null,
    sources: ["OSV"],
    references: [],
    ...partial,
  };
}

beforeEach(() => __resetKevCacheForTests());

describe("fail-closed: never clean on missing or failed data", () => {
  it("OSV HTTP 503 -> needs_validation", async () => {
    const down: typeof fetch = async () => new Response("err", { status: 503 });
    const report = await executeFullSpaceAudit(lockedLodash, undefined, { fetchImpl: down });
    expect(report.overallState).toBe("needs_validation");
    expect(report.dataGaps.some((g) => g.startsWith("osv_batch_http_503"))).toBe(true);
  });

  it("OSV network error -> needs_validation", async () => {
    const thrown: typeof fetch = async () => {
      throw new Error("net");
    };
    const report = await executeFullSpaceAudit(lockedLodash, undefined, { fetchImpl: thrown });
    expect(report.overallState).toBe("needs_validation");
  });

  it("OSV malformed batch (result count mismatch) -> incomplete", async () => {
    const bad: typeof fetch = async () => new Response(JSON.stringify({ results: [] }), { status: 200 });
    const res = await queryAdvisoriesForComponents(parseSpaceInventory(lockedLodash).components, { fetchImpl: bad });
    expect(res.complete).toBe(false);
  });

  it("exactly pinned package.json without lockfile -> needs_validation", async () => {
    const files = [{ path: "package.json", content: JSON.stringify({ dependencies: { react: "18.3.1" } }) }];
    const report = await executeFullSpaceAudit(files, undefined, { fetchImpl: osvEmpty });
    expect(report.inventory.missingLockfileFor).toEqual(["npm"]);
    expect(report.overallState).toBe("needs_validation");
  });

  it("locked + OSV clean -> clean (positive control)", async () => {
    const report = await executeFullSpaceAudit(lockedLodash, undefined, { fetchImpl: osvEmpty });
    expect(report.overallState).toBe("clean");
    expect(report.validationReasons).toEqual([]);
  });

  it("unparseable lockfile -> needs_validation", async () => {
    const files = [
      { path: "package.json", content: JSON.stringify({ dependencies: { react: "18.3.1" } }) },
      { path: "package-lock.json", content: "{ this is not json" },
    ];
    const report = await executeFullSpaceAudit(files, undefined, { fetchImpl: osvEmpty });
    expect(report.inventory.unparsedLockfiles).toContain("package-lock.json");
    expect(report.overallState).toBe("needs_validation");
  });

  it("unsupported manifest (pyproject.toml) -> needs_validation", async () => {
    const report = await executeFullSpaceAudit(
      [{ path: "pyproject.toml", content: "[project]\nname='x'" }],
      undefined,
      { fetchImpl: osvEmpty },
    );
    expect(report.overallState).toBe("needs_validation");
  });

  it("live probe 429 on a sensitive path -> needs_validation, not clean", async () => {
    const f: typeof fetch = async (i) =>
      String(i) === "https://demo.space.fast"
        ? new Response("<html>", {
            status: 200,
            headers: {
              "content-security-policy": "default-src 'self'",
              "strict-transport-security": "max-age=31536000",
              "x-content-type-options": "nosniff",
              "x-frame-options": "DENY",
            },
          })
        : new Response("rate", { status: 429 });
    const report = await probeLiveSpace("https://demo.space.fast", { fetchImpl: f });
    expect(report.overallStatus).toBe("needs_validation");
    expect(report.unverifiedPaths.length).toBeGreaterThan(0);
  });

  it("live root 5xx -> unreachable, needs_validation", async () => {
    const f: typeof fetch = async () => new Response("boom", { status: 502 });
    const report = await probeLiveSpace("https://demo.space.fast", { fetchImpl: f });
    expect(report.reachable).toBe(false);
    expect(report.overallStatus).toBe("needs_validation");
  });
});

describe("SSRF guard", () => {
  const blocked = [
    "https://[::1]/",
    "https://[::ffff:127.0.0.1]/",
    "https://127.0.0.2/",
    "https://localhost./",
    "https://0x7f000001/",
    "https://2130706433/",
    "https://100.64.0.1/",
    "https://[fd00::1]/",
    "https://0.0.0.1/",
    "https://evil.example.com/",
    "https://127.0.0.1.nip.io/",
    "https://user:pw@demo.space.fast/",
    "https://demo.space.fast:8443/",
    "http://demo.space.fast/",
    "https://foo.internal/",
  ];
  for (const u of blocked) {
    it(`blocks ${u}`, () => {
      expect(() => validateSafeProbeUrl(u)).toThrow();
    });
  }

  it("allows Spacefast hosts (and normalizes trailing dot)", () => {
    expect(validateSafeProbeUrl("https://demo.space.fast./").hostname).toBe("demo.space.fast");
    expect(validateSafeProbeUrl("https://x.drop.fast").hostname).toBe("x.drop.fast");
  });

  it("classifies private IPs (v4, v6, mapped, NAT64)", () => {
    for (const ip of ["10.0.0.1", "127.9.9.9", "169.254.169.254", "::1", "::ffff:10.0.0.1", "fe80::1", "fc00::1", "64:ff9b::a00:1"]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
    for (const ip of ["1.1.1.1", "2606:4700:4700::1111"]) {
      expect(isPrivateIp(ip), ip).toBe(false);
    }
  });

  it("refuses redirect hops to non-allowlisted hosts", async () => {
    const f: typeof fetch = async () =>
      new Response(null, { status: 302, headers: { location: "https://169.254.169.254/latest/meta-data" } });
    const report = await probeLiveSpace("https://demo.space.fast", { fetchImpl: f });
    expect(report.reachable).toBe(false);
    expect(report.unverifiedPaths[0]?.reason).toMatch(/IP literal|not a Spacefast host/);
  });

  it("uses manual redirects (never lets fetch follow)", async () => {
    const seen: RequestInit[] = [];
    const f: typeof fetch = async (_i, init) => {
      seen.push(init ?? {});
      return new Response("<html>", { status: 200 });
    };
    await probeLiveSpace("https://demo.space.fast", { fetchImpl: f });
    expect(seen.every((i) => i.redirect === "manual")).toBe(true);
  });

  it("custom domains resolving to private IPs are refused", async () => {
    const f: typeof fetch = async () => new Response("<html>", { status: 200 });
    const report = await probeLiveSpace("https://rebind.example.com", {
      fetchImpl: f,
      allowCustomDomains: true,
      resolveDns: async () => ["10.0.0.5"],
    });
    expect(report.reachable).toBe(false);
    expect(report.unverifiedPaths[0]?.reason).toMatch(/private address/);
  });
});

describe("secret redaction", () => {
  const stripe = ["sk", "live", "1234567890abcdefghijklmn"].join("_");
  const openai = ["sk", "proj", "AAAAAAAAAAAAAAAAAAAAAAAA"].join("-");
  const aws = ["AKIA", "ABCDEFGHIJKLMNOP"].join("");

  it("no finding snippet ever contains a raw secret", () => {
    const findings = scanCodeAndSecrets([
      { path: ".env.local", content: `VITE_STRIPE_SECRET_KEY=${stripe}\nX=${openai} ${aws}\n# old: ${openai}` },
      { path: "src/a.ts", content: `const s = process.env.JWT_SECRET || "MyRealProdSecret123";` },
    ]);
    expect(findings.length).toBeGreaterThan(3);
    for (const f of findings) {
      expect(f.snippetRedacted).not.toContain(stripe);
      expect(f.snippetRedacted).not.toContain(openai);
      expect(f.snippetRedacted).not.toContain(aws);
      expect(f.snippetRedacted).not.toContain("MyRealProdSecret123");
    }
    expect(findings.some((f) => f.ruleId === "SF-BUNDLE-PUBLIC-SECRET")).toBe(true);
  });

  it("redactAllSecrets masks every provider token on a line", () => {
    const out = redactAllSecrets(`a=${openai} b=${aws} c=${stripe}`);
    expect(out).not.toContain(aws);
    expect(out).not.toContain(stripe);
    expect(out).not.toContain(openai);
  });

  it("DB URI guard judges the match, not the whole line", () => {
    const findings = scanCodeAndSecrets([
      { path: "src/db.ts", content: `const a = "postgres://admin:S3cr3tPw@prod.db.example.com/app"; // not localhost` },
    ]);
    expect(findings.some((f) => f.ruleId === "SF-SEC-DB-URI")).toBe(true);
  });
});

describe("CDN inventory, SRI and unfixed advisories", () => {
  const html = [
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>',
    '<script src="https://unpkg.com/react@18"></script>',
    '<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js" integrity="sha384-x" crossorigin="anonymous"></script>',
    '<script type="importmap">{"imports":{"lodash":"https://esm.sh/lodash@4.17.15","dayjs":"https://esm.sh/dayjs"}}</script>',
  ].join("\n");

  it("inventories pinned CDN libraries and flags unpinned ones", () => {
    const inv = parseSpaceInventory([{ path: "index.html", content: html }]);
    const pinned = inv.components.filter((c) => c.pinned).map((c) => `${c.name}@${c.version}`).sort();
    expect(pinned).toEqual(["@popperjs/core@2.11.8", "jquery@3.4.1", "lodash@4.17.15"]);
    expect(inv.components.find((c) => c.name === "jquery")?.cdnUrl).toContain("cdnjs.cloudflare.com");
    expect(inv.unpinnedWarnings.map((w) => w.package).sort()).toEqual(["dayjs", "react"]);
  });

  it("a static site with only CDN scripts is never reported clean", async () => {
    const osvNone: typeof fetch = async (input) =>
      String(input).includes("querybatch")
        ? new Response(JSON.stringify({ results: [{}, {}, {}, {}] }), { status: 200 })
        : new Response("nf", { status: 404 });
    const report = await executeFullSpaceAudit([{ path: "index.html", content: html }], undefined, { fetchImpl: osvNone });
    expect(report.overallState).not.toBe("clean");
    expect(report.inventory.components.length).toBeGreaterThan(0);
  });

  it("flags third-party scripts without integrity, not the ones with it", () => {
    const sri = scanCodeAndSecrets([{ path: "index.html", content: html }]).filter((f) => f.ruleId === "SF-SRI-MISSING");
    expect(sri.map((f) => f.line)).toEqual([1, 2]);
  });

  it("CDN-loaded vulnerable version is confirmed and gets a URL update, not a package.json override", () => {
    const files = [
      { path: "index.html", content: '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>' },
      { path: "package.json", content: JSON.stringify({ name: "site", dependencies: {} }, null, 2) },
    ];
    const inv = parseSpaceInventory(files);
    const findings = evaluateAndPrioritizeFindings(
      [advisory({ id: "CVE-2020-11022", package: "jquery", installedVersion: "3.4.1", recommendedFixVersion: "3.5.0", fixedVersions: ["3.5.0"] })],
      { isLivePublicSpace: true, files, components: inv.components },
    );
    expect(findings[0]?.verdict).toBe("confirmed");
    const plan = planSpaceRemediation(files, findings);
    expect(plan.cdnUpdates).toEqual([
      expect.objectContaining({
        package: "jquery",
        file: "index.html",
        currentUrl: "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js",
        suggestedUrl: "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.0/jquery.min.js",
      }),
    ]);
    expect(plan.unifiedDiff).toBe("");
    expect(plan.updatedPackageJson).toBeNull();
  });

  it("advisories without a fix are listed as unfixed, with mitigations, and never silently dropped", () => {
    const inv = parseSpaceInventory(lockedLodash);
    const findings = evaluateAndPrioritizeFindings(
      [
        advisory({ id: "GHSA-nofix", fixedVersions: [], recommendedFixVersion: null }),
        advisory({ id: "GHSA-fixed", fixedVersions: ["4.17.21"], recommendedFixVersion: "4.17.21" }),
      ],
      { isLivePublicSpace: false, files: lockedLodash, components: inv.components },
    );
    const plan = planSpaceRemediation(lockedLodash, findings);
    expect(plan.unfixedFindings).toHaveLength(1);
    expect(plan.unfixedFindings[0]).toEqual(
      expect.objectContaining({ package: "lodash", reason: "no_patched_version", advisoryIds: ["GHSA-nofix"] }),
    );
    expect(plan.unfixedFindings[0]?.mitigations.length).toBeGreaterThan(2);
    expect(plan.spacefastPublishNotes.some((n) => n.includes("NO fix"))).toBe(true);
    expect(plan.unifiedDiff).toContain('+    "lodash": "4.17.21"');
  });
});

describe("documentation false positives", () => {
  it("code-pattern rules ignore docs, secret rules still apply", () => {
    // fake key assembled at runtime so the literal never appears in the repo (GitHub push protection)
    const fakeStripe = ["sk", "live", "1234567890abcdefghijklmn"].join("_");
    const findings = scanCodeAndSecrets([
      { path: "README.md", content: "| unsafe code | `rejectUnauthorized: false`, `eval`, `innerHTML` |" },
      { path: "README/index.html", content: "<td>rejectUnauthorized: false</td>" },
      { path: "docs/setup.md", content: `export STRIPE=${fakeStripe}` },
    ]);
    expect(findings.some((f) => f.ruleId === "SF-TOB-TLS-BYPASS")).toBe(false);
    expect(findings.some((f) => f.ruleId === "SF-SAST-DYNAMIC-EVAL")).toBe(false);
    const stripe = findings.find((f) => f.ruleId === "SF-SEC-STRIPE");
    expect(stripe?.file).toBe("docs/setup.md");
    expect(stripe?.snippetRedacted).not.toContain(fakeStripe);
  });

  it("a public /.git/HEAD is critical_exposure; a public manifest alone is needs_hardening", async () => {
    const okHeaders = {
      "content-security-policy": "default-src 'self'",
      "strict-transport-security": "max-age=31536000",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    };
    const make =
      (exposed: string, body: string): typeof fetch =>
      async (input) => {
        const url = String(input);
        if (url === "https://demo.space.fast") return new Response("<html></html>", { status: 200, headers: okHeaders });
        if (url.endsWith(exposed)) return new Response(body, { status: 200 });
        return new Response("nf", { status: 404 });
      };
    const git = await probeLiveSpace("https://demo.space.fast", { fetchImpl: make("/.git/HEAD", "ref: refs/heads/main\n") });
    expect(git.overallStatus).toBe("critical_exposure");
    const manifest = await probeLiveSpace("https://demo.space.fast", {
      fetchImpl: make("/package.json", JSON.stringify({ name: "x", dependencies: {} })),
    });
    expect(manifest.overallStatus).toBe("needs_hardening");
    expect(manifest.exposedPaths.map((p) => p.path)).toEqual(["/package.json"]);
  });
});

describe("inventory parsers", () => {
  it("yarn berry lockfile", () => {
    const berry = `__metadata:\n  version: 8\n\n"lodash@npm:^4.17.15":\n  version: 4.17.15\n  resolution: "lodash@npm:4.17.15"\n\n"@babel/core@npm:^7.0.0":\n  version: 7.24.0\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n`;
    const inv = parseSpaceInventory([{ path: "yarn.lock", content: berry }]);
    expect(inv.components.map((c) => `${c.name}@${c.version}`).sort()).toEqual(["@babel/core@7.24.0", "lodash@4.17.15"]);
    expect(inv.unparsedLockfiles).toEqual([]);
  });

  it("pnpm v5 slash format and v6 dev flag", () => {
    const v5 = `lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-x}\n    dev: true\n\n  /@babel/core/7.0.0_peer:\n    resolution: {integrity: sha512-y}\n`;
    const inv = parseSpaceInventory([{ path: "pnpm-lock.yaml", content: v5 }]);
    const lodash = inv.components.find((c) => c.name === "lodash");
    expect(lodash?.version).toBe("4.17.21");
    expect(lodash?.devOnly).toBe(true);
    expect(inv.components.find((c) => c.name === "@babel/core")?.version).toBe("7.0.0");
  });

  it("Windows-style paths are recognized", () => {
    const inv = parseSpaceInventory([
      {
        path: "apps\\web\\package-lock.json",
        content: JSON.stringify({ packages: { "node_modules/a": { version: "1.0.0" } } }),
      },
    ]);
    expect(inv.components).toHaveLength(1);
  });

  it("requirements.txt: bare names, extras, URLs never silently disappear", () => {
    const inv = parseSpaceInventory([
      { path: "requirements.txt", content: "requests\nflask[async]==2.0.0\ngit+https://github.com/x/y.git\n" },
    ]);
    expect(inv.components.find((c) => c.name === "flask")?.pinned).toBe(true);
    expect(inv.unpinnedWarnings.map((w) => w.package)).toEqual(expect.arrayContaining(["requests"]));
    expect(inv.unpinnedWarnings.length).toBe(2);
    expect(inv.missingLockfileFor).toContain("pypi");
  });

  it("npm alias resolves to the real package; workspace specifiers are ignored", () => {
    const inv = parseSpaceInventory([
      {
        path: "package.json",
        content: JSON.stringify({ dependencies: { str: "npm:string-width@4.2.3", local: "workspace:*" } }),
      },
    ]);
    expect(inv.components.map((c) => c.name)).toEqual(["string-width"]);
  });
});

describe("advisories engine", () => {
  it("wires CISA KEV from the public feed (no API key)", async () => {
    const f: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("querybatch")) return new Response(JSON.stringify({ results: [{ vulns: [{ id: "GHSA-1" }] }] }));
      if (url.includes("/vulns/GHSA-1")) {
        return new Response(
          JSON.stringify({
            id: "GHSA-1",
            aliases: ["CVE-2021-23337"],
            severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
            affected: [
              { package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] },
              { package: { name: "lodash-es", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.9.9" }] }] },
            ],
          }),
        );
      }
      if (url.includes("kev")) return new Response(JSON.stringify({ vulnerabilities: [{ cveID: "CVE-2021-23337" }] }));
      if (url.includes("epss")) return new Response(JSON.stringify({ data: [] }));
      return new Response("nf", { status: 404 });
    };
    const res = await queryAdvisoriesForComponents(parseSpaceInventory(lockedLodash).components, {
      fetchImpl: f,
      cisaKevUrl: "https://example.test/kev.json",
    });
    const rec = res.records[0]!;
    expect(rec.kevListed).toBe(true);
    expect(rec.sources).toContain("CISA KEV");
    // cve.now returned 404 in this mock, so "cve.now" is not falsely attributed:
    expect(rec.sources).not.toContain("cve.now");
    expect(rec.cvssScore).toBe(7.2);
    expect(rec.severity).toBe("high");
    expect(rec.fixedVersions).toEqual(["4.17.21"]); // lodash-es fix not mixed in
    expect(res.complete).toBe(true);
  });

  it("enriches AdvisoryRecord from SecMon cve.now (/api/v1/entries/{cveId}) when present and reports cve_now_unavailable on 5xx", async () => {
    const fOk: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("querybatch")) {
        return new Response(JSON.stringify({ results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] }] }));
      }
      if (url.includes("/vulns/GHSA-35jh-r3h4-6jhm")) {
        return new Response(
          JSON.stringify({
            id: "GHSA-35jh-r3h4-6jhm",
            aliases: ["CVE-2021-23337"],
            affected: [
              {
                package: { name: "lodash", ecosystem: "npm" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
              },
            ],
          }),
        );
      }
      if (url.includes("/api/v1/entries/CVE-2021-23337")) {
        return new Response(
          JSON.stringify({
            id: "CVE-2021-23337",
            title: "Lodash Command Injection via template",
            summary: { text: "cve.now curated summary for CVE-2021-23337", model: "secmon" },
            statedSeverity: "high",
            severity: { cvss: 7.2 },
            exploitation: { kev: true },
            affected: [
              {
                package: "lodash",
                ecosystem: "npm",
                ranges: [{ type: "SEMVER", introduced: "0", fixed: "4.17.21" }],
              },
            ],
            sources: [{ name: "NVD", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337" }],
          }),
        );
      }
      if (url.includes("kev")) return new Response(JSON.stringify({ vulnerabilities: [{ cveID: "CVE-2099-0001" }] }));
      if (url.includes("epss")) return new Response(JSON.stringify({ data: [] }));
      return new Response("nf", { status: 404 });
    };

    const resOk = await queryAdvisoriesForComponents(parseSpaceInventory(lockedLodash).components, {
      fetchImpl: fOk,
      cveNowUrl: "https://cve.now",
      cisaKevUrl: "https://example.test/kev.json",
    });
    const rec = resOk.records[0]!;
    expect(rec.sources).toContain("cve.now");
    expect(rec.title).toBe("Lodash Command Injection via template");
    expect(rec.summary).toBe("cve.now curated summary for CVE-2021-23337");
    expect(rec.cvssScore).toBe(7.2);
    expect(rec.severity).toBe("high");
    expect(rec.kevListed).toBe(true);
    expect(rec.fixedVersions).toContain("4.17.21");
    expect(rec.recommendedFixVersion).toBe("4.17.21");
    expect(rec.references).toContain("https://cve.now/CVE-2021-23337");
    expect(resOk.complete).toBe(true);

    // Now test 503 failure from cve.now -> reported in dataGaps as cve_now_unavailable
    __resetKevCacheForTests();
    const fDown: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("/api/v1/entries/")) return new Response("err", { status: 503 });
      return fOk(input);
    };
    const resDown = await queryAdvisoriesForComponents(parseSpaceInventory(lockedLodash).components, {
      fetchImpl: fDown,
      cveNowUrl: "https://cve.now",
      cisaKevUrl: "https://example.test/kev.json",
    });
    expect(resDown.records[0]?.sources).not.toContain("cve.now");
    expect(resDown.dataGaps.some((g) => g.startsWith("cve_now_unavailable"))).toBe(true);
  });

  it("KEV feed failure is reported as a data gap", async () => {
    const f: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("querybatch")) return new Response(JSON.stringify({ results: [{ vulns: [{ id: "CVE-2021-1" }] }] }));
      if (url.includes("/vulns/")) return new Response(JSON.stringify({ id: "CVE-2021-1" }));
      return new Response("down", { status: 500 });
    };
    const res = await queryAdvisoriesForComponents(parseSpaceInventory(lockedLodash).components, {
      fetchImpl: f,
      cisaKevUrl: "https://example.test/kev.json",
    });
    expect(res.dataGaps.some((g) => g.startsWith("cisa_kev_unavailable"))).toBe(true);
    expect(res.complete).toBe(false);
  });

  it("KEV falls back to the next source when the first answers 403", async () => {
    const f: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("querybatch")) return new Response(JSON.stringify({ results: [{ vulns: [{ id: "CVE-2021-23337" }] }] }));
      if (url.includes("/vulns/")) return new Response(JSON.stringify({ id: "CVE-2021-23337" }));
      if (url.startsWith("https://blocked.test")) return new Response("forbidden", { status: 403 });
      if (url.startsWith("https://mirror.test")) {
        return new Response(JSON.stringify({ vulnerabilities: [{ cveID: "CVE-2021-23337" }] }));
      }
      return new Response(JSON.stringify({ data: [] }));
    };
    const res = await queryAdvisoriesForComponents(parseSpaceInventory(lockedLodash).components, {
      fetchImpl: f,
      cisaKevUrl: "https://blocked.test/kev.json,https://mirror.test/kev.json",
    });
    expect(res.records[0]?.kevListed).toBe(true);
    expect(res.dataGaps.filter((g) => g.startsWith("cisa_kev"))).toEqual([]);
  });

  it("CVSS 3.1 vectors are scored", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
  });

  it("semver prerelease ordering and no downgrade recommendations", () => {
    expect(compareSemver("1.0.0-beta", "1.0.0")).toBeLessThan(0);
    expect(compareSemver("1.0.0-alpha.2", "1.0.0-alpha.10")).toBeLessThan(0);
    expect(selectRecommendedFixVersion("5.0.0", ["4.17.21"])).toBeNull();
    expect(selectRecommendedFixVersion("4.17.15", ["5.0.1", "4.17.21", "4.18.0"])).toBe("4.17.21");
  });
});

describe("priority verdicts", () => {
  it("pinned transitive, not imported -> needs_validation (no file-count heuristic)", () => {
    const inv = parseSpaceInventory(lockedLodash);
    const [f] = evaluateAndPrioritizeFindings([advisory({})], {
      isLivePublicSpace: false,
      files: lockedLodash,
      components: inv.components,
    });
    expect(f?.verdict).toBe("needs_validation");
  });

  it("direct prod dependency with KEV -> confirmed even without import", () => {
    const inv = parseSpaceInventory(lockedLodash);
    const [f] = evaluateAndPrioritizeFindings([advisory({ kevListed: true })], {
      isLivePublicSpace: false,
      files: lockedLodash,
      components: inv.components,
    });
    expect(f?.verdict).toBe("confirmed");
  });

  it("side-effect imports count as reachable", () => {
    const files = [...lockedLodash, { path: "src/main.ts", content: `import "lodash";` }];
    const [f] = evaluateAndPrioritizeFindings([advisory({})], {
      isLivePublicSpace: false,
      files,
      components: parseSpaceInventory(files).components,
    });
    expect(f?.verdict).toBe("confirmed");
  });
});

describe("drift and remediation", () => {
  it("compares version sets (multiple versions of one package)", () => {
    const lock = (versions: Record<string, string>) =>
      JSON.stringify({ lockfileVersion: 3, packages: Object.fromEntries(Object.entries(versions).map(([p, v]) => [p, { version: v }])) });
    const local = [{ path: "package-lock.json", content: lock({ "node_modules/ms": "2.1.3", "node_modules/debug/node_modules/ms": "2.0.0" }) }];
    const space = [{ path: "package-lock.json", content: lock({ "node_modules/debug/node_modules/ms": "2.0.0", "node_modules/ms": "2.1.3" }) }];
    expect(compareSpaceDrift(local, space).hasDrift).toBe(false);
  });

  it("produces a real unified diff with @@ hunks against the ROOT package.json", () => {
    const files = [
      { path: "node_modules/x/package.json", content: JSON.stringify({ dependencies: { lodash: "1.0.0" } }) },
      { path: "package.json", content: `${JSON.stringify({ name: "app", dependencies: { lodash: "4.17.15" } }, null, 2)}\n` },
    ];
    const plan = planSpaceRemediation(files, [
      {
        advisory: advisory({ recommendedFixVersion: "4.17.21" }),
        priorityScore: 50,
        priorityReasons: [],
        verdict: "confirmed",
        verdictReason: "",
        reachability: { importedInCode: true, importedFiles: [], calledSymbols: [] },
      },
    ]);
    expect(plan.packageJsonPath).toBe("package.json");
    expect(plan.unifiedDiff).toMatch(/^--- a\/package\.json\n\+\+\+ b\/package\.json\n@@ -\d+,\d+ \+\d+,\d+ @@/);
    expect(plan.unifiedDiff).toContain('-    "lodash": "4.17.15"\n+    "lodash": "4.17.21"');
  });

  it("uses pnpm.overrides for transitive fixes in pnpm projects", () => {
    const files = [
      { path: "package.json", content: JSON.stringify({ name: "app", dependencies: { react: "18.3.1" } }, null, 2) },
      { path: "pnpm-lock.yaml", content: "lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.15:\n    resolution: {integrity: x}\n" },
    ];
    const plan = planSpaceRemediation(files, [
      {
        advisory: advisory({ recommendedFixVersion: "4.17.21" }),
        priorityScore: 40,
        priorityReasons: [],
        verdict: "needs_validation",
        verdictReason: "",
        reachability: { importedInCode: false, importedFiles: [], calledSymbols: [] },
      },
    ]);
    expect(plan.overrideField).toBe("pnpm.overrides");
    expect(JSON.parse(plan.updatedPackageJson!).pnpm.overrides.lodash).toBe("4.17.21");
  });
});

describe("JSON-RPC / Streamable HTTP", () => {
  it("null / malformed messages return Invalid Request instead of crashing", async () => {
    expect((await handleMcpRequest(null))?.error?.code).toBe(-32600);
    expect((await handleMcpRequest({ jsonrpc: "2.0", id: 1 }))?.error?.code).toBe(-32600);
  });

  it("never responds to notifications", async () => {
    expect(await handleMcpRequest({ jsonrpc: "2.0", method: "notifications/progress" })).toBeNull();
  });

  it("negotiates protocol version", async () => {
    const r1 = await handleMcpRequest({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26" } });
    expect((r1?.result as { protocolVersion: string }).protocolVersion).toBe("2025-03-26");
    const r2 = await handleMcpRequest({ jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "1999-01-01" } });
    expect((r2?.result as { protocolVersion: string }).protocolVersion).toBe("2025-06-18");
  });

  it("tool failures are isError results; unknown tools are -32602", async () => {
    const bad = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "probe_live_space", arguments: { spaceUrl: "https://127.0.0.1" } },
    });
    expect(bad?.error).toBeUndefined();
    expect((bad?.result as { isError: boolean }).isError).toBe(true);
    const unknown = await handleMcpRequest({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "nope" } });
    expect(unknown?.error?.code).toBe(-32602);
  });

  it("worker: null body, GET /mcp, foreign Origin", async () => {
    const env = {};
    const nullRes = await worker.fetch(new Request("https://w/mcp", { method: "POST", body: "null" }), env);
    expect(nullRes.status).toBe(200);
    expect(((await nullRes.json()) as { error: { code: number } }).error.code).toBe(-32600);

    const getRes = await worker.fetch(new Request("https://w/mcp", { headers: { accept: "text/event-stream" } }), env);
    expect(getRes.status).toBe(405);

    const evil = await worker.fetch(
      new Request("https://w/mcp", { method: "POST", body: "{}", headers: { Origin: "https://evil.example" } }),
      env,
    );
    expect(evil.status).toBe(403);

    const notif = await worker.fetch(
      new Request("https://w/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) }),
      env,
    );
    expect(notif.status).toBe(202);
  });
});
