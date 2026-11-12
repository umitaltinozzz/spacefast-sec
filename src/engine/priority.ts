import type {
  AdvisoryRecord,
  DependencyComponent,
  PrioritizedFinding,
  SpaceFileInput,
  Verdict,
} from "../types.js";

export interface PriorityContext {
  isLivePublicSpace: boolean;
  files: SpaceFileInput[];
  components: DependencyComponent[];
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function tracePackageReachability(
  packageName: string,
  files: SpaceFileInput[],
): {
  importedInCode: boolean;
  importedFiles: string[];
  calledSymbols: string[];
} {
  const importedFiles: string[] = [];
  const calledSymbols = new Set<string>();
  const escaped = escapeRegex(packageName);

  // Matches ES module imports, dynamic imports, CommonJS require, Python import, Rust use
  const importRegex = new RegExp(
    `(?:from\\s+['"]${escaped}(?:\\/[^'"]*)?['"]|\\bimport\\s+['"]${escaped}(?:\\/[^'"]*)?['"]|require\\(\\s*['"]${escaped}(?:\\/[^'"]*)?['"]\\s*\\)|import\\(\\s*['"]${escaped}(?:\\/[^'"]*)?['"]\\s*\\)|^\\s*(?:import|from)\\s+${escaped.replace(/-/g, "_")}\\b)`,
    "m",
  );
  const namedImportRegex = new RegExp(
    `import\\s+\\{([^}]+)\\}\\s+from\\s+['"]${escaped}(?:\\/[^'"]*)?['"]`,
    "g",
  );

  for (const file of files) {
    if (
      /\.(?:json|lock|yaml|yml|md|txt|toml)$/i.test(file.path) ||
      /(^|[\\/])node_modules[\\/]/.test(file.path)
    ) {
      continue;
    }
    if (importRegex.test(file.content)) {
      importedFiles.push(file.path);
      for (const match of file.content.matchAll(namedImportRegex)) {
        const inner = match[1] ?? "";
        for (const sym of inner.split(",")) {
          const clean = sym.trim().split(/\s+as\s+/)[0]?.trim();
          if (clean) calledSymbols.add(clean);
        }
      }
    }
  }

  return {
    importedInCode: importedFiles.length > 0,
    importedFiles,
    calledSymbols: [...calledSymbols],
  };
}

export function evaluateAndPrioritizeFindings(
  advisories: AdvisoryRecord[],
  context: PriorityContext,
): PrioritizedFinding[] {
  const componentMap = new Map<string, DependencyComponent>();
  for (const comp of context.components) {
    componentMap.set(`${comp.ecosystem}:${comp.name}@${comp.version}`, comp);
  }

  return advisories
    .map((advisory): PrioritizedFinding => {
      const comp = componentMap.get(
        `${advisory.ecosystem}:${advisory.package}@${advisory.installedVersion}`,
      );
      const reachability = tracePackageReachability(advisory.package, context.files);

      let score = 0;
      const reasons: string[] = [];

      // 1. Base severity score
      switch (advisory.severity) {
        case "critical":
          score += 45;
          reasons.push("severity_base_critical");
          break;
        case "high":
          score += 32;
          reasons.push("severity_base_high");
          break;
        case "medium":
          score += 20;
          reasons.push("severity_base_medium");
          break;
        case "low":
          score += 10;
          reasons.push("severity_base_low");
          break;
        default:
          score += 15;
          reasons.push("severity_unknown");
          break;
      }

      // 2. Active exploitation & probability (CISA KEV + FIRST EPSS)
      if (advisory.kevListed) {
        score += 25;
        reasons.push("kev_listed");
      }
      if (advisory.epssScore !== null) {
        if (advisory.epssScore >= 0.5) {
          score += 15;
          reasons.push("epss_very_high");
        } else if (advisory.epssScore >= 0.1) {
          score += 10;
          reasons.push("epss_high");
        } else if (advisory.epssScore > 0.01) {
          score += 4;
          reasons.push("epss_elevated");
        }
      } else {
        reasons.push("epss_missing");
      }

      if (advisory.publicExploit) {
        score += 10;
        reasons.push("public_exploit");
      }

      // 3. Spacefast deployment exposure boost
      if (context.isLivePublicSpace) {
        score += 12;
        reasons.push("production_internet_facing");
      }

      // 4. Code reachability boost (a CDN <script>/importmap load executes in every visitor's browser)
      if (reachability.importedInCode || comp?.cdnUrl) {
        score += 10;
        reasons.push("reachable_in_space_code");
      }

      if (advisory.recommendedFixVersion) {
        score += 3;
        reasons.push("fix_available");
      }

      if (score > 100) {
        score = 100;
        reasons.push("score_capped_at_100");
      }

      // 5. Cloudflare Adversarial Verdict + Trail of Bits `fp-check` Gate
      // Order matters: every branch that cannot PROVE exposure falls to needs_validation.
      let verdict: Verdict;
      let verdictReason: string;

      if (!comp) {
        verdict = "needs_validation";
        verdictReason =
          "Fail-closed: advisory could not be mapped back to a parsed inventory component, so the installed version is unverified.";
      } else if (!comp.pinned) {
        verdict = "needs_validation";
        verdictReason =
          "Fail-closed: dependency uses an unpinned version range without a lockfile; exact version on Spacefast cannot be verified.";
      } else if (comp.devOnly && !reachability.importedInCode) {
        verdict = "rejected";
        verdictReason =
          "Trail of Bits fp-check: package is a dev-only dependency and is never imported in the provided Space source files.";
        score = Math.max(5, score - 25);
      } else if (reachability.importedInCode) {
        verdict = "confirmed";
        verdictReason = `Pinned version matches the advisory and the package is imported in ${reachability.importedFiles.slice(0, 3).join(", ")}.`;
      } else if (comp.cdnUrl) {
        verdict = "confirmed";
        verdictReason = `Pinned version is loaded at runtime from a CDN (${comp.cdnUrl}), so it runs in every visitor's browser.`;
      } else if (comp.direct && !comp.devOnly && advisory.kevListed) {
        verdict = "confirmed";
        verdictReason =
          "Pinned direct production dependency with a CISA KEV (actively exploited) advisory; confirmed even without a traced import.";
      } else {
        verdict = "needs_validation";
        verdictReason = comp.direct
          ? "Pinned direct dependency, but no import was found in the provided source files (it may be used via config, CSS or a build step)."
          : "Pinned transitive dependency; no direct import was found. Reachability through the parent package must be validated.";
      }

      return {
        advisory,
        priorityScore: score,
        priorityReasons: reasons,
        verdict,
        verdictReason,
        reachability,
      };
    })
    .sort((a, b) => b.priorityScore - a.priorityScore);
}
