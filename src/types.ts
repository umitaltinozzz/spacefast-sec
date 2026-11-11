export type Ecosystem = "npm" | "pypi" | "cargo" | "golang" | "composer";

export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

/**
 * Cloudflare `security-audit-skill` + SecMon fail-closed verdict model:
 * - `confirmed`: Verified vulnerability with pinned version or proven code/live exposure trace.
 * - `needs_validation`: Unpinned dependency range, missing lockfile, or unverified reachability. Never marked safe by default.
 * - `rejected`: Disproved by adversarial/fp-check verification (e.g. dev-only dependency not bundled and not imported).
 */
export type Verdict = "confirmed" | "needs_validation" | "rejected";

export interface SpaceFileInput {
  path: string;
  content: string;
}

export interface DependencyComponent {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  rawRange?: string;
  pinned: boolean;
  devOnly: boolean;
  sourceFile: string;
  purl: string;
  /** True when the package is declared directly in a manifest (package.json etc.), not only transitively. */
  direct?: boolean;
}

export interface InventoryReport {
  components: DependencyComponent[];
  unpinnedWarnings: {
    package: string;
    rawRange: string;
    sourceFile: string;
    reason: string;
  }[];
  hasLockfile: boolean;
  manifestFiles: string[];
  lockfiles: string[];
  /** Lockfiles (or package.json files) that were provided but could not be parsed. Fail-closed. */
  unparsedLockfiles: string[];
  /** Ecosystems that have a manifest but no parsed lockfile, so transitive versions are unverified. */
  missingLockfileFor: Ecosystem[];
  /** Manifests/lockfiles that exist but this engine cannot parse (pyproject.toml, composer.lock, ...). */
  unsupportedManifests: string[];
}

export interface AdvisoryQueryResult {
  records: AdvisoryRecord[];
  /** False when any upstream source failed or was truncated; callers must NOT report `clean`. */
  complete: boolean;
  /** Machine-readable description of every missing / failed data source. */
  dataGaps: string[];
}

export interface AdvisoryRecord {
  id: string;
  cveIds: string[];
  aliases: string[];
  package: string;
  ecosystem: Ecosystem;
  installedVersion: string;
  title: string;
  summary: string;
  severity: Severity;
  cvssScore: number | null;
  epssScore: number | null;
  epssPercentile: number | null;
  kevListed: boolean;
  publicExploit: boolean;
  fixedVersions: string[];
  recommendedFixVersion: string | null;
  sources: string[];
  references: string[];
}

export interface PrioritizedFinding {
  advisory: AdvisoryRecord;
  priorityScore: number;
  priorityReasons: string[];
  verdict: Verdict;
  verdictReason: string;
  reachability: {
    importedInCode: boolean;
    importedFiles: string[];
    calledSymbols: string[];
  };
}

export type CodeFindingCategory =
  | "hardcoded_secret"
  | "client_bundle_secret_leak"
  | "insecure_default_fail_open"
  | "owasp_code_pattern"
  | "exposed_sensitive_file";

export interface CodeAndSecretFinding {
  id: string;
  ruleId: string;
  category: CodeFindingCategory;
  severity: Severity;
  verdict: Verdict;
  title: string;
  description: string;
  file: string;
  line: number;
  snippetRedacted: string;
  remediationHint: string;
}

export interface LivePathProbe {
  path: string;
  status: number | null;
  exposed: boolean;
  severity: Severity;
  evidence: string;
}

export interface SecurityHeaderAudit {
  header: string;
  present: boolean;
  value: string | null;
  status: "ok" | "missing" | "misconfigured";
  recommendation: string;
}

export interface LiveProbeReport {
  targetUrl: string;
  reachable: boolean;
  exposedPaths: LivePathProbe[];
  /** Paths whose probe was inconclusive (timeout, 429, 5xx, network error). Fail-closed. */
  unverifiedPaths: { path: string; status: number | null; reason: string }[];
  headers: SecurityHeaderAudit[];
  overallStatus: "critical_exposure" | "needs_hardening" | "clean" | "needs_validation";
}

export interface DriftItem {
  package: string;
  ecosystem: Ecosystem;
  localVersion: string | null;
  spaceVersion: string | null;
  status:
    | "fixed_locally_vulnerable_in_space"
    | "version_mismatch"
    | "only_in_space"
    | "only_in_local";
  affectedCves: string[];
  /** True when the Space side version is only a range floor (no lockfile), so it is not the real installed version. */
  spaceVersionUnverified?: boolean;
}

export interface DriftReport {
  hasDrift: boolean;
  lockfileMissingInSpace: boolean;
  items: DriftItem[];
  summary: string;
}

export interface RemediationAction {
  package: string;
  ecosystem: Ecosystem;
  fromVersion: string;
  toVersion: string;
  fixesAdvisories: string[];
  priorityScore: number;
}

export interface RemediationPlan {
  actions: RemediationAction[];
  updatedPackageJson: string | null;
  /** Path of the package.json that the patch applies to (root manifest, never node_modules). */
  packageJsonPath: string | null;
  /** Which override mechanism was used for transitive deps: npm `overrides`, pnpm `pnpm.overrides`, yarn `resolutions`. */
  overrideField: "overrides" | "pnpm.overrides" | "resolutions" | null;
  unifiedDiff: string;
  /** Actions that could not be expressed as a package.json patch (non-npm ecosystems). */
  manualActions: RemediationAction[];
  spacefastPublishNotes: string[];
}

export interface CoverageLedger {
  totalFilesProvided: number;
  auditedManifests: string[];
  auditedLockfiles: string[];
  auditedSourceFiles: string[];
  skippedOrUnverifiedFiles: string[];
  liveUrlProbed: boolean;
  dataGaps: string[];
  blindSpots: string[];
}
