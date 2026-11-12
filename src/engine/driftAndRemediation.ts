import type {
  AdvisoryRecord,
  CoverageLedger,
  DriftItem,
  DriftReport,
  InventoryReport,
  PrioritizedFinding,
  RemediationAction,
  CdnUpdate,
  RemediationPlan,
  SpaceFileInput,
  UnfixedFinding,
} from "../types.js";
import { compareSemver } from "./advisories.js";
import { normalizePath, parseCdnReferences, parseSpaceInventory } from "./inventory.js";

const NPM_MANIFEST_OR_LOCK = /(^|\/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$/;

function unfixedMitigations(pkg: string, calledSymbols: string[], viaCdn: boolean): string[] {
  const out = [
    `Check whether ${pkg} can be removed or replaced with a maintained alternative.`,
    calledSymbols.length > 0
      ? `Limit or remove use of the affected API (${calledSymbols.slice(0, 4).join(", ")}) and never pass untrusted input to it.`
      : `Confirm which ${pkg} functions the Space actually uses and keep untrusted input away from them.`,
    "Watch the advisory for a patched release and re-run scan_space_full when one appears.",
  ];
  if (viaCdn) out.push("Because it is loaded from a CDN, pin the exact version and add an integrity hash so it cannot change silently.");
  return out;
}

/**
 * Compares a local workspace's files against the files currently deployed on a Spacefast Space
 * to detect security drift (e.g. a CVE fixed locally in `package.json` / lockfile that has NOT
 * yet been published to the live Space, or a missing lockfile on the Space).
 *
 * Packages are compared as version SETS, because a lockfile can contain several versions
 * of the same package.
 */
export function compareSpaceDrift(
  localFiles: SpaceFileInput[],
  spaceFiles: SpaceFileInput[],
  spaceAdvisories: AdvisoryRecord[] = [],
): DriftReport {
  const localInv = parseSpaceInventory(localFiles);
  const spaceInv = parseSpaceInventory(spaceFiles);

  const collect = (inv: InventoryReport) => {
    const map = new Map<string, { versions: Set<string>; unverified: boolean }>();
    for (const comp of inv.components) {
      const key = `${comp.ecosystem}:${comp.name}`;
      const entry = map.get(key) ?? { versions: new Set<string>(), unverified: false };
      entry.versions.add(comp.version);
      if (!comp.pinned) entry.unverified = true;
      map.set(key, entry);
    }
    return map;
  };
  const localMap = collect(localInv);
  const spaceMap = collect(spaceInv);

  const fmt = (s?: Set<string>) => (s && s.size > 0 ? [...s].sort(compareSemver).join(", ") : null);
  const sameSet = (a: Set<string>, b: Set<string>) => a.size === b.size && [...a].every((v) => b.has(v));

  const items: DriftItem[] = [];
  const lockfileMissingInSpace = localInv.hasLockfile && !spaceInv.hasLockfile;

  for (const key of new Set([...localMap.keys(), ...spaceMap.keys()])) {
    const sep = key.indexOf(":");
    const ecosystem = key.slice(0, sep) as DriftItem["ecosystem"];
    const pkgName = key.slice(sep + 1);
    const local = localMap.get(key);
    const space = spaceMap.get(key);

    if (local && space && sameSet(local.versions, space.versions)) continue;

    if (local && space) {
      const vulnerableOnlyInSpace = spaceAdvisories.filter(
        (adv) =>
          adv.ecosystem === ecosystem &&
          adv.package === pkgName &&
          space.versions.has(adv.installedVersion) &&
          !local.versions.has(adv.installedVersion),
      );
      items.push({
        package: pkgName,
        ecosystem,
        localVersion: fmt(local.versions),
        spaceVersion: fmt(space.versions),
        status: vulnerableOnlyInSpace.length > 0 ? "fixed_locally_vulnerable_in_space" : "version_mismatch",
        affectedCves: [
          ...new Set(vulnerableOnlyInSpace.flatMap((a) => (a.cveIds.length > 0 ? a.cveIds : [a.id]))),
        ],
        spaceVersionUnverified: space.unverified,
      });
    } else if (space) {
      items.push({
        package: pkgName,
        ecosystem,
        localVersion: null,
        spaceVersion: fmt(space.versions),
        status: "only_in_space",
        affectedCves: [],
        spaceVersionUnverified: space.unverified,
      });
    } else if (local) {
      items.push({
        package: pkgName,
        ecosystem,
        localVersion: fmt(local.versions),
        spaceVersion: null,
        status: "only_in_local",
        affectedCves: [],
      });
    }
  }

  const hasDrift = items.length > 0 || lockfileMissingInSpace;
  const unverifiedNote = items.some((i) => i.spaceVersionUnverified)
    ? " Some Space versions are only range floors (no lockfile on the Space), so they may differ from what is actually installed."
    : "";
  const summary = !hasDrift
    ? "Local workspace and Spacefast deployment dependencies are in sync."
    : `Detected ${items.length} package drift item(s)${lockfileMissingInSpace ? " and a missing lockfile on the Space" : ""}.${unverifiedNote}`;

  return { hasDrift, lockfileMissingInSpace, items, summary };
}

// ---------------------------------------------------------------------------
// Unified diff (small LCS line diff; package.json files are tiny)
// ---------------------------------------------------------------------------

export function createUnifiedDiff(path: string, before: string, after: string, context = 3): string {
  if (before === after) return "";
  const a = before.split("\n");
  const b = after.split("\n");
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  type Op = { type: " " | "-" | "+"; text: string; ai: number; bi: number };
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      ops.push({ type: " ", text: a[i]!, ai: i, bi: j });
      i += 1;
      j += 1;
    } else if (i < n && (j >= m || lcs[i + 1]![j]! >= lcs[i]![j + 1]!)) {
      // Deletions before insertions (conventional unified diff ordering).
      ops.push({ type: "-", text: a[i]!, ai: i, bi: j });
      i += 1;
    } else {
      ops.push({ type: "+", text: b[j]!, ai: i, bi: j });
      j += 1;
    }
  }

  const out = [`--- a/${path}`, `+++ b/${path}`];
  let idx = 0;
  while (idx < ops.length) {
    while (idx < ops.length && ops[idx]!.type === " ") idx += 1;
    if (idx >= ops.length) break;
    const start = Math.max(0, idx - context);
    let end = idx;
    let lastChange = idx;
    while (end < ops.length && end - lastChange <= context * 2) {
      if (ops[end]!.type !== " ") lastChange = end;
      end += 1;
    }
    end = Math.min(ops.length, lastChange + context + 1);
    const hunk = ops.slice(start, end);
    const aStart = hunk[0]!.ai + 1;
    const bStart = hunk[0]!.bi + 1;
    const aLen = hunk.filter((o) => o.type !== "+").length;
    const bLen = hunk.filter((o) => o.type !== "-").length;
    out.push(`@@ -${aLen === 0 ? aStart - 1 : aStart},${aLen} +${bLen === 0 ? bStart - 1 : bStart},${bLen} @@`);
    for (const op of hunk) out.push(`${op.type}${op.text}`);
    idx = end;
  }
  return out.join("\n");
}

function pickRootPackageJson(files: SpaceFileInput[]): SpaceFileInput | undefined {
  return files
    .filter((f) => {
      const p = normalizePath(f.path);
      return (p === "package.json" || p.endsWith("/package.json")) && !/(^|\/)node_modules\//.test(p);
    })
    .sort((x, y) => normalizePath(x.path).split("/").length - normalizePath(y.path).split("/").length)[0];
}

function detectOverrideField(files: SpaceFileInput[]): NonNullable<RemediationPlan["overrideField"]> {
  const bases = files.map((f) => normalizePath(f.path).split("/").pop());
  if (bases.includes("pnpm-lock.yaml")) return "pnpm.overrides";
  if (bases.includes("yarn.lock")) return "resolutions";
  return "overrides";
}

/**
 * Generates an actionable, deterministic `package.json` remediation patch and a real unified
 * diff (with @@ hunks) that can be applied to a Space via the Spacefast MCP (`edit-space`).
 */
export function planSpaceRemediation(
  files: SpaceFileInput[],
  findings: PrioritizedFinding[],
): RemediationPlan {
  const upgrades = new Map<string, RemediationAction>();
  const unfixed = new Map<string, UnfixedFinding & { symbols: Set<string> }>();

  // Where each npm package is loaded from: package.json / lockfile, and/or CDN URLs.
  const managedNames = new Set(
    parseSpaceInventory(files.filter((f) => NPM_MANIFEST_OR_LOCK.test(normalizePath(f.path))))
      .components.filter((c) => c.ecosystem === "npm")
      .map((c) => c.name),
  );
  const cdnRefs = files.flatMap((f) =>
    parseCdnReferences(f.content, normalizePath(f.path)).components.map((c) => ({
      name: c.name,
      version: c.version,
      url: c.cdnUrl ?? "",
      file: c.sourceFile,
    })),
  );

  for (const finding of findings) {
    if (finding.verdict === "rejected") continue;
    const fixVer = finding.advisory.recommendedFixVersion;
    if (!fixVer) {
      const adv = finding.advisory;
      const key = `${adv.ecosystem}:${adv.package}@${adv.installedVersion}`;
      const entry =
        unfixed.get(key) ??
        ({
          package: adv.package,
          ecosystem: adv.ecosystem,
          installedVersion: adv.installedVersion,
          advisoryIds: [],
          priorityScore: 0,
          reason: adv.fixedVersions.length === 0 ? "no_patched_version" : "installed_branch_not_covered",
          mitigations: [],
          symbols: new Set<string>(),
        } as UnfixedFinding & { symbols: Set<string> });
      if (!entry.advisoryIds.includes(adv.id)) entry.advisoryIds.push(adv.id);
      entry.priorityScore = Math.max(entry.priorityScore, finding.priorityScore);
      finding.reachability.calledSymbols.forEach((s) => entry.symbols.add(s));
      unfixed.set(key, entry);
      continue;
    }
    const key = `${finding.advisory.ecosystem}:${finding.advisory.package}`;
    const existing = upgrades.get(key);
    if (!existing) {
      upgrades.set(key, {
        package: finding.advisory.package,
        ecosystem: finding.advisory.ecosystem,
        fromVersion: finding.advisory.installedVersion,
        toVersion: fixVer,
        fixesAdvisories: [finding.advisory.id],
        priorityScore: finding.priorityScore,
      });
    } else {
      // One manifest entry can only hold one version: take the highest required fix.
      if (compareSemver(fixVer, existing.toVersion) > 0) existing.toVersion = fixVer;
      if (compareSemver(finding.advisory.installedVersion, existing.fromVersion) < 0) {
        existing.fromVersion = finding.advisory.installedVersion;
      }
      if (!existing.fixesAdvisories.includes(finding.advisory.id)) existing.fixesAdvisories.push(finding.advisory.id);
      existing.priorityScore = Math.max(existing.priorityScore, finding.priorityScore);
    }
  }

  const actions = [...upgrades.values()].sort((a, b) => b.priorityScore - a.priorityScore);
  const manualActions = actions.filter((a) => a.ecosystem !== "npm");

  // CDN-loaded copies are fixed by editing the URL, not package.json.
  const cdnUpdates: CdnUpdate[] = [];
  for (const act of actions.filter((a) => a.ecosystem === "npm")) {
    for (const ref of cdnRefs) {
      if (ref.name !== act.package || compareSemver(ref.version, act.toVersion) >= 0) continue;
      const suggestedUrl = ref.url.includes(`@${ref.version}`)
        ? ref.url.replace(`@${ref.version}`, `@${act.toVersion}`)
        : ref.url.replace(`/${ref.version}/`, `/${act.toVersion}/`);
      cdnUpdates.push({
        package: act.package,
        fromVersion: ref.version,
        toVersion: act.toVersion,
        file: ref.file,
        currentUrl: ref.url,
        suggestedUrl,
        fixesAdvisories: act.fixesAdvisories,
      });
    }
  }
  const cdnOnly = new Set(cdnUpdates.map((u) => u.package).filter((name) => !managedNames.has(name)));
  // package.json only gets packages it actually manages (never CDN-only ones as bogus overrides).
  const npmActions = actions.filter((a) => a.ecosystem === "npm" && !cdnOnly.has(a.package));

  const unfixedFindings: UnfixedFinding[] = [...unfixed.values()]
    .map(({ symbols, ...rest }) => ({
      ...rest,
      mitigations: unfixedMitigations(rest.package, [...symbols], cdnRefs.some((r) => r.name === rest.package)),
    }))
    .sort((a, b) => b.priorityScore - a.priorityScore);

  const pkgFile = pickRootPackageJson(files);
  let updatedPackageJson: string | null = null;
  let unifiedDiff = "";
  let overrideField: RemediationPlan["overrideField"] = null;

  if (pkgFile && npmActions.length > 0) {
    try {
      const parsed = JSON.parse(pkgFile.content) as Record<string, unknown>;
      const indentMatch = pkgFile.content.match(/\n([ \t]+)"/);
      const indent = indentMatch?.[1] ?? "  ";
      const field = detectOverrideField(files);

      for (const act of npmActions) {
        let updatedDirect = false;
        for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
          const deps = parsed[section] as Record<string, string> | undefined;
          if (deps && typeof deps === "object" && act.package in deps) {
            deps[act.package] = act.toVersion;
            updatedDirect = true;
          }
        }
        if (!updatedDirect) {
          overrideField = field;
          let target: Record<string, string>;
          if (field === "pnpm.overrides") {
            const pnpm = (parsed.pnpm as Record<string, unknown> | undefined) ?? {};
            parsed.pnpm = pnpm;
            target = (pnpm.overrides as Record<string, string> | undefined) ?? {};
            pnpm.overrides = target;
          } else {
            target = (parsed[field] as Record<string, string> | undefined) ?? {};
            parsed[field] = target;
          }
          target[act.package] = act.toVersion;
        }
      }

      const trailingNewline = pkgFile.content.endsWith("\n") ? "\n" : "";
      updatedPackageJson = `${JSON.stringify(parsed, null, indent)}${trailingNewline}`;
      // Diff against the original text normalized the same way, so formatting noise never appears as a change.
      const normalizedOriginal = `${JSON.stringify(JSON.parse(pkgFile.content), null, indent)}${trailingNewline}`;
      unifiedDiff = createUnifiedDiff(normalizePath(pkgFile.path), normalizedOriginal, updatedPackageJson);
    } catch {
      updatedPackageJson = null;
      unifiedDiff = "";
    }
  }

  const spacefastPublishNotes = [
    "1. Show the unifiedDiff to the user and get explicit approval before modifying the Space.",
    "2. Use the Spacefast MCP (https://mcp.spacefast.com, edit-space workflow) to write the updated package.json to the Space.",
    "3. Regenerate the lockfile in the SAME change (package-lock.json / pnpm-lock.yaml / yarn.lock). A package.json change without a matching lockfile makes `npm ci` / frozen-lockfile installs fail.",
    "4. Trigger a Spacefast build/publish and verify the deployment; if a major upgrade breaks the build, follow the fix-deployment workflow.",
    "5. Re-run scan_space_full (and probe_live_space) to prove the confirmed findings are gone.",
  ];
  if (manualActions.length > 0) {
    spacefastPublishNotes.push(
      `${manualActions.length} non-npm upgrade(s) (${[...new Set(manualActions.map((a) => a.ecosystem))].join(", ")}) must be applied manually in their own manifest; no automatic patch was generated.`,
    );
  }
  if (cdnUpdates.length > 0) {
    spacefastPublishNotes.push(
      `${cdnUpdates.length} CDN URL(s) must be edited in place (see cdnUpdates: file, currentUrl, suggestedUrl); the package.json diff does not change what the browser loads from a CDN.`,
    );
  }
  if (unfixedFindings.length > 0) {
    spacefastPublishNotes.push(
      `${unfixedFindings.reduce((n, u) => n + u.advisoryIds.length, 0)} advisory(ies) in ${unfixedFindings.length} package(s) have NO fix in this plan (see unfixedFindings). Tell the user explicitly that applying the diff does not resolve them, and present the mitigations.`,
    );
  }

  return {
    actions,
    updatedPackageJson,
    packageJsonPath: updatedPackageJson && pkgFile ? normalizePath(pkgFile.path) : null,
    overrideField,
    unifiedDiff,
    manualActions,
    unfixedFindings,
    cdnUpdates,
    spacefastPublishNotes,
  };
}

/**
 * Builds the Cloudflare `security-audit-skill` Phase 1/4 Coverage Ledger so the user can see
 * exactly which files were audited, which lockfiles were verified, and what blind spots remain.
 */
export function buildCoverageLedger(
  files: SpaceFileInput[],
  inventory: InventoryReport,
  liveUrlProbed: boolean,
  dataGaps: string[] = [],
): CoverageLedger {
  const auditedSourceFiles: string[] = [];
  const skippedOrUnverifiedFiles: string[] = [];
  const blindSpots: string[] = [];

  for (const file of files) {
    const p = normalizePath(file.path);
    if (/\.(png|jpg|jpeg|gif|webp|avif|ico|woff|woff2|ttf|eot|mp4|webm|pdf)$/i.test(p)) {
      skippedOrUnverifiedFiles.push(p);
    } else if (!inventory.manifestFiles.includes(file.path) && !inventory.lockfiles.includes(file.path)) {
      auditedSourceFiles.push(p);
    }
  }

  for (const eco of inventory.missingLockfileFor) {
    blindSpots.push(
      `No parsed lockfile for ${eco}. Transitive dependencies and exact resolved versions could not be verified (needs_validation).`,
    );
  }
  for (const f of inventory.unparsedLockfiles) {
    blindSpots.push(`Dependency file ${f} was provided but could not be parsed (unknown format or corrupt); its packages were NOT audited.`);
  }
  for (const f of inventory.unsupportedManifests) {
    blindSpots.push(`Manifest ${f} is not supported by this engine; its dependencies were NOT audited.`);
  }
  for (const gap of dataGaps) {
    blindSpots.push(`Upstream data gap: ${gap}`);
  }
  if (!liveUrlProbed) {
    blindSpots.push(
      "No live https://<name>.space.fast URL was probed. Live HTTP security headers and static file exposure (/.env, /.git/HEAD) were not checked against the running deployment.",
    );
  }

  return {
    totalFilesProvided: files.length,
    auditedManifests: inventory.manifestFiles,
    auditedLockfiles: inventory.lockfiles.filter((l) => !inventory.unparsedLockfiles.includes(l)),
    auditedSourceFiles,
    skippedOrUnverifiedFiles,
    liveUrlProbed,
    dataGaps,
    blindSpots,
  };
}
