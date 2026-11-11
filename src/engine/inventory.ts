import type { DependencyComponent, Ecosystem, InventoryReport, SpaceFileInput } from "../types.js";

function makePurl(ecosystem: Ecosystem, name: string, version: string): string {
  const cleanVersion = encodeURIComponent(version);
  if (ecosystem === "npm") {
    if (name.startsWith("@")) {
      const [scope, pkg] = name.split("/");
      return `pkg:npm/${encodeURIComponent(scope ?? "")}/${encodeURIComponent(pkg ?? "")}@${cleanVersion}`;
    }
    return `pkg:npm/${encodeURIComponent(name)}@${cleanVersion}`;
  }
  return `pkg:${ecosystem}/${encodeURIComponent(name)}@${cleanVersion}`;
}

export function normalizePath(p: string): string {
  return p.replace(/\\/g, "/");
}

function baseName(p: string): string {
  return normalizePath(p).split("/").pop() ?? p;
}

function isInsideNodeModules(p: string): boolean {
  return /(^|\/)node_modules\//.test(normalizePath(p));
}

export function isExactVersion(spec: string): boolean {
  const trimmed = spec.trim().replace(/^=/, "").replace(/^v(?=\d)/, "");
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(trimmed);
}

export function extractFloorVersion(spec: string): string | null {
  const trimmed = spec.trim();
  if (isExactVersion(trimmed)) return trimmed.replace(/^=/, "").replace(/^v(?=\d)/, "");
  const match = trimmed.match(/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/);
  return match?.[1] ?? null;
}

/** Local / non-registry specifiers that can never match an OSV advisory. */
function isLocalSpecifier(spec: string): boolean {
  return /^(workspace:|link:|file:|portal:|\.{0,2}\/)/.test(spec.trim());
}

// ---------------------------------------------------------------------------
// npm lockfiles
// ---------------------------------------------------------------------------

function parsePackageLockJson(content: string, sourceFile: string): DependencyComponent[] {
  const out: DependencyComponent[] = [];
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return out;
  }

  const packages = parsed.packages as Record<string, Record<string, unknown>> | undefined;
  if (packages && typeof packages === "object") {
    for (const [pkgPath, meta] of Object.entries(packages)) {
      // Root ("") and local workspace folders are not registry packages.
      if (!pkgPath || !pkgPath.includes("node_modules/")) continue;
      if (meta?.link === true) continue;
      const version = typeof meta?.version === "string" ? meta.version : null;
      if (!version) continue;
      const inferredName = pkgPath.slice(pkgPath.lastIndexOf("node_modules/") + "node_modules/".length);
      const name = typeof meta?.name === "string" ? meta.name : inferredName;
      if (!name) continue;
      out.push({
        ecosystem: "npm",
        name,
        version,
        pinned: true,
        devOnly: meta?.dev === true,
        sourceFile,
        purl: makePurl("npm", name, version),
      });
    }
  }

  // lockfileVersion 1
  if (out.length === 0 && parsed.dependencies && typeof parsed.dependencies === "object") {
    const walk = (deps: Record<string, Record<string, unknown>>) => {
      for (const [name, meta] of Object.entries(deps)) {
        const version = typeof meta?.version === "string" ? meta.version : null;
        if (version && /^\d/.test(version)) {
          out.push({
            ecosystem: "npm",
            name,
            version,
            pinned: true,
            devOnly: meta?.dev === true,
            sourceFile,
            purl: makePurl("npm", name, version),
          });
        }
        if (meta?.dependencies && typeof meta.dependencies === "object") {
          walk(meta.dependencies as Record<string, Record<string, unknown>>);
        }
      }
    };
    walk(parsed.dependencies as Record<string, Record<string, unknown>>);
  }
  return out;
}

function parsePnpmLockYaml(content: string, sourceFile: string): DependencyComponent[] {
  const out: DependencyComponent[] = [];
  const seen = new Map<string, DependencyComponent>();
  let section = "";
  let current: DependencyComponent | null = null;

  const add = (name: string, version: string) => {
    const key = `${name}@${version}`;
    const existing = seen.get(key);
    if (existing) {
      current = existing;
      return;
    }
    const comp: DependencyComponent = {
      ecosystem: "npm",
      name,
      version,
      pinned: true,
      devOnly: false,
      sourceFile,
      purl: makePurl("npm", name, version),
    };
    seen.set(key, comp);
    out.push(comp);
    current = comp;
  };

  for (const rawLine of content.split(/\r?\n/)) {
    const top = rawLine.match(/^([A-Za-z]+):/);
    if (top) {
      section = top[1] ?? "";
      current = null;
      continue;
    }
    if (section !== "packages" && section !== "snapshots") continue;

    // pnpm v6+: `  /pkg@1.2.3:` , `  /@scope/pkg@1.2.3(peer):` , v9: `  'pkg@1.2.3':`
    const atForm = rawLine.match(/^ {2}['"]?\/?((?:@[^@/'":\s]+\/)?[^@/'":\s]+)@(\d+\.\d+\.\d+[^('":\s]*)/);
    if (atForm?.[1] && atForm[2]) {
      add(atForm[1], atForm[2]);
      continue;
    }
    // pnpm v5: `  /pkg/1.2.3:` or `  /@scope/pkg/1.2.3_peer:`
    const slashForm = rawLine.match(/^ {2}\/((?:@[^/'":\s]+\/)?[^/'":\s]+)\/(\d+\.\d+\.\d+[^_('":\s]*)/);
    if (slashForm?.[1] && slashForm[2]) {
      add(slashForm[1], slashForm[2]);
      continue;
    }
    if (/^ {2}\S/.test(rawLine)) {
      current = null;
      continue;
    }
    if (current && /^ {4}dev:\s*true\b/.test(rawLine)) {
      (current as DependencyComponent).devOnly = true;
    }
  }
  return out;
}

function parseYarnLock(content: string, sourceFile: string): DependencyComponent[] {
  const out: DependencyComponent[] = [];
  let currentNames: string[] = [];
  for (const line of content.split(/\r?\n/)) {
    if (line && !line.startsWith(" ") && !line.startsWith("#") && line.trimEnd().endsWith(":")) {
      const header = line.trimEnd().slice(0, -1);
      currentNames = header
        .split(",")
        .map((part) => part.trim().replace(/^['"]|['"]$/g, ""))
        .map((spec) => {
          // First "@" after position 0 separates name from range/protocol (handles @scope/name).
          const atIdx = spec.indexOf("@", 1);
          if (atIdx <= 0) return "";
          const range = spec.slice(atIdx + 1);
          if (/^(workspace|link|portal|file):/.test(range)) return "";
          return spec.slice(0, atIdx);
        })
        .filter(Boolean);
    } else if (currentNames.length > 0) {
      // yarn v1: `  version "1.2.3"`   yarn berry: `  version: 1.2.3`
      const verMatch = line.match(/^\s+version:?\s+["']?(\d+\.\d+\.\d+[^"'\s]*)["']?/);
      if (verMatch?.[1]) {
        const version = verMatch[1];
        for (const name of new Set(currentNames)) {
          out.push({
            ecosystem: "npm",
            name,
            version,
            pinned: true,
            devOnly: false,
            sourceFile,
            purl: makePurl("npm", name, version),
          });
        }
        currentNames = [];
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Other ecosystems
// ---------------------------------------------------------------------------

function parseRequirementsTxt(content: string, sourceFile: string): {
  components: DependencyComponent[];
  unpinned: InventoryReport["unpinnedWarnings"];
  looksCompiled: boolean;
} {
  const components: DependencyComponent[] = [];
  const unpinned: InventoryReport["unpinnedWarnings"] = [];
  // pip-compile / uv export output pins the full transitive tree and annotates with "# via".
  const looksCompiled = /^\s+#\s+via\b/m.test(content) || /^#.*pip-compile/m.test(content);

  for (const rawLine of content.split(/\r?\n/)) {
    const line = (rawLine.split(" #")[0] ?? "").replace(/^#.*$/, "").split(";")[0]?.trim() ?? "";
    if (!line || line.startsWith("--hash")) continue;
    if (line.startsWith("-") || line.includes("://") || / @ /.test(line)) {
      unpinned.push({
        package: line.split(/\s+/)[0] ?? line,
        rawRange: line,
        sourceFile,
        reason: "Requirement line (include/editable/URL/VCS) cannot be resolved to an exact registry version (needs_validation).",
      });
      continue;
    }
    const exactMatch = line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9_.+!-]+)\s*(?:\\)?$/);
    if (exactMatch?.[1] && exactMatch[2] && !exactMatch[2].includes("*")) {
      const name = exactMatch[1].toLowerCase();
      const version = exactMatch[2];
      components.push({
        ecosystem: "pypi",
        name,
        version,
        rawRange: line,
        pinned: true,
        devOnly: false,
        direct: true,
        sourceFile,
        purl: makePurl("pypi", name, version),
      });
      continue;
    }
    const nameMatch = line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(.*)$/);
    if (!nameMatch?.[1]) continue;
    const name = nameMatch[1].toLowerCase();
    const rest = nameMatch[2] ?? "";
    unpinned.push({
      package: name,
      rawRange: line,
      sourceFile,
      reason: rest
        ? "Unpinned Python dependency range; exact installed version cannot be verified without a lockfile."
        : "Python dependency without any version constraint; installed version is unknown (needs_validation).",
    });
    const floor = rest.match(/(?:>=|~=|==)\s*([0-9][A-Za-z0-9_.+-]*)/)?.[1];
    if (floor) {
      components.push({
        ecosystem: "pypi",
        name,
        version: floor,
        rawRange: line,
        pinned: false,
        devOnly: false,
        direct: true,
        sourceFile,
        purl: makePurl("pypi", name, floor),
      });
    }
  }
  return { components, unpinned, looksCompiled };
}

function parseCargoLock(content: string, sourceFile: string): DependencyComponent[] {
  const out: DependencyComponent[] = [];
  for (const block of content.split(/\[\[package\]\]/).slice(1)) {
    const nameMatch = block.match(/^\s*name\s*=\s*"([^"]+)"/m);
    const versionMatch = block.match(/^\s*version\s*=\s*"([^"]+)"/m);
    // Packages without `source` are local workspace crates, not crates.io packages.
    if (!/^\s*source\s*=/m.test(block)) continue;
    if (nameMatch?.[1] && versionMatch?.[1]) {
      out.push({
        ecosystem: "cargo",
        name: nameMatch[1],
        version: versionMatch[1],
        pinned: true,
        devOnly: false,
        sourceFile,
        purl: makePurl("cargo", nameMatch[1], versionMatch[1]),
      });
    }
  }
  return out;
}

function parseGoMod(content: string, sourceFile: string): DependencyComponent[] {
  const out: DependencyComponent[] = [];
  let inRequireBlock = false;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.split("//")[0]?.trim() ?? "";
    if (/^require\s*\($/.test(line)) {
      inRequireBlock = true;
      continue;
    }
    if (inRequireBlock && line === ")") {
      inRequireBlock = false;
      continue;
    }
    const match = inRequireBlock
      ? line.match(/^([a-zA-Z0-9._~/-]+\.[a-zA-Z0-9._~/-]+)\s+v(\d+\.\d+\.\d+\S*)$/)
      : line.match(/^require\s+([a-zA-Z0-9._~/-]+\.[a-zA-Z0-9._~/-]+)\s+v(\d+\.\d+\.\d+\S*)$/);
    if (match?.[1] && match[2]) {
      out.push({
        ecosystem: "golang",
        name: match[1],
        version: match[2],
        pinned: true,
        devOnly: false,
        direct: !/\/\/\s*indirect/.test(rawLine),
        sourceFile,
        purl: makePurl("golang", match[1], match[2]),
      });
    }
  }
  return out;
}

const UNSUPPORTED_MANIFESTS = new Set([
  "pyproject.toml",
  "poetry.lock",
  "Pipfile",
  "Pipfile.lock",
  "uv.lock",
  "composer.json",
  "composer.lock",
  "Gemfile.lock",
  "bun.lockb",
  "bun.lock",
]);

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function parseSpaceInventory(files: SpaceFileInput[]): InventoryReport {
  const components: DependencyComponent[] = [];
  const unpinnedWarnings: InventoryReport["unpinnedWarnings"] = [];
  const manifestFiles: string[] = [];
  const lockfiles: string[] = [];
  const unparsedLockfiles: string[] = [];
  const unsupportedManifests: string[] = [];
  const lockedEcosystems = new Set<Ecosystem>();
  const ecosystemsWithManifest = new Set<Ecosystem>();

  const registerLock = (file: SpaceFileInput, eco: Ecosystem, parsed: DependencyComponent[]) => {
    lockfiles.push(file.path);
    if (parsed.length === 0 && file.content.trim().length > 0) {
      unparsedLockfiles.push(file.path);
    } else {
      lockedEcosystems.add(eco);
    }
    components.push(...parsed);
  };

  for (const file of files) {
    if (isInsideNodeModules(file.path)) continue;
    const base = baseName(file.path);
    if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
      registerLock(file, "npm", parsePackageLockJson(file.content, file.path));
    } else if (base === "pnpm-lock.yaml") {
      registerLock(file, "npm", parsePnpmLockYaml(file.content, file.path));
    } else if (base === "yarn.lock") {
      registerLock(file, "npm", parseYarnLock(file.content, file.path));
    } else if (base === "Cargo.lock") {
      registerLock(file, "cargo", parseCargoLock(file.content, file.path));
    } else if (base === "Cargo.toml") {
      manifestFiles.push(file.path);
      ecosystemsWithManifest.add("cargo");
    } else if (base === "go.mod") {
      // Since Go 1.17 go.mod lists the full module graph (incl. // indirect) at exact versions.
      manifestFiles.push(file.path);
      ecosystemsWithManifest.add("golang");
      lockedEcosystems.add("golang");
      components.push(...parseGoMod(file.content, file.path));
    } else if (base === "requirements.txt" || /^requirements[-_.].*\.txt$/.test(base)) {
      manifestFiles.push(file.path);
      ecosystemsWithManifest.add("pypi");
      const parsed = parseRequirementsTxt(file.content, file.path);
      components.push(...parsed.components);
      unpinnedWarnings.push(...parsed.unpinned);
      if (parsed.looksCompiled) lockedEcosystems.add("pypi");
    } else if (UNSUPPORTED_MANIFESTS.has(base)) {
      unsupportedManifests.push(file.path);
    }
  }

  const lockedNpmNames = new Set(
    components.filter((c) => c.ecosystem === "npm" && c.pinned).map((c) => c.name),
  );
  const directNpm = new Map<string, boolean>(); // name -> devOnly

  for (const file of files) {
    if (baseName(file.path) !== "package.json" || isInsideNodeModules(file.path)) continue;
    manifestFiles.push(file.path);
    let pkg: Record<string, unknown>;
    try {
      pkg = JSON.parse(file.content) as Record<string, unknown>;
    } catch {
      unparsedLockfiles.push(file.path);
      continue;
    }

    const sections: [unknown, boolean][] = [
      [pkg.dependencies, false],
      [pkg.optionalDependencies, false],
      [pkg.peerDependencies, false],
      [pkg.devDependencies, true],
    ];

    for (const [section, devOnly] of sections) {
      if (!section || typeof section !== "object") continue;
      for (const [declaredName, rawSpecUnknown] of Object.entries(section as Record<string, unknown>)) {
        if (typeof rawSpecUnknown !== "string") continue;
        if (isLocalSpecifier(rawSpecUnknown)) continue;
        ecosystemsWithManifest.add("npm");

        // npm alias: "foo": "npm:real-pkg@1.2.3"
        let name = declaredName;
        let rawSpec = rawSpecUnknown;
        const alias = rawSpec.match(/^npm:((?:@[^/@]+\/)?[^@]+)@(.+)$/);
        if (alias?.[1] && alias[2]) {
          name = alias[1];
          rawSpec = alias[2];
        }

        const prev = directNpm.get(name);
        directNpm.set(name, prev === undefined ? devOnly : prev && devOnly);

        const exact = isExactVersion(rawSpec);
        const floor = extractFloorVersion(rawSpec);
        const coveredByLockfile = lockedNpmNames.has(name);

        if (!exact && !coveredByLockfile) {
          unpinnedWarnings.push({
            package: name,
            rawRange: rawSpecUnknown,
            sourceFile: file.path,
            reason: floor
              ? "Dependency uses a range specifier in package.json without a lockfile resolution (fail-closed: needs_validation)."
              : "Dependency specifier (tag/git/URL/*) cannot be resolved to a version without a lockfile (fail-closed: needs_validation).",
          });
        }

        if (!coveredByLockfile && floor) {
          components.push({
            ecosystem: "npm",
            name,
            version: floor.replace(/^=/, ""),
            rawRange: rawSpecUnknown,
            pinned: exact,
            devOnly,
            sourceFile: file.path,
            purl: makePurl("npm", name, floor),
          });
        }
      }
    }
  }

  // Mark direct deps; a lockfile entry that is a direct prod dep is never devOnly.
  for (const comp of components) {
    if (comp.ecosystem !== "npm") continue;
    const dev = directNpm.get(comp.name);
    if (dev !== undefined) {
      comp.direct = true;
      if (!dev) comp.devOnly = false;
    }
  }

  // Deduplicate by ecosystem+name+version while preserving the most conservative flags.
  const deduped = new Map<string, DependencyComponent>();
  for (const comp of components) {
    const key = `${comp.ecosystem}:${comp.name}@${comp.version}`;
    const existing = deduped.get(key);
    if (!existing) {
      deduped.set(key, { ...comp });
      continue;
    }
    existing.pinned = existing.pinned || comp.pinned;
    existing.devOnly = existing.devOnly && comp.devOnly;
    existing.direct = Boolean(existing.direct || comp.direct);
  }

  const missingLockfileFor = [...ecosystemsWithManifest].filter((eco) => !lockedEcosystems.has(eco));

  return {
    components: [...deduped.values()],
    unpinnedWarnings,
    hasLockfile: lockedEcosystems.size > 0,
    manifestFiles,
    lockfiles,
    unparsedLockfiles,
    missingLockfileFor,
    unsupportedManifests,
  };
}
