import type {
  CodeAndSecretFinding,
  CodeFindingCategory,
  Severity,
  SpaceFileInput,
  Verdict,
} from "../types.js";

interface PatternRule {
  ruleId: string;
  category: CodeFindingCategory;
  severity: Severity;
  verdict: Verdict;
  title: string;
  regex: RegExp;
  isSecret?: boolean;
  remediationHint: string;
  /** Receives the matched token so guards judge the match itself, not the whole line. */
  falsePositiveGuard?: (line: string, filePath: string, match: string) => boolean;
}

function maskToken(token: string): string {
  if (token.length < 10) return "[REDACTED]";
  return `${token.slice(0, 4)}${"*".repeat(Math.min(12, Math.max(4, token.length - 6)))}${token.slice(-2)}`;
}

/**
 * Redacts a single secret value in a line of text. Kept for backwards compatibility;
 * prefer `redactSnippet`, which masks EVERY secret on the line.
 */
export function redactSecretInLine(line: string, match: string): string {
  if (!match) return line.trim().slice(0, 220);
  return redactAllSecrets(line.split(match).join(maskToken(match))).trim().slice(0, 220);
}

/** Masks every token matched by any secret rule (global), so one finding never leaks another secret on the same line. */
export function redactAllSecrets(line: string): string {
  let out = line;
  for (const rule of SECRET_RULES_GLOBAL) {
    out = out.replace(rule, (full: string, group1?: string) => {
      const token = typeof group1 === "string" && group1 ? group1 : full;
      return full.split(token).join(maskToken(token));
    });
  }
  return out;
}

/**
 * Masks literal values on a line: `KEY=value`, `KEY: value` and quoted strings.
 * Used for rules whose purpose is "a secret value is here" even when the value
 * does not match a known provider pattern (VITE_*_SECRET=..., env || "fallback").
 */
function maskLiteralValues(line: string): string {
  return line
    .replace(/(["'`])([^"'`]{4,})\1/g, (_m, q: string, v: string) => `${q}${maskToken(v)}${q}`)
    .replace(/([=:]\s*)([^\s"'`;,)}\]]{6,})/g, (_m, pre: string, v: string) =>
      v.includes("*") ? `${pre}${v}` : `${pre}${maskToken(v)}`,
    );
}

function buildSnippet(line: string, rule: PatternRule): string {
  let out = redactAllSecrets(line);
  if (
    rule.isSecret ||
    rule.category === "client_bundle_secret_leak" ||
    rule.category === "insecure_default_fail_open"
  ) {
    out = maskLiteralValues(out);
  }
  return out.trim().slice(0, 220);
}

const SENSITIVE_FILE_PATTERNS: Array<{
  regex: RegExp;
  ruleId: string;
  severity: Severity;
  title: string;
  remediationHint: string;
}> = [
  {
    regex: /(^|\/)\.env(\.(local|production|development|staging))?$/i,
    ruleId: "SF-FILE-ENV",
    severity: "critical",
    title: "Dotenv configuration file present in Space bundle",
    remediationHint:
      "Remove .env files from the Spacefast workspace immediately. When deployed as static assets (especially via drop.fast), .env files can be publicly downloaded at https://<space>.space.fast/.env. Rotate all keys inside this file.",
  },
  {
    regex: /(^|\/)\.git\/(config|HEAD|credentials)$/i,
    ruleId: "SF-FILE-GIT",
    severity: "critical",
    title: "Exposed .git repository metadata in Space bundle",
    remediationHint:
      "Remove the .git directory from your deployed Space files so attackers cannot reconstruct source history and committed secrets.",
  },
  {
    regex: /(^|\/)(id_rsa|id_ed25519|.*\.pem|.*\.key)$/i,
    ruleId: "SF-FILE-PRIVKEY",
    severity: "critical",
    title: "Private key file included in Space bundle",
    remediationHint:
      "Delete private key files (.pem, .key, id_rsa, id_ed25519) from the Space immediately and revoke/rotate the key pair.",
  },
  {
    regex: /(^|\/)\.npmrc$/i,
    ruleId: "SF-FILE-NPMRC",
    severity: "high",
    title: ".npmrc file included in Space bundle",
    remediationHint:
      "Remove .npmrc from the deployed Space if it contains _authToken or private registry tokens.",
  },
  {
    regex: /\.(sqlite|sqlite3|db)$/i,
    ruleId: "SF-FILE-DB",
    severity: "high",
    title: "Embedded SQLite database file included in Space bundle",
    remediationHint:
      "Ensure SQLite database files are not served inside the public static web root of the Space.",
  },
  {
    regex: /\.js\.map$/i,
    ruleId: "SF-FILE-SOURCEMAP",
    severity: "low",
    title: "Production JavaScript source map (.js.map) exposed",
    remediationHint:
      "Disable production source maps (e.g. build.sourcemap = false in vite.config.ts) or delete *.js.map files before deploying to Spacefast so original unminified source code and comments are not exposed.",
  },
];

const PATTERN_RULES: PatternRule[] = [
  // 1. Secret Detection Rules (Semgrep + SecMon)
  {
    ruleId: "SF-SEC-OPENAI",
    category: "hardcoded_secret",
    severity: "critical",
    verdict: "confirmed",
    title: "Hardcoded OpenAI API Key",
    regex: /\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,})\b/,
    isSecret: true,
    remediationHint:
      "Revoke this OpenAI API key immediately, remove it from client/repo files, and route AI requests through a backend endpoint using server-side secrets.",
  },
  {
    ruleId: "SF-SEC-ANTHROPIC",
    category: "hardcoded_secret",
    severity: "critical",
    verdict: "confirmed",
    title: "Hardcoded Anthropic API Key",
    regex: /\b(sk-ant-api03-[A-Za-z0-9_-]{20,})\b/,
    isSecret: true,
    remediationHint:
      "Revoke this Anthropic API key in the Anthropic Console and move Claude API calls to a secure backend Worker.",
  },
  {
    ruleId: "SF-SEC-AWS",
    category: "hardcoded_secret",
    severity: "critical",
    verdict: "confirmed",
    title: "Hardcoded AWS Access Key ID",
    regex: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/,
    isSecret: true,
    remediationHint:
      "Deactivate this AWS IAM access key in AWS IAM Console immediately and rotate credentials.",
  },
  {
    ruleId: "SF-SEC-GITHUB",
    category: "hardcoded_secret",
    severity: "critical",
    verdict: "confirmed",
    title: "Hardcoded GitHub Personal Access Token",
    regex: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})\b/,
    isSecret: true,
    remediationHint:
      "Revoke the GitHub token in GitHub Developer Settings and remove it from the Space codebase.",
  },
  {
    ruleId: "SF-SEC-SLACK",
    category: "hardcoded_secret",
    severity: "high",
    verdict: "confirmed",
    title: "Hardcoded Slack Bot/User Token",
    regex: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b/,
    isSecret: true,
    remediationHint:
      "Revoke the Slack token in the Slack App management portal and move webhook/API calls server-side.",
  },
  {
    ruleId: "SF-SEC-STRIPE",
    category: "hardcoded_secret",
    severity: "critical",
    verdict: "confirmed",
    title: "Hardcoded Stripe Live Secret / Restricted Key",
    regex: /\b((?:sk|rk)_live_[0-9a-zA-Z]{16,})\b/,
    isSecret: true,
    remediationHint:
      "Roll this Stripe live secret key immediately in the Stripe Dashboard. Never embed sk_live_ or rk_live_ keys in frontend code.",
  },
  {
    ruleId: "SF-SEC-PRIVATE-KEY",
    category: "hardcoded_secret",
    severity: "critical",
    verdict: "confirmed",
    title: "Embedded PEM Private Key Block",
    regex: /(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)/,
    isSecret: true,
    remediationHint:
      "Remove the private key block from source code and rotate the corresponding certificate/key.",
  },
  {
    ruleId: "SF-SEC-DB-URI",
    category: "hardcoded_secret",
    severity: "critical",
    verdict: "confirmed",
    title: "Database Connection URI with Embedded Credentials",
    regex: /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^/\s:@]+:[^/\s@]+@[^\s"']+)/i,
    isSecret: true,
    falsePositiveGuard: (_line, _path, match) =>
      /@(localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|redis|mongo)(:\d+)?(\/|$)/i.test(match) ||
      /:\/\/(user|username|postgres|root):(pass|password|postgres|secret|changeme)@/i.test(match) ||
      /\$\{|<[^>]+>/.test(match),
    remediationHint:
      "Rotate the database password immediately and never include database connection strings in Spacefast static/client files.",
  },

  // 2. Client-Side Bundle Secret Leakage (Vite / Next.js / CRA public env vars)
  {
    ruleId: "SF-BUNDLE-PUBLIC-SECRET",
    category: "client_bundle_secret_leak",
    severity: "critical",
    verdict: "confirmed",
    title: "Private Secret Exposed via Public Frontend Env Prefix (VITE_ / NEXT_PUBLIC_ / REACT_APP_)",
    regex:
      /\b((?:VITE|NEXT_PUBLIC|REACT_APP|PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|ADMIN_KEY|API_KEY|PASSWORD|TOKEN)[A-Z0-9_]*)\b/,
    isSecret: false,
    falsePositiveGuard: (line) =>
      /PUBLIC_SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY|VITE_SUPABASE_ANON_KEY|PUBLIC_POSTHOG_KEY|NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY/i.test(
        line,
      ),
    remediationHint:
      "Variables prefixed with VITE_, NEXT_PUBLIC_, REACT_APP_, or PUBLIC_ are compiled directly into the public JavaScript bundle sent to every browser visitor. Move this secret to a server-only environment variable without a public prefix.",
  },

  // 3. Trail of Bits `insecure-defaults` (Fail-Open Patterns)
  {
    ruleId: "SF-TOB-FAILOPEN-SECRET",
    category: "insecure_default_fail_open",
    severity: "high",
    verdict: "confirmed",
    title: "Fail-Open Secret Fallback (Trail of Bits insecure-defaults)",
    regex:
      /process\.env\.[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD)[A-Z0-9_]*\s*(?:\|\||\?\?)\s*["'`][^"'`]{1,80}["'`]/i,
    isSecret: false,
    remediationHint:
      "Do not fall back to a hardcoded default secret when an environment variable is missing (fail-open). Throw a startup error if the required secret environment variable is undefined (fail-closed).",
  },
  {
    ruleId: "SF-TOB-TLS-BYPASS",
    category: "insecure_default_fail_open",
    severity: "high",
    verdict: "confirmed",
    title: "TLS Certificate Verification Disabled (rejectUnauthorized: false / NODE_TLS_REJECT_UNAUTHORIZED=0)",
    regex: /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?)/,
    isSecret: false,
    remediationHint:
      "Enable strict TLS certificate verification (rejectUnauthorized: true) to prevent Man-in-the-Middle (MitM) interception.",
  },
  {
    ruleId: "SF-TOB-CORS-WILDCARD-CREDS",
    category: "insecure_default_fail_open",
    severity: "high",
    verdict: "needs_validation",
    title: "Overly Permissive CORS Wildcard Policy",
    regex: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']/i,
    isSecret: false,
    remediationHint:
      "Restrict Access-Control-Allow-Origin to explicit trusted origins (such as your https://<name>.space.fast domain) rather than '*'.",
  },

  // 4. Semgrep `code-security` OWASP Top 10 SAST Rules
  {
    ruleId: "SF-SAST-DANGEROUS-HTML",
    category: "owasp_code_pattern",
    severity: "high",
    verdict: "needs_validation",
    title: "Potential DOM XSS via dangerouslySetInnerHTML / innerHTML / v-html",
    regex: /(?:dangerouslySetInnerHTML\s*[:=]\s*\{\s*\{?\s*__html\s*:|\.innerHTML\s*=\s*(?!["'`]\s*["'`])|v-html\s*=)/,
    isSecret: false,
    falsePositiveGuard: (line) => line.includes("DOMPurify.sanitize") || line.includes("sanitizeHtml("),
    remediationHint:
      "Sanitize untrusted HTML with DOMPurify.sanitize(...) before rendering via dangerouslySetInnerHTML / innerHTML, or render plain text via React JSX expressions.",
  },
  {
    ruleId: "SF-SAST-DYNAMIC-EVAL",
    category: "owasp_code_pattern",
    severity: "high",
    verdict: "confirmed",
    title: "Dynamic Code Execution via eval() or new Function()",
    regex: /\b(?:eval\s*\(|new\s+Function\s*\()/,
    isSecret: false,
    remediationHint:
      "Replace eval() and new Function() with safe structured parsing (e.g. JSON.parse) or explicit dispatch tables.",
  },
  {
    ruleId: "SF-SAST-SQL-INTERPOLATION",
    category: "owasp_code_pattern",
    severity: "critical",
    verdict: "confirmed",
    title: "Raw SQL String Interpolation (Potential SQL Injection)",
    regex:
      /\b(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^;`\n]*\$\{[^}]+\}/i,
    isSecret: false,
    remediationHint:
      "Use parameterized queries / prepared statements ($1, ?) or safe ORM query builders instead of template literal interpolation (${...}) inside SQL strings.",
  },
  {
    ruleId: "SF-SAST-COMMAND-EXEC",
    category: "owasp_code_pattern",
    severity: "critical",
    verdict: "needs_validation",
    title: "Shell Command Execution via child_process.exec / execSync with Interpolation",
    regex: /\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/,
    isSecret: false,
    remediationHint:
      "Never pass interpolated strings to exec/execSync. Use execFile / spawn with a fixed command binary and an explicit argument array.",
  },
];

const SECRET_RULES_GLOBAL: RegExp[] = PATTERN_RULES.filter((r) => r.isSecret).map(
  (r) => new RegExp(r.regex.source, r.regex.flags.includes("g") ? r.regex.flags : `${r.regex.flags}g`),
);

export function isDocumentationFile(filePath: string): boolean {
  const p = filePath.replace(/\\/g, "/");
  return (
    /\.(md|mdx|markdown|txt|rst|adoc)$/i.test(p) ||
    /(^|\/)(docs?|README)\//i.test(p) ||
    /(^|\/)(CHANGELOG|LICENSE|README)(\.[a-z]+)?$/i.test(p)
  );
}

function isSkippedNonCodeFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    lower.endsWith("package-lock.json") ||
    lower.endsWith("pnpm-lock.yaml") ||
    lower.endsWith("yarn.lock") ||
    lower.endsWith("cargo.lock") ||
    lower.endsWith(".png") ||
    lower.endsWith(".jpg") ||
    lower.endsWith(".jpeg") ||
    lower.endsWith(".gif") ||
    lower.endsWith(".woff2") ||
    lower.endsWith(".ico")
  );
}

/**
 * Scans all provided Space files for:
 * 1. Sensitive exposed files (.env, .git, private keys, .js.map)
 * 2. Hardcoded API keys/tokens/credentials (with automatic redaction)
 * 3. Public frontend bundle env var leaks (VITE_*, NEXT_PUBLIC_*, REACT_APP_*)
 * 4. Trail of Bits `insecure-defaults` fail-open patterns
 * 5. Semgrep OWASP Top 10 SAST patterns (XSS, eval, SQLi, command injection)
 */
export function scanCodeAndSecrets(files: SpaceFileInput[]): CodeAndSecretFinding[] {
  const findings: CodeAndSecretFinding[] = [];

  for (const file of files) {
    const normalizedPath = file.path.replace(/\\/g, "/");

    // 1. Check sensitive file presence first
    for (const fileRule of SENSITIVE_FILE_PATTERNS) {
      if (fileRule.regex.test(normalizedPath)) {
        findings.push({
          id: `${fileRule.ruleId}:${normalizedPath}`,
          ruleId: fileRule.ruleId,
          category: "exposed_sensitive_file",
          severity: fileRule.severity,
          verdict: "confirmed",
          title: fileRule.title,
          description: `The file '${normalizedPath}' was found inside the Space project tree. Static hosting or drag-and-drop deployments can expose this file directly over HTTP.`,
          file: normalizedPath,
          line: 1,
          snippetRedacted: `File present in Space bundle: ${normalizedPath}`,
          remediationHint: fileRule.remediationHint,
        });
      }
    }

    if (isSkippedNonCodeFile(normalizedPath)) {
      continue;
    }

    // Documentation (README.md, docs/, Spacefast's rendered README/ page) only gets secret rules:
    // code-pattern rules there match prose and examples, not executed code.
    const docsOnly = isDocumentationFile(normalizedPath);

    const lines = file.content.split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx] ?? "";
      const lineNumber = idx + 1;
      const trimmed = line.trim();

      if (docsOnly || !trimmed || trimmed.startsWith("//") || trimmed.startsWith("#")) {
        for (const rule of PATTERN_RULES) {
          if (!rule.isSecret) continue;
          const match = rule.regex.exec(line);
          if (match) {
            const secretMatch = match[1] ?? match[0];
            if (rule.falsePositiveGuard && rule.falsePositiveGuard(line, normalizedPath, secretMatch)) {
              continue;
            }
            findings.push({
              id: `${rule.ruleId}:${normalizedPath}:${lineNumber}`,
              ruleId: rule.ruleId,
              category: rule.category,
              severity: rule.severity,
              verdict: rule.verdict,
              title: rule.title,
              description: docsOnly
                ? `${rule.title} detected in documentation at ${normalizedPath}:${lineNumber}. Documentation files are often deployed and publicly readable.`
                : `${rule.title} detected in comment at ${normalizedPath}:${lineNumber}. Even commented-out secrets are shipped to browsers in unminified builds or source maps.`,
              file: normalizedPath,
              line: lineNumber,
              snippetRedacted: buildSnippet(line, rule),
              remediationHint: rule.remediationHint,
            });
          }
        }
        continue;
      }

      for (const rule of PATTERN_RULES) {
        const match = rule.regex.exec(line);
        if (!match) continue;
        const matchedToken = match[1] ?? match[0];
        if (rule.falsePositiveGuard && rule.falsePositiveGuard(line, normalizedPath, matchedToken)) {
          continue;
        }
        const snippetRedacted = buildSnippet(line, rule);

        findings.push({
          id: `${rule.ruleId}:${normalizedPath}:${lineNumber}`,
          ruleId: rule.ruleId,
          category: rule.category,
          severity: rule.severity,
          verdict: rule.verdict,
          title: rule.title,
          description: `${rule.title} detected at ${normalizedPath}:${lineNumber}.`,
          file: normalizedPath,
          line: lineNumber,
          snippetRedacted,
          remediationHint: rule.remediationHint,
        });
      }
    }

    // Third-party <script src> without Subresource Integrity (HTML only, never docs).
    if (!docsOnly && /\.html?$/i.test(normalizedPath)) {
      for (const m of file.content.matchAll(/<script\b[^>]*\bsrc\s*=\s*["'](https?:)?\/\/[^"']+["'][^>]*>/gi)) {
        const tag = m[0];
        if (/\bintegrity\s*=/i.test(tag)) continue;
        const lineNumber = file.content.slice(0, m.index ?? 0).split(/\r?\n/).length;
        findings.push({
          id: `SF-SRI-MISSING:${normalizedPath}:${lineNumber}`,
          ruleId: "SF-SRI-MISSING",
          category: "insecure_default_fail_open",
          severity: "low",
          verdict: "needs_validation",
          title: "Third-party script loaded without Subresource Integrity",
          description: `${normalizedPath}:${lineNumber} loads a script from another origin without an integrity hash. If that CDN or package is compromised, the modified code runs on the Space.`,
          file: normalizedPath,
          line: lineNumber,
          snippetRedacted: tag.slice(0, 220),
          remediationHint:
            'Pin an exact version in the URL and add integrity="sha384-..." crossorigin="anonymous" (generate the hash with srihash.org or `openssl dgst -sha384 -binary | openssl base64 -A`), or self-host the file.',
        });
      }
    }
  }

  const severityOrder: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    unknown: 4,
  };
  return findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
}
