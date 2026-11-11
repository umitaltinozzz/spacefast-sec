# Spacefast Security MCP — Privacy Policy (review draft)

_Last reviewed: 12 November 2026. Review and approve this text before publishing or relying on it as a legal policy._

## What the service does

Spacefast Security is a security-auditing MCP service hosted on Cloudflare Workers. It analyzes files and deployment URLs that users or connected AI assistants explicitly submit. The service can analyze project manifests and lockfiles, dependency and vulnerability information, code patterns, and allowed public Spacefast websites.

This **cloud-based service is not the same as** the local-first Security Monitor desktop application. Using the cloud MCP service sends supplied inputs to the remote Worker.

## Data processed

- The service receives the MCP request content, which may include source code, dependency manifests and lockfiles, file paths, package names and versions, site URLs, and scan options.
- The service returns findings, suggested fixes, file locations, validation gaps, and related advisory information.
- Connection metadata, including IP addresses, request times, and request headers, may be processed by Cloudflare to route, protect, rate limit, or operate the service.
- When authorized users request a live probe, the service makes HTTP requests to the permitted Spacefast deployment. The destination may observe those requests.
- To enrich dependency findings, the service uses external public providers such as OSV, cve.now, CISA KEV, and FIRST EPSS. These services may receive the identifiers necessary to perform advisory lookups and may process requests under their own policies.

## Sensitive information

Do not submit raw tokens, private keys, credentials, personal records, or confidential source code unless you are authorized to transfer that data to this remote service. The recommended workflow sends only the **path** (with empty content) for sensitive files such as `.env`, `.npmrc`, PEM/private key files, and similar secrets. Security findings are intended to redact detected secret values, but automated redaction is not guaranteed to catch every credential in arbitrary input.

## Storage and retention

The repository's current Worker source does not declare an application database for scan bodies or scan results. It uses temporary in-memory computation and advisory caches. However, hosting providers, network intermediaries, security services, and external advisory providers may retain technical metadata according to their own configurations and policies. No promise is made here that all requests are immediately or permanently erased. Do not submit data that you cannot authorize the service to process.

## Security and access

The public MCP endpoint currently does not authenticate callers. The Worker uses an origin allowlist for browser requests, a per-IP rate-limit binding, bounded input sizes, and restricted live-probe host suffixes. A CORS origin restriction is **not** a substitute for authentication. Users should operate it only on projects they own or are permitted to test.

## User control

You control whether your AI client sends project files or site URLs to the MCP service. You can remove or disable the plugin connection from your AI client. This does not automatically remove technical records retained by the hosting or advisory providers.

## Questions

Open an issue at https://github.com/umitaltinozzz/spacefast-sec/issues to ask about data handling, security, or privacy.

## Third-party services

Cloudflare Workers: https://www.cloudflare.com/privacypolicy/

OSV: https://osv.dev/

cve.now: https://cve.now/

CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

FIRST EPSS: https://www.first.org/epss/
