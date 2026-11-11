# Spacefast Security (`spacefast-sec`) for Gemini CLI

`spacefast-sec` is the deterministic security and CVE auditor for Spacefast (`*.space.fast` and `drop.fast`), powered by the [Security Monitor (`secmon`)](https://github.com/umitaltinozzz/security-monitor) engine and [cve.now](https://cve.now).

Use [`skills/spacefast-security/SKILL.md`](skills/spacefast-security/SKILL.md) as the source of truth.

## Setup

Configure `~/.gemini/settings.json` to connect both the official Spacefast MCP and `spacefast-sec`:

```json
{
  "mcpServers": {
    "spacefast": {
      "httpUrl": "https://mcp.spacefast.com",
      "oauth": {
        "enabled": true
      }
    },
    "spacefast-sec": {
      "httpUrl": "https://spacefast-sec-mcp.umiqi.workers.dev/mcp"
    }
  }
}
```

## Safety Rules

- Never claim a Space is safe unless `scan_space_full` returns `overallState: "clean"` and `validationReasons` is empty.
- Never send the contents of `.env*`, `.npmrc`, `*.pem`, `*.key`, or `id_*` files—send only their file paths with `content: ""`.
- Always show `remediationPlan.unifiedDiff` and wait for explicit user approval before modifying files on the Space.
