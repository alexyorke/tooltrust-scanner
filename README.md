<p align="center">
  <img src="docs/logo.svg" alt="ToolTrust" width="80" />
</p>

<h1 align="center">ToolTrust Scanner</h1>

<p align="center">
  <strong>We scanned 207 MCP servers. 70% have security issues.</strong><br/>
  Your AI agent trusts them all.
</p>

<p align="center">
  <a href="https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml"><img src="https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml"><img src="https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml/badge.svg" alt="Security" /></a>
  <a href="https://github.com/AgentSafe-AI/tooltrust-scanner/stargazers"><img src="https://img.shields.io/github/stars/AgentSafe-AI/tooltrust-scanner?style=social" alt="GitHub stars" /></a>
  <a href="https://goreportcard.com/report/github.com/AgentSafe-AI/tooltrust-scanner"><img src="https://goreportcard.com/badge/github.com/AgentSafe-AI/tooltrust-scanner" alt="Go Report Card" /></a>
  <a href="https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner"><img src="https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner/badges/score.svg" alt="Glama MCP score" /></a>
  <a href="https://www.npmjs.com/package/tooltrust-mcp"><img src="https://img.shields.io/npm/v/tooltrust-mcp?label=npm&color=blue" alt="npm" /></a>
  <a href="https://www.npmjs.com/package/tooltrust-mcp"><img src="https://img.shields.io/npm/dm/tooltrust-mcp?label=npm%20downloads" alt="npm downloads" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
</p>

---

Every MCP tool your agent calls is an attack surface — prompt injection, data exfiltration, privilege escalation, supply-chain backdoors. **ToolTrust** scans tool definitions *before* your agent trusts them and assigns a trust grade (**A–F**) so you know the risk.

> **About supply-chain findings:** Rule **AS-008** flags *dependencies and packages your MCP stack uses*, not a vulnerability in ToolTrust itself. See [docs/RULES.md](docs/RULES.md). If you see a **BLOCK**-level AS-008 hit, remove the affected package and rotate credentials.

![ToolTrust MCP demo](docs/mcp-demo.gif)

## Live UI

![ToolTrust Directory UI](docs/tooltrust-ui.png)

- Browse the public directory: [https://www.tooltrust.dev/](https://www.tooltrust.dev/)
- Look up historical grades for popular MCP servers
- Review findings in a browser before installing or trusting a server

## What it looks like

```
Scan Summary: 14 tools scanned | 13 allowed | 1 need approval | 0 blocked
Tool Grades: A×13  C×1
Findings by Severity: HIGH×1  MEDIUM×14  LOW×1 (16 total)

Flagged Tools:
• search_files  🟡 GRADE C  needs approval
  [AS-002] High: Network access declared
  [AS-011] Low: Missing rate-limit or timeout
  Action now: Keep this tool on manual approval until the risky capabilities are reviewed.
```

## Let your AI agent scan its own tools

Add ToolTrust as an MCP server in your `.mcp.json` and your agent can audit every tool it has access to:

> **Note:** First run downloads a ~10MB Go binary from GitHub Releases. Subsequent runs use the cached binary.

```json
{
  "mcpServers": {
    "tooltrust": {
      "command": "npx",
      "args": ["-y", "tooltrust-mcp"]
    }
  }
}
```

Then ask your agent to run:

- `tooltrust_scan_config` to scan all configured MCP servers
- `tooltrust_scan_server` to scan one specific server
- Full MCP tool list: [Usage guide](docs/USAGE.md#mcp-tools)

Or use the CLI:

```bash
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash
tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

## What we found scanning 207 servers

| Metric | Count |
|--------|-------|
| MCP servers scanned | 207 |
| Individual tools analyzed | 3,235 |
| Total security findings | 3,613 |
| Servers with at least one finding | 145 (70%) |
| Servers with a clean Grade A | 22 (10%) |
| Servers with arbitrary code execution | 16 |

**Only 10% of MCP servers get a clean bill of health.** [Read the full analysis →](docs/blog-post-draft.md)

## What it catches

The scanner runs **12 built-in rules** today (AS-001 through AS-011 and AS-013). **AS-012 (tool drift)** is documented in [docs/RULES.md](docs/RULES.md) as a planned rule and is **not** emitted by the engine yet — so marketed “13 rules” usually means “12 active + AS-012 on the roadmap.”

- Prompt injection and tool poisoning hidden in descriptions
- Excessive permissions such as `exec`, `network`, `db`, and `fs`
- Supply-chain CVEs and known compromised package versions (offline blacklist)
- Privilege escalation and arbitrary code execution patterns
- Typosquatting, tool shadowing, and insecure secret handling
- Missing rate-limit, timeout, or retry configuration on risky tools

Full rule catalog: [docs/RULES.md](docs/RULES.md) · [tooltrust.dev](https://www.tooltrust.dev/)

## How it works

1. **Parse** — Connects to a live MCP server (or reads a JSON file) and extracts every tool definition
2. **Analyze** — Runs all active rules against each tool's name, description, schema, and permissions
3. **Grade** — Assigns a numeric risk score and letter grade (A–F) per tool
4. **Enforce** — Maps each grade to a gateway policy: `ALLOW`, `REQUIRE_APPROVAL`, or `BLOCK`

Pure static analysis for core rules. Optional deep scan and OSV lookups may use the network; see [docs/USAGE.md](docs/USAGE.md).

## Install

```bash
# One-line install (macOS / Linux)
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash

# Go
go install github.com/AgentSafe-AI/tooltrust-scanner/cmd/tooltrust-scanner@latest

# Homebrew
brew install AgentSafe-AI/tap/tooltrust-scanner

# npx (no install needed)
npx -y tooltrust-mcp
```

**Windows:** Prefer `go install` or a release binary from [Releases](https://github.com/AgentSafe-AI/tooltrust-scanner/releases). More methods: [docs/USAGE.md](docs/USAGE.md).

## MCP tools

When running as an MCP server, ToolTrust exposes these tools to your agent:

| Tool | What it does |
|------|-------------|
| `tooltrust_scan_config` | Scan all MCP servers in your `.mcp.json` or `~/.claude.json` |
| `tooltrust_scan_server` | Launch and scan a specific MCP server by command |
| `tooltrust_scanner_scan` | Scan a raw JSON blob of tool definitions |
| `tooltrust_lookup` | Look up a server's trust grade from the ToolTrust Directory |
| `tooltrust_list_rules` | List all built-in security rules |

## CI / GitHub Actions

Block risky MCP servers in your pipeline:

```yaml
- name: Audit MCP Server
  uses: AgentSafe-AI/tooltrust-scanner@main
  with:
    server: "npx -y @modelcontextprotocol/server-filesystem /tmp"
    fail-on: "approval"
```

## Scan-before-install gate

```bash
tooltrust-scanner gate @modelcontextprotocol/server-memory -- /tmp
```

Full gate options and pre-commit hook setup: [docs/USAGE.md](docs/USAGE.md)

## Add a trust badge to your project

```markdown
[![ToolTrust Grade A](https://img.shields.io/badge/ToolTrust-Grade%20A-brightgreen)](https://www.tooltrust.dev/)
```

> [![ToolTrust Grade A](https://img.shields.io/badge/ToolTrust-Grade%20A-brightgreen)](https://www.tooltrust.dev/)

## More ways to use ToolTrust

- CLI install, examples, and flags: [Usage guide](docs/USAGE.md#cli)
- Scan-before-install workflow: [Gate docs](docs/USAGE.md#gate)
- CI / GitHub Actions examples: [CI integration](docs/USAGE.md#github-actions)
- Pre-commit / alias setup: [Pre-hook integration](docs/USAGE.md#pre-hook-integration)

---

[Usage guide](docs/USAGE.md) · [Developer guide](docs/DEVELOPER.md) · [Contributing](docs/CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Security](docs/SECURITY.md) · [License: MIT](LICENSE)

© 2026 [AgentSafe AI](https://github.com/AgentSafe-AI)
