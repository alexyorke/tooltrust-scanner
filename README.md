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
  <a href="https://codecov.io/gh/AgentSafe-AI/tooltrust-scanner"><img src="https://codecov.io/gh/AgentSafe-AI/tooltrust-scanner/branch/main/graph/badge.svg" alt="Codecov" /></a>
  <a href="https://goreportcard.com/report/github.com/AgentSafe-AI/tooltrust-scanner"><img src="https://goreportcard.com/badge/github.com/AgentSafe-AI/tooltrust-scanner" alt="Go Report Card" /></a>
  <a href="https://www.npmjs.com/package/tooltrust-mcp"><img src="https://img.shields.io/npm/v/tooltrust-mcp?label=npm&color=blue" alt="npm" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://github.com/AgentSafe-AI/tooltrust-scanner/stargazers"><img src="https://img.shields.io/github/stars/AgentSafe-AI/tooltrust-scanner?style=social" alt="GitHub stars" /></a>
</p>

---

**Scan MCP tool definitions for prompt injection, excessive permissions, and supply-chain risk before your AI agent trusts them.** ToolTrust is a **static analyzer**: it grades each tool **A–F** and maps scores to gateway policies (`ALLOW`, `REQUIRE_APPROVAL`, `BLOCK`).

> ToolTrust flags confirmed compromised packages via rule **AS-008** (offline blacklist). If you see AS-008 on a **BLOCK** entry, remove the package and rotate credentials. See [docs/RULES.md](docs/RULES.md) for the full blacklist.

![ToolTrust MCP demo](docs/mcp-demo.gif)

## Contents

- [Pick your path](#pick-your-path)
- [Install](#install)
- [Quick start](#quick-start)
- [Safe installation with `gate`](#safe-installation-with-gate)
- [MCP server (self-audit)](#mcp-server-self-audit)
- [GitHub Actions](#github-actions)
- [What we found (207 servers)](#what-we-found-scanning-207-servers)
- [What it catches](#what-it-catches)
- [How it works](#how-it-works)
- [Browse the directory](#browse-the-directory)
- [What ToolTrust does not do](#what-tooltrust-does-not-do)
- [Development](#development)
- [Links](#links)

## Pick your path

1. **CLI** — Scan a live MCP server or a JSON tool file; use **`gate`** to scan before install.
2. **MCP server** — Add `tooltrust-mcp` to your MCP config so your agent runs `tooltrust_scan_config` and related tools.
3. **CI/CD** — Use the composite GitHub Action to fail pipelines when tools exceed your policy (`fail-on`).

## Install

| Method | Command | Best for |
|--------|---------|----------|
| **Homebrew** | `brew install AgentSafe-AI/tap/tooltrust-scanner` | macOS (and Linux via Homebrew) |
| **Go** | `go install github.com/AgentSafe-AI/tooltrust-scanner/cmd/tooltrust-scanner@latest` | Any platform with Go 1.26+ |
| **Install script** | `curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh \| bash` | macOS / Linux (release asset naming) |
| **npm / npx** | `npx -y tooltrust-mcp` | Running the MCP server without a local Go build |

**Windows:** Prefer **`go install`** or download the **`tooltrust-scanner_windows_amd64.exe`** asset from [Releases](https://github.com/AgentSafe-AI/tooltrust-scanner/releases). The curl install script and the composite Action's download URL target non-`.exe` release names on Unix—on Windows, use Go or the release binary until those paths are aligned.

**Docker:** Build locally (`docker build -t tooltrust-scanner .`) or use images from **GHCR** (`ghcr.io/agentsafe-ai/tooltrust-scanner`, tags from releases). Entrypoint is `tooltrust-scanner`.

## Quick start

```bash
# Scan a live MCP server
tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Or scan a static JSON file
tooltrust-scanner scan --input testdata/tools.json --protocol mcp --fail-on block
```

**`--output`:** `text` (default), `json`, or `sarif`. **`--db`** persists results to SQLite (retained history for review—not cryptographically signed).

Example output:

```text
Scan Summary: 14 tools scanned | 13 allowed | 1 need approval | 0 blocked
Tool Grades: A×13  C×1
Findings by Severity: HIGH×1  MEDIUM×14  LOW×1 (16 total)

Flagged Tools:
• search_files  GRADE C  needs approval
  [AS-002] High: Network access declared
  [AS-011] Low: Missing rate-limit or timeout
  Action now: Keep this tool on manual approval until capabilities are reviewed.
```

## Safe installation with `gate`

`gate` scans a package as a live MCP server, then installs only if the **worst tool grade** passes your threshold:

- **Grade A or B** — Proceeds automatically (if not blocked by `--block-on`).
- **Grade C or D** — Interactive confirmation (if not blocked).
- **Grade F** — Blocked when the worst grade reaches the block threshold (default: block at **F** only).

**`--block-on`** sets the **minimum grade that blocks installation** (`F` default, or `D`, `C`, `B`). Example: `--block-on B` blocks when the worst grade is **B or worse**—only **A** proceeds without hitting the block path.

```bash
tooltrust-scanner gate @modelcontextprotocol/server-memory -- /tmp

# Scan only (no install)
tooltrust-scanner gate --dry-run @modelcontextprotocol/server-filesystem -- /tmp

# Stricter: block at D or worse
tooltrust-scanner gate --block-on D @some/package -- /tmp

# User-scoped config (~/.claude.json) instead of project .mcp.json
tooltrust-scanner gate --scope user @some/package -- /tmp
```

Other flags: `--force` (install regardless of grade), `--name`, `--deep-scan`, `--rules-dir`. Full details: [docs/USAGE.md](docs/USAGE.md).

## MCP server (self-audit)

ToolTrust's MCP process is a **stdio** MCP server (not a network gateway). Your **host** (Claude, Cursor, etc.) launches it; it can **spawn subprocesses** to connect to other MCP servers over stdio for live scans.

Add to `.mcp.json` or `~/.claude.json`:

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

Then ask your agent to run **`tooltrust_scan_config`** (scan all configured servers) or **`tooltrust_scan_server`** (one server). Full tool inventory: [docs/USAGE.md](docs/USAGE.md).

## GitHub Actions

Fail CI when any tool would require approval or be blocked (default **`fail-on: approval`** → fails on grades **C, D, or F**).

`fail-on` values are **policy names**, not letter grades: `allow` | `approval` | `block`.

- **`approval`** — Fail if any tool is `REQUIRE_APPROVAL` or `BLOCK`.
- **`block`** — Fail only if any tool is `BLOCK`.
- **`allow`** — Fail if any tool is not fully `ALLOW` (i.e. **every tool must be grade A or B**).

```yaml
- name: Audit MCP Server
  uses: AgentSafe-AI/tooltrust-scanner@main
  with:
    server: "npx -y @modelcontextprotocol/server-filesystem /tmp"
    fail-on: "approval"
  # Outputs for later steps:
  #   steps.<id>.outputs.grade   — summary letter grade (from mean score)
  #   steps.<id>.outputs.score   — numeric summary score
  #   steps.<id>.outputs.result  — full JSON report
```

You can pass **`input`** instead of **`server`** for a static `tools.json`. **`deep-scan: "true"`** enables semantic / ONNX-assisted analysis. Extended example: [docs/github-actions-scan.yml](docs/github-actions-scan.yml).

**Note:** The action downloads a release binary as `tooltrust` on the job `PATH`; locally you use **`tooltrust-scanner`**.

## What we found scanning 207 servers

Figures below are from our [study write-up](docs/blog-post-draft.md).

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

ToolTrust runs **12** built-in static rules (AS-001–011 and AS-013). [docs/RULES.md](docs/RULES.md) is the canonical reference.

| Threat | Rule | What it detects |
|--------|------|-----------------|
| Prompt injection | AS-001 | Malicious instructions in descriptions |
| Excessive permissions | AS-002 | Broad `exec` / `network` / `db` / `fs` |
| Scope mismatch | AS-003 | Name vs declared capabilities mismatch |
| Supply-chain CVEs | AS-004 | OSV CVEs in declared dependencies |
| Privilege escalation | AS-005 | `admin` / `root` / `sudo`-style scopes |
| Arbitrary code execution | AS-006 | Shell / eval / arbitrary execution patterns |
| Missing metadata | AS-007 | Missing description or input schema |
| Known compromised packages | AS-008 | Offline blacklist (some entries WARN, some BLOCK) |
| Typosquatting | AS-009 | Names near well-known tools |
| Secret handling | AS-010 | Parameters that accept secrets as plaintext |
| DoS resilience | AS-011 | Risky ops without rate-limit / timeout hints |
| Tool shadowing | AS-013 | Exact duplicate normalized tool names |

## How it works

1. **Parse** — MCP JSON file (`--input` + `--protocol mcp`) or live server (`--server`); adapters produce `UnifiedTool` models.
2. **Analyze** — `pkg/analyzer` runs registered checkers; aggregates a **`RiskScore`** per tool.
3. **Grade** — Numeric score → letter grade **A–F**.
4. **Enforce** — `pkg/gateway.Evaluate` maps each score to a **`GatewayPolicy`**: `ALLOW`, `REQUIRE_APPROVAL`, or `BLOCK`, plus a human-readable **Reason** (and optional rate limit for grade B).

Pure static analysis for the core rules. Optional **`--deep-scan`** loads a quantized model for deeper prompt-injection signals. Aside from **OSV** (AS-004) and optional Directory lookup, data stays on your machine. Architecture details: [docs/DEVELOPER.md](docs/DEVELOPER.md).

## Browse the directory

![ToolTrust Directory UI](docs/tooltrust-ui.png)

Curated grades for many public MCP servers: **[tooltrust.dev](https://www.tooltrust.dev/)** (A–F style reporting).

## What ToolTrust does not do

- **Runtime sandbox** for arbitrary third-party MCP server code (see `pkg/sandbox` for future interface only).
- **PII redaction**, **EDR**, **eBPF**, or **inline filtering** of all MCP JSON-RPC traffic.
- **Cryptographically signed** audit trails in **`--db`** (SQLite JSON records).
- **OpenAI / Skills** file-based scans (**stubs** today).
- **AS-012 Tool drift** in engine (**not implemented**—see [docs/RULES.md](docs/RULES.md)).

## Development

Requires **Go 1.26+**. See [docs/DEVELOPER.md](docs/DEVELOPER.md) for architecture and the full developer guide, and [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for contribution workflow and AI-agent guardrails.

```bash
git clone https://github.com/AgentSafe-AI/tooltrust-scanner.git
cd tooltrust-scanner
make test          # race detector; required before PRs
make build         # local binaries
```

## Links

[Usage](docs/USAGE.md) · [Rules](docs/RULES.md) · [Developer guide](docs/DEVELOPER.md) · [Contributing](docs/CONTRIBUTING.md) · [Deployment & security](docs/DEPLOYMENT.md) · [Changelog](CHANGELOG.md) · [Security](docs/SECURITY.md) · [License: MIT](LICENSE) · [Version](VERSION)

**Support:** [GitHub Issues](https://github.com/AgentSafe-AI/tooltrust-scanner/issues) · **Security contact:** see [docs/SECURITY.md](docs/SECURITY.md)

© 2026 [AgentSafe AI](https://github.com/AgentSafe-AI)
