# We Scanned 207 MCP Servers. 70% Have Security Issues.

*A data-driven look at the attack surface hiding in your AI agent's toolbox.*

---

MCP (Model Context Protocol) is how AI agents connect to the world — file systems, databases, APIs, browsers. In the last 6 months, the MCP ecosystem has exploded: thousands of servers, deep integration into Claude, Cursor, Windsurf, and other agent frameworks.

But every MCP tool your agent calls is an attack surface. And nobody was checking.

We built [ToolTrust Scanner](https://github.com/AgentSafe-AI/tooltrust-scanner) — an open-source static analysis tool that scans MCP server definitions for prompt injection, data exfiltration, privilege escalation, and arbitrary code execution. Then we pointed it at every popular MCP server we could find.

Here's what we found.

## The Numbers

| Metric | Count |
|--------|-------|
| MCP servers scanned | 207 |
| Individual tools analyzed | 3,235 |
| Total security findings | 3,613 |
| Servers with at least one finding | 145 (70%) |
| Servers with a clean Grade A | 22 (10%) |
| Critical findings (code execution) | 16 |

**Only 10% of MCP servers get a clean bill of health.**

## Grade Distribution

```
Grade A (safe):           ██░░░░░░░░░░░░░░░░░░  10%
Grade B (low risk):       ████░░░░░░░░░░░░░░░░  20%
Grade C (review needed):  ████████░░░░░░░░░░░░  39%
Grade D (high risk):      █░░░░░░░░░░░░░░░░░░░   4%
Incomplete scan:          █████░░░░░░░░░░░░░░░  24%
```

The most common grade is **C** — "review recommended." These servers aren't malicious, but they request broad permissions or have patterns that an attacker could exploit.

## What We Found

### 1. Excessive Permissions Are Everywhere (2,473 findings)

The #1 issue: tools requesting more access than they need. A tool named `search_documents` shouldn't need `exec` permission. A `list_files` tool shouldn't need network access.

This matters because MCP doesn't enforce least-privilege. If a tool declares it needs filesystem access, your agent grants it — no questions asked.

### 2. 16 Servers Allow Arbitrary Code Execution

These servers expose tools that can run arbitrary scripts, JavaScript, or shell commands in your environment. Some are intentional (Chrome DevTools, code runners), but many users don't realize they're giving their AI agent a shell.

Servers with code execution capabilities include: chrome-devtools-mcp, codex-mcp-server, mcp-server-cloudflare, mcp-server-code-runner, n8n, puppeteer-mcp-server, and mcp-server-siri-shortcuts.

**If you're using any of these, your agent can execute arbitrary code on your machine.** That's by design for some (DevTools, Puppeteer), but it means you must trust every prompt the agent generates — including ones influenced by tool descriptions from *other* servers.

### 3. Missing Rate Limits and Timeouts (951 findings)

Nearly half of servers have no rate-limiting or timeout configuration. A misbehaving or manipulated agent could hammer an API endpoint with unlimited requests.

### 4. Insecure Secret Handling (97 findings)

97 tools accept credentials (API keys, passwords, tokens) as direct input parameters instead of using environment variables or secure credential stores. This means your secrets flow through the LLM context window.

## The Scariest Finding: Tool Poisoning Is Real

Tool poisoning is when a malicious MCP server hides prompt injection payloads in its tool descriptions. Your agent reads these descriptions to understand what tools do — but a poisoned description can instruct the agent to ignore its safety guidelines, exfiltrate data, or call other tools in unexpected ways.

We check for this (rule AS-001), and while we didn't find widespread malicious poisoning in popular servers, the attack surface is real. A single compromised server in your `.mcp.json` can influence how your agent uses *every other server*.

## How We Scan

ToolTrust Scanner uses 11 static analysis rules:

- **AS-001**: Prompt poisoning / injection in tool descriptions
- **AS-002**: Excessive permissions (exec, network, db, fs)
- **AS-003**: Scope mismatch (name contradicts permissions)
- **AS-004**: Supply chain CVEs via OSV
- **AS-005**: Privilege escalation (admin scopes, sudo)
- **AS-006**: Arbitrary code execution
- **AS-007**: Missing description or schema
- **AS-009**: Typosquatting (edit-distance impersonation)
- **AS-010**: Insecure secret handling
- **AS-011**: Missing rate-limits or timeouts
- **AS-013**: Tool shadowing (duplicate name hijacking)

The scanner is pure static analysis — no LLM calls, no network requests (except for CVE lookups). It runs in milliseconds and produces deterministic results.

## Try It Yourself

**Scan your own setup in 30 seconds:**

Add ToolTrust as an MCP server to your `.mcp.json`:

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

Then ask your agent: *"Run tooltrust_scan_config"*

It reads your MCP config, connects to each server, and scans every tool — all in parallel.

**Or use the CLI:**

```bash
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash
tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

**Or browse the public directory:**

[www.tooltrust.dev](https://www.tooltrust.dev) — look up any server's grade before you install it.

## What We're Building Next

ToolTrust started as a scanner. It's becoming a trust registry — like npm audit for MCP servers. Every server gets a grade. Grades are public, transparent, and reproducible.

The goal: before your AI agent calls any tool, it should know the risk.

---

*ToolTrust Scanner is open-source (MIT). [GitHub](https://github.com/AgentSafe-AI/tooltrust-scanner) · [Directory](https://www.tooltrust.dev) · Built by [AgentSafe AI](https://github.com/AgentSafe-AI)*
