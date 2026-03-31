# Deployment & Security Reference

Operational guidance for teams deploying MCP servers and integrating ToolTrust into security programs.

## MCP deployment hygiene

For **operators** building or running MCP servers (general best practices):

- Treat MCP connections as **identity grants**; prefer **narrow OAuth scopes** and **short-lived tokens**.
- Validate **`redirect_uri`** with **exact** string matching on OAuth flows.
- Consider **RFC 8707** (resource indicators) and **RFC 8693** (token exchange) where applicable to reduce confused-deputy risk.
- Run sensitive servers with **minimal network exposure** (e.g. bind to loopback where appropriate).
- Avoid **secrets in tool arguments**—aligns with **AS-010**.

ToolTrust **does not** enforce these; it helps you **audit tool definitions** and **configure policy**.

## Static scanner vs gateways

ToolTrust focuses on **offline / CI-friendly static analysis** and **clear grades**, plus **`gate`** for install-time decisions. **Managed gateways** and **runtime proxies** may add latency and live interception; ToolTrust is **not** positioned as a sub‑5ms gateway or EDR layer. Use it to **inventory and score** tool definitions and to **enforce policy signals** (HITL / block) that your host or pipeline implements.

## Threat mapping

High-level mapping (illustrative—scanner uses static heuristics, not runtime monitoring):

| Area | Category | Relation to ToolTrust |
|------|-----------|------------------------|
| Identity & access | Weak / missing access control | AS-002, AS-005, permissions surface |
| Input handling | Injection / poisoning | AS-001, AS-006, schema / metadata AS-007 |
| Data boundary | Prompt injection / tool poisoning | AS-001 |
| Protection | Secrets in parameters | AS-010 |
| Integrity | Typosquat / shadowing | AS-009, AS-013 |
| Session / transport | (Tool metadata) | AS-011 hints; binding is operational |
| Supply chain | Vulnerable or malicious deps | AS-004, AS-008 |
| Operations | Observability | Scan output, optional `--db`; not full SIEM |

### OWASP Agentic-style crosswalk (illustrative)

| Theme | Example mitigation signal |
|-------|---------------------------|
| Goal hijack / poisoning | AS-001 findings |
| Tool misuse | Grades C/D → `REQUIRE_APPROVAL` (HITL) |
| Insecure tool design | AS-007, AS-011 |
| Supply chain | AS-004, AS-008 |

## Regulated environments (HIPAA-style framing)

ToolTrust can **support** parts of a **technical safeguards** program (e.g. reviewing **over-broad tool permissions**, **injection patterns**, **known-bad dependencies**) by producing **consistent, reviewable** scan output. It is **not** a HIPAA certification, legal advice, or a complete compliance control. Organizations must integrate it into **broader risk analysis** and **human review** where required.

## Claude / Claude Code configuration notes

Typical Claude Code **scope** order (confirm against current Anthropic documentation):

| Priority | Scope | Typical location | Notes |
|----------|--------|------------------|--------|
| Highest | Managed | `/etc/claude-code/` (Unix) or enterprise policy | Org-wide |
| — | CLI | — | Session overrides |
| Mid | Local | `.claude/settings.local.json` | Per-session local |
| Project | Project | `.claude/settings.json` | Team-shared |
| Lowest | User | `~/.claude/settings.json` | Personal |

**Desktop / config paths** (verify for your product version):

| OS | Claude Desktop (typical) | Claude Code / user settings (typical) |
|----|---------------------------|----------------------------------------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.claude/settings.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` | See vendor docs |
| Linux | `~/.config/Claude/claude_desktop_config.json` | See vendor docs |

Use **`claude mcp add …`** with the appropriate **scope** flags for your workflow. Claude Code may keep **timestamped backups** of settings when updating—useful if an MCP add fails mid-write.

## Credential storage

Do not hardcode PATs or API keys in MCP JSON committed to git.

**bash**

```bash
echo "GITHUB_PAT=your_token_here" >> .env
printf '\n.env\n.mcp.json\n' >> .gitignore
```

**PowerShell**

```powershell
Add-Content -Path .env -Value "GITHUB_PAT=your_token_here"
Add-Content -Path .gitignore -Value ".env`n.mcp.json`n"
```

Reference tokens from your environment or secret store when configuring MCP—never commit them.

## Why documentation matters

**Misconfigured MCP exposure** can negate host security—for example, admin UI bound to `0.0.0.0` with weak auth can leak keys and conversation data. Static checks on **permissions** and **network-facing defaults** (AS-002 and related patterns) help catch risky **declared** capabilities before wide rollout.

**Shadow MCP** (unapproved servers in configs) is harder to govern without **inventory**. `tooltrust_scan_config` and CI scans help teams **list and grade** what is configured.
