# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| v0.1.x  | :white_check_mark: |
| &lt; v0.1 | :x:              |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you believe you have found a security vulnerability in ToolTrust Scanner:

1. **Email** the maintainers with details. You can reach us via:
   - Open an issue with the `security` label and mark it as **private** if your GitHub org supports it, or
   - Email us at **contact@tooltrust.dev**

2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment (e.g., what an attacker could do)
   - Suggested fix (if any)

3. **Expected response**: We aim to acknowledge within 48 hours and provide an initial assessment within 7 days.

4. **Disclosure**: We will coordinate with you on public disclosure. We ask that you give us a reasonable time to address the issue before public disclosure.

## Security-Critical Areas

ToolTrust Scanner is a static analysis tool that scans tool definitions. Areas of particular security interest:

- **Parser behavior** — malformed input handling in `pkg/adapter/*`
- **OSV API interaction** — supply-chain checker (`pkg/analyzer/supply_chain.go`) makes outbound requests; ensure no injection or credential leakage
- **CLI file handling** — `--input` and `--db` paths; avoid path traversal or unexpected file access

## Dependencies

We use `govulncheck` in CI and keep dependencies up to date. Report any dependency-level vulnerabilities through the same channels above.

## Operating MCP servers safely

General guidance for teams running **any** MCP server (not specific to ToolTrust Scanner’s implementation):

- **Redirect URI validation** — Use exact string matching for OAuth `redirect_uri` values to reduce token theft.
- **Tokens and scopes** — Prefer **narrow OAuth scopes**, **short-lived tokens**, and **RFC 8693** (token exchange) / **RFC 8707** (resource indicators) where your stack supports them to limit confused-deputy risk.
- **Secrets** — Do not pass long-lived PATs or API keys as **tool arguments**; use environment variables or a secret store.
- **Network exposure** — Bind admin or debug interfaces to **loopback** unless you intend public exposure; document firewall rules for remote MCP over HTTP/SSE.
- **Isolation** — Run untrusted or high-risk servers in containers or dedicated hosts according to your org policy.

## What ToolTrust Scanner does not do

ToolTrust Scanner performs **static analysis** on tool definitions (and optional live `tools/list` via subprocess). It does **not**:

- Execute or sandbox arbitrary third-party MCP server code at runtime.
- Enforce OAuth, network binding, or OS-level policies on other processes.
- Replace EDR, SIEM, or organizational approval workflows.

Use scan output and gateway-style grades as **inputs** to your governance process, not as sole proof of safety.
