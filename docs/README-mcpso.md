# ToolTrust Scanner

**We scanned 207 MCP servers. 70% have security issues.** Your AI agent trusts them all.

ToolTrust scans MCP tool definitions for prompt injection, data exfiltration, privilege escalation, and supply-chain attacks — then assigns a trust grade (A–F) so you know the risk before your agent calls anything.

> Pure static analysis. No LLM calls. No data leaves your machine. Runs in milliseconds.

![ToolTrust MCP demo](https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/docs/mcp-demo.gif)

## Scan your setup in 30 seconds

Add ToolTrust as an MCP server:

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

It reads your MCP config, connects to each server in parallel, scans every tool, and returns a risk report with grades and enforcement decisions.

## What it catches

| Threat | What it detects |
|--------|-----------------|
| Prompt injection | Malicious instructions hidden in tool descriptions |
| Arbitrary code execution | Tools that run `eval()`, `exec()`, or arbitrary scripts |
| Data exfiltration | Tools that send data to external endpoints |
| Privilege escalation | Tools requesting admin/sudo/root access |
| Supply-chain CVEs | Known vulnerabilities in server dependencies |
| Known malware | Confirmed compromised package versions (LiteLLM, Trivy, Langflow) |
| Typosquatting | Tool names impersonating legitimate tools |
| Tool shadowing | Duplicate tool names designed to hijack agent behavior |
| Secret leakage | API keys or passwords accepted as plaintext parameters |
| Missing rate limits | Tools with no timeout or rate-limit configuration |

**12** built-in rules run today (AS-001–AS-011, AS-013). **AS-012** is documented as planned, not yet enforced — see [docs/RULES.md](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/RULES.md). Full catalog · [tooltrust.dev](https://www.tooltrust.dev/)

## Key numbers

| Metric | Count |
|--------|-------|
| MCP servers scanned | 207 |
| Individual tools analyzed | 3,235 |
| Total security findings | 3,613 |
| Servers with at least one finding | 145 (70%) |
| Clean Grade A | 22 (10%) |
| Servers with arbitrary code execution | 16 |

## Live Directory

Browse trust grades for popular MCP servers before you install them: **[tooltrust.dev](https://www.tooltrust.dev/)**

![ToolTrust Directory UI](https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/docs/tooltrust-ui.png)

## More ways to use ToolTrust

- **CLI**: `tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"`
- **Scan-before-install gate**: `tooltrust-scanner gate @modelcontextprotocol/server-memory -- /tmp`
- **GitHub Actions**: block risky servers in CI
- **Pre-commit hook**: auto-scan `.mcp.json` on every commit

Full docs: [Usage Guide](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/USAGE.md) · [Developer Guide](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/DEVELOPER.md)

## Links

- GitHub: [AgentSafe-AI/tooltrust-scanner](https://github.com/AgentSafe-AI/tooltrust-scanner)
- Live Directory: [tooltrust.dev](https://www.tooltrust.dev/)
- Security: [SECURITY.md](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/SECURITY.md)
- MIT Licensed
