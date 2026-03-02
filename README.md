# AgentSafe

[![CI](https://github.com/AgentSafe-AI/agentsafe/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentSafe-AI/agentsafe/actions/workflows/ci.yml)
[![Security](https://github.com/AgentSafe-AI/agentsafe/actions/workflows/security.yml/badge.svg)](https://github.com/AgentSafe-AI/agentsafe/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/AgentSafe-AI/agentsafe/branch/main/graph/badge.svg)](https://codecov.io/gh/AgentSafe-AI/agentsafe)
[![Go Report Card](https://goreportcard.com/badge/github.com/AgentSafe-AI/agentsafe?v=2)](https://goreportcard.com/report/github.com/AgentSafe-AI/agentsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.24-00ADD8.svg)](go.mod)

**The security trust layer for MCP servers, OpenAI tools, and AI Skills.**

AgentSafe scans tool definitions *before* an AI agent runs them — blocking prompt injection, over-permission, and scope mismatches at the source.

---

## What we scan

| Rule | ID | Detects |
|------|----|---------|
| 🛡️ **Tool Poisoning** | AS-001 | Prompt injection hidden in tool descriptions (`ignore previous instructions`, `system:`, `<INST>`) |
| 🔑 **Over-Permission** | AS-002 | Tools declaring `exec`, `network`, or `db` beyond their stated purpose |
| 📐 **Scope Mismatch** | AS-004 | Name vs. permission contradictions (`read_config` + `exec` permission) |
| 📦 **Large Attack Surface** | AS-003 | Input schemas exposing > 10 parameters |

## Risk grades

| Grade | Score | Gateway action |
|-------|-------|----------------|
| **A** | 0–10 | `ALLOW` |
| **B** | 11–25 | `ALLOW` + rate limit |
| **C** | 26–50 | `REQUIRE_APPROVAL` |
| **D** | 51–75 | `REQUIRE_APPROVAL` |
| **F** | 76+ | `BLOCK` |

Score = `Σ (weight × findings)` — weights: Critical **25** · High **15** · Medium **8** · Low **3**

---

## Quick integration

**CLI**
```bash
# install
curl -L https://github.com/AgentSafe-AI/agentsafe/releases/latest/download/agentsafe_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed s/x86_64/amd64/) \
  -o /usr/local/bin/agentsafe && chmod +x /usr/local/bin/agentsafe

agentsafe scan --protocol mcp --input tools.json
```

**GitHub Actions** — add one step to your CI:
```yaml
- name: AgentSafe scan
  run: agentsafe scan --protocol mcp --input testdata/tools.json --fail-on block
```

**MCP meta-scanner** — let Claude scan tools for you:
```bash
agentsafe-mcp   # stdio transport, exposes agentsafe_scan to any MCP client
```

**Docker**
```bash
docker run --rm -v $(pwd)/tools.json:/tools.json \
  ghcr.io/AgentSafe-AI/agentsafe:latest scan --protocol mcp --input /tools.json
```

---

## Example output

```json
{
  "policies": [
    {
      "ToolName": "run_shell",
      "Action": "BLOCK",
      "Score": {
        "Score": 80, "Grade": "F",
        "Issues": [
          { "RuleID": "AS-001", "Severity": "CRITICAL", "Code": "TOOL_POISONING" },
          { "RuleID": "AS-002", "Severity": "HIGH",     "Code": "HIGH_RISK_PERMISSION" }
        ]
      }
    }
  ],
  "summary": { "total": 3, "allowed": 1, "requireApproval": 1, "blocked": 1 }
}
```

---

## Architecture

```
pkg/adapter/    Protocol converters → UnifiedTool  (MCP · OpenAI · Skills · A2A)
pkg/analyzer/   Scan rules AS-001 – AS-004, Engine API, weighted scoring
pkg/gateway/    RiskScore → GatewayPolicy  (ALLOW · REQUIRE_APPROVAL · BLOCK)
pkg/model/      Core types: UnifiedTool · RiskScore · GatewayPolicy
cmd/agentsafe/  CLI entry point
cmd/mcpserver/  MCP meta-scanner server
```

## Development

```bash
make test           # race detector — must pass before every commit
make lint           # golangci-lint
make coverage       # ≥60% enforced on pkg/ + internal/
make cross-compile  # linux · darwin · windows binaries in dist/
```

TDD workflow: RED → GREEN → REFACTOR. See [`.cursor/skills/tdd-go/SKILL.md`](.cursor/skills/tdd-go/SKILL.md).

---

## Roadmap

- **v0.2** — OpenAI Function Calling · Markdown Skills · A2A adapters
- **v0.3** — SQLite scan history · certified JSON/PDF reports · REST API
- **v0.4** — K8s + gVisor sandbox for dynamic behavioural analysis
- **v0.5** — MCP/Skills Security Directory (public website, searchable by grade)
- **v1.0** — Browser extension · webhook gateway · signed scan certificates

---

## Contributing

PRs welcome — run `make test` first. See [CONTRIBUTING](CONTRIBUTING.md) for the TDD contract.

## License

[MIT](LICENSE) © 2026 AgentSafe-AI
