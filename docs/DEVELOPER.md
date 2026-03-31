# ToolTrust Scanner — Developer Guide

## Prerequisites

- Go 1.26+ — [install](https://go.dev/dl/)
- `golangci-lint` v2 — `brew install golangci-lint` or see [golangci-lint docs](https://golangci-lint.run/usage/install/)
- Docker (optional, for image builds)

## Architecture

```
github.com/AgentSafe-AI/tooltrust-scanner
│
├── cmd/
│   ├── tooltrust-scanner/  CLI — scan, gate, version
│   └── tooltrust-mcp/      MCP stdio server (tooltrust_scan_config, etc.)
│
├── pkg/
│   ├── adapter/         Protocol converters → UnifiedTool
│   │   ├── mcp/         MCP tools/list parser          ✅ implemented
│   │   ├── openai/      OpenAI function-calling         🚧 stub (Parse not implemented)
│   │   ├── skills/      Markdown Skills (SKILL.md)      🚧 stub (Parse not implemented)
│   │   └── a2a/         Agent-to-Agent protocol         📋 planned
│   │
│   ├── analyzer/        Scan engine + rule catalog
│   │   ├── engine.go    Engine — NewEngine / Scan (uses context.Background)
│   │   ├── analyzer.go  Scanner — orchestrates checkers; Scan(ctx) respects cancel
│   │   ├── poisoning.go      AS-001 Tool Poisoning
│   │   ├── permission.go     AS-002 Permission Surface
│   │   ├── scope.go          AS-003 Scope Mismatch
│   │   ├── supply_chain.go   AS-004 Supply Chain CVE (OSV API)
│   │   ├── privilege.go      AS-005 Privilege Escalation
│   │   ├── arbitrary_code.go AS-006 Arbitrary Code Execution
│   │   ├── insufficient_data.go AS-007 Insufficient Tool Data
│   │   ├── blacklist.go      AS-008 Known Compromised Packages
│   │   ├── typosquatting.go  AS-009 Typosquatting
│   │   ├── secrets.go        AS-010 Secret Handling
│   │   ├── dos.go            AS-011 DoS Resilience
│   │   ├── shadowing.go      AS-013 Tool Shadowing
│   │   ├── custom.go         Custom YAML rules loader
│   │   └── export_test.go   (test hooks)
│   │
│   ├── gateway/         Evaluate(toolName, RiskScore) → GatewayPolicy + Reason
│   ├── model/           Core types: UnifiedTool · RiskScore · GatewayPolicy · ActionFromGrade
│   ├── storage/         SQLite persistence (modernc.org/sqlite, no CGo)
│   └── sandbox/         K8s + gVisor interface (reserved; not active sandbox)
│
├── internal/
│   └── jsonschema/      Minimal JSON Schema helpers
│
├── testdata/
│   └── tools.json       Sample MCP fixture for E2E testing
│
├── .github/workflows/   CI · Release · Security (govulncheck, gosec)
├── .cursor/skills/      TDD red-green-refactor skill
├── Dockerfile           Multi-stage build → scratch image (~8 MB)
└── Makefile
```

### Engine vs Scanner

- **`analyzer.Scanner`** — `Scan(ctx, tool)` respects **context cancellation** between checkers.
- **`analyzer.Engine`** — Thin wrapper; `Scan(tool)` calls `Scanner.Scan(context.Background(), tool)` so CLI/library one-shots are deterministic (checkers themselves do not rely on external cancel for normal paths).

### Gateway

`gateway.Evaluate` in `pkg/gateway/policy.go` maps a `model.RiskScore` to `model.GatewayPolicy` (`Action`, `Reason`, optional `RateLimit` for grade B). Actions derive from grades via `model.ActionFromGrade` (`pkg/model/policy.go`).

## Make targets

```bash
make test           # race detector + all packages — required before every commit
make test-verbose   # with -v flag
make coverage       # ≥60% threshold enforced on pkg/ + internal/
make coverage-html  # open HTML report in browser
make lint           # go vet ./... (see note below)
make fmt            # go fmt ./...
make vet            # go vet ./...
make build          # ./tooltrust-scanner + ./tooltrust-mcp in repo root
make cross-compile  # linux/amd64 · linux/arm64 · darwin/amd64 · darwin/arm64 · windows/amd64
make docker         # build ghcr.io/agentsafe-ai/tooltrust-scanner:dev
make scan           # self-scan testdata/tools.json (integration check)
make clean          # remove built binaries + coverage files
```

**Lint parity with CI:** CI runs **`golangci-lint`** (v2, see `.golangci.yml`). Locally run `golangci-lint run` (or use the golangci-lint GitHub Action on your branch). `make lint` currently runs **`go vet` only** unless you extend the Makefile.

## TDD workflow

This project follows strict **red → green → refactor** TDD.  
Full guide: [`.cursor/skills/tdd-go/SKILL.md`](../.cursor/skills/tdd-go/SKILL.md)

1. **RED** — Write a failing `_test.go` that defines the contract.
2. **GREEN** — Write the minimal code to make it pass (ugly is fine).
3. **REFACTOR** — Clean up; `make test` must still exit 0.

`make test` must exit 0 before every commit. CI enforces this.

## Adding a new scan rule

1. Create `pkg/analyzer/<rule>.go` implementing the `checker` interface:
   ```go
   type checker interface {
       Check(tool model.UnifiedTool) ([]model.Issue, error)
   }
   ```
2. Assign the next available rule ID (e.g. `AS-006`) in each `model.Issue` you return.
3. Register the checker in `NewScanner()` inside `pkg/analyzer/analyzer.go`.
4. Write `pkg/analyzer/<rule>_test.go` — start with the failing test (RED).
5. Update the [rule table](../README.md#what-it-catches) in `README.md`.

## ToolTrust Directory JSON schema

All scan output conforms to `schema_version: "1.0"`:

```json
{
  "schema_version": "1.0",
  "policies": [
    {
      "tool_name": "run_shell",
      "action": "BLOCK",
      "rate_limit": null,
      "reason": "",
      "score": {
        "risk_score": 80,
        "grade": "F",
        "findings": [
          {
            "rule_id": "AS-001",
            "severity": "CRITICAL",
            "code": "TOOL_POISONING",
            "description": "possible prompt injection detected in tool description",
            "location": "description"
          }
        ]
      }
    }
  ],
  "summary": {
    "total": 1,
    "allowed": 0,
    "require_approval": 0,
    "blocked": 1,
    "scanned_at": "2026-02-27T10:00:00Z"
  }
}
```

## Adding a new protocol adapter

1. Create `pkg/adapter/<protocol>/adapter.go` implementing `adapter.Adapter`:
   ```go
   type Adapter interface {
       Parse(ctx context.Context, data []byte) ([]model.UnifiedTool, error)
       Protocol() model.ProtocolType
   }
   ```
2. Write a `_test.go` with table-driven cases for valid + invalid inputs.
3. Wire it into `cmd/tooltrust-scanner/main.go`'s `switch protocol { ... }`.

## CI/CD

| Workflow | Triggers | Key jobs |
|----------|----------|----------|
| `ci.yml` | push/PR to main | test (race), coverage ≥60%, lint, build, self-scan |
| `release.yml` | `v*.*.*` tags | cross-compile, GitHub Release, Docker push to GHCR |
| `security.yml` | push/PR + weekly | govulncheck, gosec (SARIF), dependency-review, meta-scan |

## Release process

1. Ensure `main` is green: `make test` and **`golangci-lint run`** (or green CI)
2. Update [CHANGELOG.md](../CHANGELOG.md): move items from `[Unreleased]` to a new version section
3. Commit changelog: `git add CHANGELOG.md && git commit -m "chore: release v0.1.3"`
4. Tag: `git tag v0.1.3`
5. Push tag: `git push origin v0.1.3`
6. Release workflow runs: builds `tooltrust-scanner_*` and `tooltrust-mcp_*` binaries, creates GitHub Release, pushes Docker image to GHCR
7. If using Homebrew [Formula](../Formula/tooltrust-scanner.rb): update `url` and `sha256` (run `shasum -a 256` on the new tarball)
