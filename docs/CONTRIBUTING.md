# Contributing to ToolTrust Scanner

Thank you for your interest in contributing. This document explains how to set up your environment, submit changes, and add new scan rules or adapters.

## Prerequisites

- Go 1.26+
- `golangci-lint` v2 — `brew install golangci-lint` or see [golangci-lint docs](https://golangci-lint.run/usage/install/)
- Git

## Development setup

```bash
git clone https://github.com/AgentSafe-AI/tooltrust-scanner.git
cd tooltrust-scanner
go mod download
make test
golangci-lint run   # matches CI; optional: make lint for go vet only
```

## Workflow

1. **Fork** the repo and create a branch from `main`.
2. **Make changes** — follow the [TDD workflow](../.cursor/skills/tdd-go/SKILL.md): write failing tests first, then implement, then refactor.
3. **Run checks** — `make test` must pass; **`golangci-lint run`** must pass for CI parity (`make lint` runs `go vet` only—see [docs/DEVELOPER.md](docs/DEVELOPER.md)).
4. **Commit** — use conventional commits: `feat:`, `fix:`, `docs:`, `chore:`.
5. **Open a PR** — target `main` and describe your change. Link any related issues.

## Adding a new scan rule

See [docs/DEVELOPER.md#adding-a-new-scan-rule](docs/DEVELOPER.md#adding-a-new-scan-rule) for the step-by-step guide. Summary:

1. Create `pkg/analyzer/<rule>.go` implementing the `checker` interface.
2. Assign the next available rule ID (e.g. `AS-006`) in each `model.Issue`.
3. Register the checker in `NewScanner()` in `pkg/analyzer/analyzer.go`.
4. Write `pkg/analyzer/<rule>_test.go` following TDD.
5. Update the [rule table](../README.md#what-it-catches) in `README.md`.

## Adding a new protocol adapter

See [docs/DEVELOPER.md#adding-a-new-protocol-adapter](docs/DEVELOPER.md#adding-a-new-protocol-adapter).

## Code style

- Format: `make fmt` (runs `go fmt`)
- Lint: **`golangci-lint run`** — must pass with zero issues (CI). `make lint` runs `go vet` only.
- Tests: `make test` — race detector enabled; all tests must pass

## Questions

- **Bug reports** — use [GitHub Issues](https://github.com/AgentSafe-AI/tooltrust-scanner/issues).
- **Feature requests** — open an issue with the `enhancement` label.
- **Security** — see [docs/SECURITY.md](SECURITY.md).

## For AI agents

### Always

- Run **`go test ./...`** or **`make test`** before proposing merges.
- Keep **copy-paste commands** in docs aligned with real flags and binaries (`tooltrust-scanner`, not `tooltrust-scan`).
- Document new checkers in [docs/RULES.md](RULES.md) and the [What it catches](../README.md#what-it-catches) table.

### Ask first

- Changing **severity weights** or checker registration in `pkg/analyzer`.
- Changing **`gateway.Evaluate`** policy thresholds or rate-limit behavior.
- Adding **third-party dependencies** or new **network** behavior.

### Never

- Delete or skip failing tests; commit secrets; document **OpenAI/Skills file scans** as supported (adapters are **stubs**).
- Claim **runtime sandboxing** of arbitrary MCP servers, **signed audit chains**, **AS-012**, or **micro-VM / QEMU** features not implemented in this repo.

**Protocols:** `--protocol mcp` is what works for **`--input`** and **`--server`**. **`openai`** and **`skills`** adapters exist but **`Parse` is not implemented**—do not generate OpenAI/Skills file-scan commands.

## Add a trust badge

Show your server's ToolTrust grade:

```markdown
[![ToolTrust Grade A](https://img.shields.io/badge/ToolTrust-Grade%20A-brightgreen)](https://www.tooltrust.dev/)
```

> [![ToolTrust Grade A](https://img.shields.io/badge/ToolTrust-Grade%20A-brightgreen)](https://www.tooltrust.dev/)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
