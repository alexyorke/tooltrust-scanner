# Scanner Scope Guardrails

This document records the intended scope of ToolTrust Scanner so future work
does not gradually turn the MCP scanner into a catch-all security platform.

## Primary Goal

ToolTrust Scanner exists to scan MCP tools and MCP servers before an agent
trusts them.

The core product should stay optimized for:

- MCP tool-definition analysis
- MCP permission and execution-risk analysis
- MCP supply-chain analysis that directly improves MCP install/trust decisions
- MCP-oriented gateway output (`ALLOW`, `APPROVAL`, `BLOCK`)

## What Belongs in the Core Scanner

The following are considered core and should remain first-class:

- MCP adapter and live MCP `tools/list` scanning
- Static tool-definition checks such as prompt injection, privilege, shadowing
- Dependency inventory recovery for MCP servers
- Supply-chain checks that materially change trust decisions:
  - version blacklist
  - OSV/CVE lookup
  - transitive lockfile analysis
  - IOC metadata detection
- Human-readable risk reports and policy decisions

## What Is Allowed but Should Stay Optional

These capabilities are useful, but they should not dominate the main binary or
main code path:

- deep semantic scanning / ONNX-based analysis
- SQLite persistence / historical storage
- threat-intel automation and feed monitoring
- IOC candidate generation and promotion tooling
- future tarball signature extraction or large artifact analysis
- protocol adapters that are not directly needed for MCP scanning

Rule of thumb:

- if a feature helps scan MCP tools directly, it is likely core
- if a feature helps maintain intelligence, history, or future research, it
  should usually be optional or isolated

## What Should Not Inflate the Main Binary by Default

Avoid coupling these tightly into `tooltrust-scanner` unless there is a strong
MCP-first justification:

- heavy ML/runtime dependencies
- large embedded datasets without strong detection value
- continuous threat-intel polling logic
- package-manager-specific execution helpers that are not required for scanning
- non-MCP product experiments

## Decision Checklist for New Features

Before adding a major feature, answer:

1. Does this directly improve MCP trust decisions at scan time?
2. Would most scanner users expect this in the default CLI?
3. Can this be implemented as data instead of more code?
4. Can this live in a separate command, workflow, or optional package instead?
5. Does it materially increase binary size, dependency count, or maintenance load?

If the answer pattern is:

- `yes` to 1 and 2, and `no` to 4 and 5 -> core is reasonable
- `no` to 1 or 2, or `yes` to 4 and 5 -> keep it optional or separate

## Current Guidance

As of March 31, 2026:

- IOC files such as `pkg/analyzer/data/npm_iocs.json` are core enough because
  they directly improve MCP supply-chain detection at low cost.
- Transitive lockfile parsing is core because many MCP servers hide risk in
  indirect dependencies.
- Threat-intel watchers are useful, but should remain workflow/docs/data-pipeline
  concerns rather than expanding the main scan path.
- Deep scan should remain opt-in.

## Preferred Architecture Direction

Keep the project split conceptually into:

- Core scanner: MCP scan, analyzers, gateway decisions, essential supply-chain checks
- Optional intelligence layer: watchers, candidate feeds, promotion workflow
- Optional heavy analysis layer: deep semantic or artifact-intensive analysis

When in doubt, prefer:

- small embedded data files over new code paths
- optional tooling over mandatory runtime dependencies
- MCP-first detection value over generic security breadth
