package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pterm/pterm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestCheckFailOn_Empty(t *testing.T) {
	err := checkFailOn("", ScanSummary{Blocked: 5})
	assert.NoError(t, err)
}

func TestCheckFailOn_BlockWithBlocked(t *testing.T) {
	err := checkFailOn("block", ScanSummary{Total: 3, Blocked: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "BLOCKED")
}

func TestCheckFailOn_BlockWithNoneBlocked(t *testing.T) {
	err := checkFailOn("block", ScanSummary{Total: 3, Allowed: 2, RequireApproval: 1})
	assert.NoError(t, err)
}

func TestCheckFailOn_ApprovalTriggered(t *testing.T) {
	err := checkFailOn("approval", ScanSummary{Total: 3, RequireApproval: 2, Allowed: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "require approval")
}

func TestCheckFailOn_ApprovalNotTriggered(t *testing.T) {
	err := checkFailOn("approval", ScanSummary{Total: 3, Allowed: 3})
	assert.NoError(t, err)
}

func TestCheckFailOn_AllowTriggered(t *testing.T) {
	err := checkFailOn("allow", ScanSummary{Total: 3, Allowed: 1, RequireApproval: 2})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "allowed")
}

func TestCheckFailOn_AllowNotTriggered(t *testing.T) {
	err := checkFailOn("allow", ScanSummary{Total: 3, Allowed: 3})
	assert.NoError(t, err)
}

func TestCheckFailOn_InvalidValue(t *testing.T) {
	err := checkFailOn("bogus", ScanSummary{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --fail-on")
}

func TestNewScanCmd_ProtocolFlagIsMCPOnly(t *testing.T) {
	cmd := newScanCmd()
	flag := cmd.Flags().Lookup("protocol")
	if assert.NotNil(t, flag) {
		assert.Contains(t, flag.Usage, "mcp")
		assert.NotContains(t, flag.Usage, "openai")
		assert.NotContains(t, flag.Usage, "skills")
	}
}

func TestNewScanCmd_OutputFlagListsSupportedFormats(t *testing.T) {
	cmd := newScanCmd()
	flag := cmd.Flags().Lookup("output")
	if assert.NotNil(t, flag) {
		assert.Contains(t, flag.Usage, "text")
		assert.Contains(t, flag.Usage, "json")
		assert.Contains(t, flag.Usage, "sarif")
	}
}

func TestRunScan_InvalidFailOnDoesNotWriteReport(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, "tools.json")
	output := filepath.Join(tmp, "report.json")
	require.NoError(t, os.WriteFile(input, []byte(`{"tools":[]}`), 0o644))

	err := runScan(context.Background(), scanOpts{
		inputFile:  input,
		protocol:   "mcp",
		output:     "json",
		outputFile: output,
		failOn:     "bogus",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --fail-on")
	assert.NoFileExists(t, output)
}

func TestRunScan_JSONOutputDoesNotSuppressLaterTextOutput(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, "tools.json")
	jsonOutput := filepath.Join(tmp, "report.json")
	require.NoError(t, os.WriteFile(input, []byte(`{"tools":[]}`), 0o644))

	prevOutput := pterm.Output
	pterm.EnableOutput()
	t.Cleanup(func() {
		if prevOutput {
			pterm.EnableOutput()
		} else {
			pterm.DisableOutput()
		}
		pterm.SetDefaultOutput(os.Stdout)
	})

	var buf bytes.Buffer
	pterm.SetDefaultOutput(&buf)

	err := runScan(context.Background(), scanOpts{
		inputFile:  input,
		protocol:   "mcp",
		output:     "json",
		outputFile: jsonOutput,
	})
	require.NoError(t, err)

	buf.Reset()

	err = runScan(context.Background(), scanOpts{
		inputFile: input,
		protocol:  "mcp",
		output:    "text",
	})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Scan Summary")
}

func TestRunScan_JSONOutput_EmptyPoliciesUseArray(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, "tools.json")
	output := filepath.Join(tmp, "report.json")
	require.NoError(t, os.WriteFile(input, []byte(`{"tools":[]}`), 0o644))

	err := runScan(context.Background(), scanOpts{
		inputFile:  input,
		protocol:   "mcp",
		output:     "json",
		outputFile: output,
	})
	require.NoError(t, err)

	data, err := os.ReadFile(output)
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(data, &payload))

	policies, ok := payload["policies"].([]any)
	require.True(t, ok)
	assert.Empty(t, policies)
}

func TestWriteOutput_JSONOmitsDependencyVisibilityFields(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.json")
	report := ScanReport{
		SchemaVersion: "1.0",
		Policies: []model.GatewayPolicy{
			{
				ToolName: "read_file",
				Action:   model.ActionAllow,
				Score:    model.RiskScore{Grade: model.GradeA},
			},
		},
		Summary: ScanSummary{
			Total:     1,
			Allowed:   1,
			AvgScore:  0,
			AvgGrade:  "A",
			ScannedAt: time.Now().UTC(),
		},
	}

	require.NoError(t, writeOutput(scanOpts{output: "json", outputFile: out}, report))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "dependency_visibility")
	assert.NotContains(t, string(data), "dependency_note")
}

func TestRunScan_RejectsMCPConfigInput(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, ".mcp.json")
	output := filepath.Join(tmp, "report.json")
	require.NoError(t, os.WriteFile(input, []byte(`{
		"mcpServers": {
			"evil": {
				"command": "npx",
				"args": ["-y", "some-server"]
			}
		}
	}`), 0o644))

	err := runScan(context.Background(), scanOpts{
		inputFile:  input,
		protocol:   "mcp",
		output:     "json",
		outputFile: output,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "MCP tools/list")
	assert.NoFileExists(t, output)
}

func TestRunScan_PersistenceErrorSurfaces(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, "tools.json")
	output := filepath.Join(tmp, "report.json")
	dbPath := filepath.Join(tmp, "missing", "scans.db")
	require.NoError(t, os.WriteFile(input, []byte(`{"tools":[]}`), 0o644))

	err := runScan(context.Background(), scanOpts{
		inputFile:  input,
		protocol:   "mcp",
		output:     "json",
		outputFile: output,
		dbPath:     dbPath,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "persist")
	assert.NoFileExists(t, dbPath)
}

func TestPrintPtermUI_UsesPrecomputedSummary(t *testing.T) {
	prevOutput := pterm.Output
	pterm.EnableOutput()
	t.Cleanup(func() {
		if prevOutput {
			pterm.EnableOutput()
		} else {
			pterm.DisableOutput()
		}
		pterm.SetDefaultOutput(os.Stdout)
	})

	var buf bytes.Buffer
	pterm.SetDefaultOutput(&buf)

	report := ScanReport{
		Policies: []model.GatewayPolicy{
			{
				ToolName: "read_file",
				Action:   model.ActionAllow,
				Score:    model.RiskScore{Score: 1, Grade: model.GradeA},
			},
		},
		Summary: ScanSummary{
			Total:     1,
			Allowed:   1,
			AvgScore:  99,
			AvgGrade:  "Z",
			ScannedAt: time.Now().UTC(),
		},
	}

	require.NoError(t, printPtermUI(report))
	assert.Contains(t, buf.String(), "Avg Risk Score   : 99 (grade Z)")
}

func TestPrintPtermUI_OmitsDependencyVisibilityContext(t *testing.T) {
	prevOutput := pterm.Output
	pterm.EnableOutput()
	t.Cleanup(func() {
		if prevOutput {
			pterm.EnableOutput()
		} else {
			pterm.DisableOutput()
		}
		pterm.SetDefaultOutput(os.Stdout)
	})

	var buf bytes.Buffer
	pterm.SetDefaultOutput(&buf)

	report := ScanReport{
		Policies: []model.GatewayPolicy{
			{
				ToolName: "deploy_site",
				Action:   model.ActionRequireApproval,
				Behavior: []string{"uses_network"},
				Score:    model.RiskScore{Grade: model.GradeC},
			},
		},
		Summary: ScanSummary{
			Total:           1,
			RequireApproval: 1,
			AvgGrade:        "C",
			ScannedAt:       time.Now().UTC(),
		},
	}

	require.NoError(t, printPtermUI(report))
	assert.NotContains(t, buf.String(), "Dependency visibility:")
	assert.NotContains(t, buf.String(), "dependency artifacts")
}

func TestWriteOutput_TextHonorsOutputFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.txt")
	report := ScanReport{
		Policies: []model.GatewayPolicy{},
		Summary: ScanSummary{
			ScannedAt: time.Now().UTC(),
		},
	}

	require.NoError(t, writeOutput(scanOpts{output: "text", outputFile: out}, report))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(data), "Scan Summary")
}

func TestWriteOutput_TextOutputFileRestoresPtermOutput(t *testing.T) {
	prevOutput := pterm.Output
	pterm.EnableOutput()
	t.Cleanup(func() {
		if prevOutput {
			pterm.EnableOutput()
		} else {
			pterm.DisableOutput()
		}
		pterm.SetDefaultOutput(os.Stdout)
	})

	var buf bytes.Buffer
	pterm.SetDefaultOutput(&buf)

	out := filepath.Join(t.TempDir(), "report.txt")
	report := ScanReport{
		Policies: []model.GatewayPolicy{},
		Summary: ScanSummary{
			ScannedAt: time.Now().UTC(),
		},
	}

	require.NoError(t, writeOutput(scanOpts{output: "text", outputFile: out}, report))

	buf.Reset()
	require.NoError(t, printPtermUI(report))
	assert.Contains(t, buf.String(), "Scan Summary")
}

func TestShouldPrintWriteNotice_FileIsNonInteractive(t *testing.T) {
	output, err := os.Create(filepath.Join(t.TempDir(), "stderr.txt"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = output.Close()
	})

	assert.False(t, shouldPrintWriteNotice(output))
	assert.False(t, shouldPrintWriteNotice(nil))
}

func TestFormatToolLabel_HidesScoreForAllowGradeA(t *testing.T) {
	label := formatToolLabel(model.GatewayPolicy{
		ToolName: "read_file",
		Action:   model.ActionAllow,
		Score: model.RiskScore{
			Score: 8,
			Grade: model.GradeA,
		},
	})

	assert.Contains(t, label, "[ALLOW]")
	assert.NotContains(t, label, "score=8")
	assert.NotContains(t, label, "grade=A")
}

func TestFormatToolLabel_KeepsGradeForApproval(t *testing.T) {
	label := formatToolLabel(model.GatewayPolicy{
		ToolName: "search_files",
		Action:   model.ActionRequireApproval,
		Score: model.RiskScore{
			Score: 25,
			Grade: model.GradeC,
		},
	})

	assert.Contains(t, label, "[APPROVAL]")
	assert.Contains(t, label, "grade=C")
	assert.NotContains(t, label, "score=25")
}

func TestFormatIssueLabel_HidesRedundantEvidenceForAllowGradeA(t *testing.T) {
	// AS-002 CAPABILITY_SURFACE is always redundant (capabilities listed in description).
	// For Grade A / Allow tools, shouldSuppressIssueDetail hides evidence and hint.
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-002",
		Severity:    model.SeverityInfo,
		Code:        "CAPABILITY_SURFACE",
		Description: "declared capabilities: filesystem access",
		Evidence: []model.Evidence{
			{Kind: "capability", Value: "fs"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionAllow,
		Score:  model.RiskScore{Grade: model.GradeA},
	}, true)

	assert.Contains(t, label, "• [AS-002] INFO:")
	assert.NotContains(t, label, "Evidence:")
	assert.NotContains(t, label, "Tool requests broad permissions")
}

func TestFormatIssueLabel_HidesRedundantSingleEvidenceForFlaggedTools(t *testing.T) {
	// AS-002 CAPABILITY_SURFACE is always considered redundant (evidence is
	// already stated in the description). For flagged tools, evidence is hidden
	// but the AS-002 hint is still shown.
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-002",
		Severity:    model.SeverityInfo,
		Code:        "CAPABILITY_SURFACE",
		Description: "declared capabilities: network access",
		Evidence: []model.Evidence{
			{Kind: "capability", Value: "network"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score:  model.RiskScore{Grade: model.GradeC},
	}, true)

	assert.Contains(t, label, "• [AS-002] INFO:")
	assert.NotContains(t, label, "Evidence:")
	assert.Contains(t, label, "Tool requests broad permissions")
}

func TestFormatIssueLabel_KeepsCompactEvidenceForNonRedundantFlaggedTools(t *testing.T) {
	// LARGE_INPUT_SURFACE (AS-002, Low) is not redundant — the first evidence item
	// (schema_property_count) is shown; additional items are compacted.
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-002",
		Severity:    model.SeverityLow,
		Code:        "LARGE_INPUT_SURFACE",
		Description: "input schema exposes 15 properties (threshold: 10)",
		Evidence: []model.Evidence{
			{Kind: "schema_property_count", Value: "15"},
			{Kind: "schema_property_threshold", Value: "10"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score:  model.RiskScore{Grade: model.GradeC},
	}, true)

	assert.Contains(t, label, "Evidence: schema_property_count=15")
	assert.Contains(t, label, "… 1 more evidence item(s)")
	assert.NotContains(t, label, "schema_property_threshold=10")
}

func TestFormatIssueLabel_HidesHintWhenAlreadyShownForRule(t *testing.T) {
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-002",
		Severity:    model.SeverityInfo,
		Code:        "CAPABILITY_SURFACE",
		Description: "declared capabilities: network access",
		Evidence: []model.Evidence{
			{Kind: "capability", Value: "network"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score:  model.RiskScore{Grade: model.GradeC},
	}, false)

	assert.Contains(t, label, "• [AS-002] INFO:")
	assert.NotContains(t, label, "Tool requests broad permissions")
}

func TestFormatIssueLabel_ShowsHintForNPMLifecycleScripts(t *testing.T) {
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-015",
		Severity:    model.SeverityMedium,
		Description: "npm package axios@1.14.1 publishes a postinstall lifecycle script (node install.js). Review whether this install-time execution is expected.",
		Evidence: []model.Evidence{
			{Kind: "package", Value: "axios"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score:  model.RiskScore{Grade: model.GradeC},
	}, true)

	assert.Contains(t, label, "• [AS-015] MEDIUM:")
	assert.Contains(t, label, "Review the install-time script before use")
}

func TestSummarizeToolReason_EmptyForAllow(t *testing.T) {
	reason := summarizeToolReason(model.GatewayPolicy{
		Action: model.ActionAllow,
		Score: model.RiskScore{
			Grade: model.GradeA,
			Issues: []model.Issue{
				{
					RuleID:      "AS-002",
					Code:        "CAPABILITY_SURFACE",
					Description: "declared capabilities: filesystem access",
					Evidence:    []model.Evidence{{Kind: "capability", Value: "fs"}},
				},
			},
		},
	})

	assert.Equal(t, "", reason)
}

func TestSummarizeToolReason_ForApproval(t *testing.T) {
	// AS-002 now emits a single CAPABILITY_SURFACE summary.
	// summarizeIssueReason for CAPABILITY_SURFACE strips the "declared capabilities: " prefix.
	reason := summarizeToolReason(model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score: model.RiskScore{
			Grade: model.GradeC,
			Issues: []model.Issue{
				{
					RuleID:      "AS-002",
					Code:        "CAPABILITY_SURFACE",
					Description: "declared capabilities: filesystem access, network access",
					Evidence: []model.Evidence{
						{Kind: "capability", Value: "fs"},
						{Kind: "capability", Value: "network"},
					},
				},
				{
					RuleID:      "AS-011",
					Description: "tool performs network or execution operations but declares no rate-limit, timeout, or retry configuration",
				},
			},
		},
	})

	assert.Equal(t, "filesystem access, network access + missing rate-limit/timeout", reason)
}

func TestToolReasonLabel_ForApproval(t *testing.T) {
	assert.Equal(t, "Why approval: ", toolReasonLabel(model.GatewayPolicy{Action: model.ActionRequireApproval}))
}

func TestToolReasonLabel_ForBlock(t *testing.T) {
	assert.Equal(t, "Why blocked: ", toolReasonLabel(model.GatewayPolicy{Action: model.ActionBlock}))
}

func TestToolContextLines_EmptyForAllowGradeA(t *testing.T) {
	lines := toolContextLines(model.GatewayPolicy{
		Action: model.ActionAllow,
		Score:  model.RiskScore{Grade: model.GradeA},
		Behavior: []string{
			"reads_files",
		},
		Destinations: []string{
			"dynamic URL input (url)",
		},
	})

	assert.Nil(t, lines)
}

func TestToolContextLines_ForFlaggedTool(t *testing.T) {
	lines := toolContextLines(model.GatewayPolicy{
		Action: model.ActionRequireApproval,
		Score:  model.RiskScore{Grade: model.GradeC},
		Behavior: []string{
			"reads_files",
			"uses_network",
		},
		Destinations: []string{
			"dynamic URL input (url)",
			"hardcoded domain: api.postmarkapp.com",
		},
	})

	assert.Equal(t, []string{
		"Behavior: reads_files, uses_network",
		"Destination: dynamic URL input (url); hardcoded domain: api.postmarkapp.com",
	}, lines)
}

func TestFormatIssueLabel_HidesAS014NoiseForAllowGradeA(t *testing.T) {
	label := formatIssueLabel(model.Issue{
		RuleID:      "AS-014",
		Severity:    model.SeverityInfo,
		Description: "Tool did not expose metadata.dependencies or repo_url, so supply-chain coverage is limited.",
		Evidence: []model.Evidence{
			{Kind: "dependency_visibility", Value: "none"},
		},
	}, model.GatewayPolicy{
		Action: model.ActionAllow,
		Score:  model.RiskScore{Grade: model.GradeA},
	}, true)

	assert.Equal(t, "", label)
}

func TestParseRequirementsFile_StripsMarkersAndInlineComments(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "requirements.txt")
	require.NoError(t, os.WriteFile(path, []byte(`
requests==2.31.0 ; python_version >= "3.10"
flask==3.0.0 # web framework
urllib3[socks]==2.2.1
`), 0o644))

	deps, err := parseRequirementsFile(path)
	require.NoError(t, err)
	require.Len(t, deps, 3)
	assert.Equal(t, nodeDependency{Name: "requests", Version: "2.31.0", Ecosystem: "PyPI", Source: "local_lockfile"}, deps[0])
	assert.Equal(t, nodeDependency{Name: "flask", Version: "3.0.0", Ecosystem: "PyPI", Source: "local_lockfile"}, deps[1])
	assert.Equal(t, nodeDependency{Name: "urllib3", Version: "2.2.1", Ecosystem: "PyPI", Source: "local_lockfile"}, deps[2])
}

func TestParsePNPMLockfile_StripsPeerSuffixes(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
packages:
  '/@scope/pkg@1.2.3(peer@2.0.0)':
    resolution: {}
  '/left-pad@1.3.0':
    resolution: {}
`), 0o644))

	deps, err := parsePNPMLockfile(path)
	require.NoError(t, err)
	require.Len(t, deps, 2)
	assert.Contains(t, deps, nodeDependency{Name: "@scope/pkg", Version: "1.2.3", Ecosystem: "npm", Source: "local_lockfile"})
	assert.Contains(t, deps, nodeDependency{Name: "left-pad", Version: "1.3.0", Ecosystem: "npm", Source: "local_lockfile"})
}

func TestParsePNPMLockfile_ModernBarePackageKeys(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
lockfileVersion: '11.0'
packages:
  string-width@4.2.3:
    resolution: {}
  '@scope/pkg@1.2.3(peer@2.0.0)':
    resolution: {}
`), 0o644))

	deps, err := parsePNPMLockfile(path)
	require.NoError(t, err)
	require.Len(t, deps, 2)
	assert.Contains(t, deps, nodeDependency{Name: "string-width", Version: "4.2.3", Ecosystem: "npm", Source: "local_lockfile"})
	assert.Contains(t, deps, nodeDependency{Name: "@scope/pkg", Version: "1.2.3", Ecosystem: "npm", Source: "local_lockfile"})
}

func TestParsePNPMLockfile_NPMAliasUsesRealPackageName(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
lockfileVersion: '11.0'
packages:
  /string-width-cjs@npm:string-width@^4.2.3:
    resolution: {}
`), 0o644))

	deps, err := parsePNPMLockfile(path)
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, nodeDependency{Name: "string-width", Version: "^4.2.3", Ecosystem: "npm", Source: "local_lockfile"}, deps[0])
}
