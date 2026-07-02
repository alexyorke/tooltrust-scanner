package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/jsonschema"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// ── tooltrust_scanner_scan tests ────────────────────────────────────────────

func TestHandleScanJSON_ValidInput(t *testing.T) {
	toolsJSON := `{"tools":[{"name":"read_file","description":"Reads a file from disk","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}`
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"tools_json": toolsJSON}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)

	require.Len(t, result.Content, 1)

	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "Scan Summary:")
	assert.Contains(t, text, "Tool Grades:")
	assert.Contains(t, text, "Findings by Severity:")
	// AS-002 now emits a single Info CAPABILITY_SURFACE summary (weight 0).
	// read_file with a "path" property infers FS permission → one AS-002 Info.
	// AS-014 also emits one Info (no dependency metadata on this JSON-only tool).
	// Both are Info (weight 0) → score 0 → Grade A.
	assert.Contains(t, text, "INFO×2")
	assert.Contains(t, text, "2 total")
	assert.NotContains(t, text, "Flagged Tools:")
	assert.Contains(t, text, "All tools are ✅ GRADE A and allowed.")
	assert.Contains(t, text, "1 tools")
}

func TestHandleScanJSON_EmptyToolsJSON(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"tools_json": ""}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleScanJSON_MissingArgument(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleScanJSON_InvalidJSON(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"tools_json": "not valid json"}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleScanJSON_UnsupportedProtocol(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"tools_json": `{"tools":[]}`,
		"protocol":   "openapi",
	}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "unsupported protocol")
}

func TestHandleScanJSON_EmptyToolsList(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"tools_json": `{"tools":[]}`}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)

	require.Len(t, result.Content, 1)
	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "Scan Summary:")
	assert.Contains(t, text, "0 tools")
	assert.Contains(t, text, "Tool Grades: None")
	assert.Contains(t, text, "Findings by Severity: None (0 total)")
	assert.Contains(t, text, "All tools are ✅ GRADE A")
}

func TestRenderTextReport_IncludesEvidenceForFlaggedTools(t *testing.T) {
	result := &ScanResult{
		Summary: ScanSummary{
			Total:           1,
			Allowed:         0,
			RequireApproval: 1,
			Blocked:         0,
		},
		Policies: []model.GatewayPolicy{
			{
				ToolName: "send_env",
				Action:   model.ActionRequireApproval,
				Score: model.RiskScore{
					Grade: model.GradeC,
					Issues: []model.Issue{
						{
							RuleID:      "AS-002",
							Severity:    model.SeverityHigh,
							Description: "tool declares network permission",
							Evidence: []model.Evidence{
								{Kind: "permission", Value: "network"},
								{Kind: "schema_property_count", Value: "12"},
							},
						},
					},
				},
			},
		},
	}

	text := renderTextReport(result)
	assert.Contains(t, text, "Flagged Tools:")
	assert.Contains(t, text, "Evidence: permission=network")
	assert.Contains(t, text, "Evidence: … 1 more item(s)")
	assert.NotContains(t, text, "schema_property_count=12")
}

func TestRenderTextReport_IncludesBehaviorAndDestinationContext(t *testing.T) {
	result := &ScanResult{
		Summary: ScanSummary{
			Total:           1,
			Allowed:         0,
			RequireApproval: 1,
			Blocked:         0,
		},
		Policies: []model.GatewayPolicy{
			{
				ToolName:     "send_email",
				Action:       model.ActionRequireApproval,
				Behavior:     []string{"reads_env", "uses_network"},
				Destinations: []string{"dynamic email recipient (bcc)", "hardcoded domain: api.postmarkapp.com"},
				Score:        model.RiskScore{Grade: model.GradeC},
			},
		},
	}

	text := renderTextReport(result)
	assert.Contains(t, text, "Behavior: reads_env, uses_network")
	assert.Contains(t, text, "Destination: dynamic email recipient (bcc); hardcoded domain: api.postmarkapp.com")
}

func TestRenderTextReport_OmitsDependencyVisibilityContext(t *testing.T) {
	result := &ScanResult{
		Summary: ScanSummary{
			Total:           1,
			Allowed:         0,
			RequireApproval: 1,
			Blocked:         0,
		},
		Policies: []model.GatewayPolicy{
			{
				ToolName:     "deploy_site",
				Action:       model.ActionRequireApproval,
				Behavior:     []string{"uses_network"},
				Destinations: []string{"dynamic URL input (url)"},
				Score:        model.RiskScore{Grade: model.GradeC},
			},
		},
	}

	text := renderTextReport(result)
	assert.NotContains(t, text, "Dependency visibility:")
	assert.NotContains(t, text, "dependency artifacts scanned")
}

func TestRenderTextReport_CapabilitySurfaceUsesCurrentAS002WordingAndKeepsNetworkFSGuidance(t *testing.T) {
	result := &ScanResult{
		Summary: ScanSummary{
			Total:           1,
			Allowed:         0,
			RequireApproval: 1,
			Blocked:         0,
		},
		Policies: []model.GatewayPolicy{
			{
				ToolName: "send_env",
				Action:   model.ActionRequireApproval,
				Score: model.RiskScore{
					Grade: model.GradeC,
					Issues: []model.Issue{
						{
							RuleID:      "AS-002",
							Code:        "CAPABILITY_SURFACE",
							Severity:    model.SeverityInfo,
							Description: "declared capabilities: network access, filesystem access",
							Evidence: []model.Evidence{
								{Kind: "capability", Value: "network"},
								{Kind: "capability", Value: "fs"},
							},
						},
					},
				},
			},
		},
	}

	text := renderTextReport(result)
	assert.Contains(t, text, "declared capabilities: network access, filesystem access")
	assert.Contains(t, text, "Safer configuration:")
	assert.Contains(t, text, "confirm the tool truly needs network access")
	assert.Contains(t, text, "limit filesystem access to the intended directories only")
}

func TestRenderTextReport_DoesNotAddCapabilitySpecificExecOrHTTPAdvice(t *testing.T) {
	result := &ScanResult{
		Summary: ScanSummary{
			Total:           1,
			Allowed:         0,
			RequireApproval: 1,
			Blocked:         0,
		},
		Policies: []model.GatewayPolicy{
			{
				ToolName: "run_command",
				Action:   model.ActionRequireApproval,
				Score: model.RiskScore{
					Grade: model.GradeC,
					Issues: []model.Issue{
						{
							RuleID:      "AS-002",
							Code:        "CAPABILITY_SURFACE",
							Severity:    model.SeverityInfo,
							Description: "declared capabilities: code/command execution, HTTP requests",
							Evidence: []model.Evidence{
								{Kind: "capability", Value: "exec"},
								{Kind: "capability", Value: "http"},
							},
						},
					},
				},
			},
		},
	}

	text := renderTextReport(result)
	assert.Contains(t, text, "declared capabilities: code/command execution, HTTP requests")
	assert.NotContains(t, text, "remove code/command execution if it is not required")
	assert.NotContains(t, text, "remove HTTP requests if it is not required")
}

func TestProcessToolsRaw_PopulatesBehaviorAndDestinationContext(t *testing.T) {
	tools := []model.UnifiedTool{
		{
			Name:        "fetch_url",
			Description: "Fetch a remote resource over HTTPS.",
			Permissions: []model.Permission{model.PermissionNetwork},
			InputSchema: jsonschema.Schema{
				Properties: map[string]jsonschema.Property{
					"url": {Type: "string"},
				},
			},
		},
	}

	result, err := processToolsRaw(context.Background(), tools)
	require.NoError(t, err)
	require.Len(t, result.Policies, 1)
	assert.Equal(t, []string{"uses_network"}, result.Policies[0].Behavior)
	assert.Equal(t, []string{"dynamic URL input (url)"}, result.Policies[0].Destinations)
}

func TestProcessToolsRaw_UsesScannerJSONSummaryContract(t *testing.T) {
	tools := []model.UnifiedTool{
		{
			Name:        "read_file",
			Description: "Reads a file from disk.",
			InputSchema: jsonschema.Schema{
				Properties: map[string]jsonschema.Property{
					"path": {Type: "string"},
				},
			},
		},
	}

	result, err := processToolsRaw(context.Background(), tools)
	require.NoError(t, err)

	encoded, err := json.Marshal(result)
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(encoded, &payload))

	assert.Equal(t, "1.0", payload["schema_version"])

	summary, ok := payload["summary"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, summary, "require_approval")
	assert.NotContains(t, summary, "requireApproval")
	assert.Equal(t, float64(1), summary["allowed"])
	assert.Equal(t, float64(0), summary["avg_score"])
	assert.Equal(t, "A", summary["avg_grade"])

	scannedAt, ok := summary["scanned_at"].(string)
	require.True(t, ok)
	_, err = time.Parse(time.RFC3339, scannedAt)
	require.NoError(t, err)
}

func TestScanOneServer_EmptyToolServerUsesScannerSummaryContract(t *testing.T) {
	serverDir := createTempEmptyMCPServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := scanOneServer(ctx, "empty-server", mcpServerEntry{
		Command: "go",
		Args:    []string{"run", serverDir},
	})

	require.Equal(t, "ok", result.Status)
	require.NotNil(t, result.Result)
	assert.Equal(t, 0, result.Result.Summary.Total)
	assert.Equal(t, 0, result.Result.Summary.Allowed)
	assert.Equal(t, 0, result.Result.Summary.RequireApproval)
	assert.Equal(t, 0, result.Result.Summary.Blocked)
	assert.Equal(t, 0, result.Result.Summary.AvgScore)
	assert.Equal(t, "A", result.Result.Summary.AvgGrade)
	assert.False(t, result.Result.Summary.ScannedAt.IsZero())

	encoded, err := json.Marshal(result.Result)
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(encoded, &payload))

	assert.Equal(t, "1.0", payload["schema_version"])
	policies, ok := payload["policies"].([]any)
	require.True(t, ok)
	assert.Empty(t, policies)

	summary, ok := payload["summary"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "A", summary["avg_grade"])
	assert.NotEqual(t, "0001-01-01T00:00:00Z", summary["scanned_at"])
}

// ── tooltrust_scan_server tests ─────────────────────────────────────────────

func TestHandleScanServer_EmptyCommand(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"command": ""}

	result, err := handleScanServer(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleScanServer_WhitespaceOnlyCommand(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"command": "   "}

	result, err := handleScanServer(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "command argument is required")
}

func TestHandleScanServer_MissingArgument(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleScanServer(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleScanServer_InvalidCommand(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"command": "/nonexistent/command/that/does/not/exist"}

	result, err := handleScanServer(context.Background(), req)
	require.NoError(t, err)
	// Should return error text (not crash), because the command can't be found.
	assert.False(t, result.IsError) // returned as text, not error
	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "Failed to scan live server")
}

func TestHandleScanServer_EmptyToolServerReturnsStructuredReport(t *testing.T) {
	serverDir := createTempEmptyMCPServer(t)

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"command": `go run "` + serverDir + `"`}

	result, err := handleScanServer(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)

	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "Scan Summary:")
	assert.Contains(t, text, "0 tools")
	assert.Contains(t, text, "Tool Grades: None")
	assert.Contains(t, text, "Findings by Severity: None (0 total)")
}

func TestHandleScanServer_CommandWithLeadingEnvAssignments(t *testing.T) {
	serverDir := createTempEmptyMCPServer(t)

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"command": `TOOLTRUST_TEST_MODE=1 go run "` + serverDir + `"`}

	result, err := handleScanServer(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)

	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "Scan Summary:")
	assert.Contains(t, text, "0 tools")
	assert.Contains(t, text, "Tool Grades: None")
	assert.Contains(t, text, "Findings by Severity: None (0 total)")
}

// ── tooltrust_lookup tests ──────────────────────────────────────────────────

func TestHandleLookup_MissingArgument(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleLookup(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleLookup_EmptyName(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"server_name": ""}

	result, err := handleLookup(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleLookup_WhitespaceOnlyName(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"server_name": "   "}

	result, err := handleLookup(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "server_name argument is required")
}

func TestHandleLookup_RejectsNonKebabServerNameBeforeHTTP(t *testing.T) {
	origTransport := http.DefaultClient.Transport
	t.Cleanup(func() {
		http.DefaultClient.Transport = origTransport
	})

	called := false
	http.DefaultClient.Transport = roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     make(http.Header),
		}, nil
	})

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"server_name": "../README"}

	result, err := handleLookup(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
	assert.False(t, called, "invalid server name should be rejected before any HTTP request")
	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "server_name must be a kebab-case identifier")
}

// ── tooltrust_list_rules tests ──────────────────────────────────────────────

func TestHandleListRules_ReturnsAllRules(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleListRules(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)

	var rules []map[string]string
	text := result.Content[0].(mcplib.TextContent).Text
	require.NoError(t, json.Unmarshal([]byte(text), &rules))
	assert.Len(t, rules, 16, "should return all 16 built-in rules")

	// Verify expected rule IDs.
	ids := make(map[string]bool)
	for _, r := range rules {
		ids[r["id"]] = true
		assert.NotEmpty(t, r["title"], "rule %s should have a title", r["id"])
		assert.NotEmpty(t, r["description"], "rule %s should have a description", r["id"])
	}
	expectedIDs := []string{"AS-001", "AS-002", "AS-003", "AS-004", "AS-005", "AS-006", "AS-007", "AS-008", "AS-009", "AS-010", "AS-011", "AS-013", "AS-014", "AS-015", "AS-016", "AS-017"}
	for _, id := range expectedIDs {
		assert.True(t, ids[id], "missing rule %s", id)
	}
}

// ── tooltrust_scan_config tests ─────────────────────────────────────────────

func TestLoadMCPConfig_DotMCPJSON(t *testing.T) {
	dir := t.TempDir()
	configData := `{"mcpServers":{"test-server":{"command":"echo","args":["hello"]}}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(configData), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	path, cfg, err := loadMCPConfig()
	require.NoError(t, err)
	assert.Equal(t, ".mcp.json", path)
	assert.Len(t, cfg.MCPServers, 1)
	assert.Equal(t, "echo", cfg.MCPServers["test-server"].Command)
}

func TestLoadMCPConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte("not json"), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	_, _, err := loadMCPConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse .mcp.json")
}

func TestLoadMCPConfig_LocalReadErrorDoesNotFallBackToHomeConfig(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".mcp.json"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".claude.json"), []byte(`{"mcpServers":{"home-server":{"command":"node"}}}`), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	isolateUserHome(t, dir)

	_, _, err := loadMCPConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read .mcp.json")
}

func TestLoadMCPConfig_NoConfigFound(t *testing.T) {
	dir := t.TempDir()

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	isolateUserHome(t, dir)

	_, _, err := loadMCPConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no MCP config found")
}

func TestLoadMCPConfig_WithEnvVars(t *testing.T) {
	dir := t.TempDir()
	configData := `{"mcpServers":{"api-server":{"command":"node","args":["server.js"],"env":{"API_KEY":"test123","PORT":"3000"}}}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(configData), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	_, cfg, err := loadMCPConfig()
	require.NoError(t, err)
	assert.Equal(t, "test123", cfg.MCPServers["api-server"].Env["API_KEY"])
	assert.Equal(t, "3000", cfg.MCPServers["api-server"].Env["PORT"])
}

func TestLoadMCPConfig_EmptyServers(t *testing.T) {
	dir := t.TempDir()
	configData := `{"mcpServers":{}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(configData), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	_, cfg, err := loadMCPConfig()
	require.NoError(t, err)
	assert.Empty(t, cfg.MCPServers)
}

func TestHandleScanConfig_EmptyServers(t *testing.T) {
	dir := t.TempDir()
	configData := `{"mcpServers":{}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(configData), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleScanConfig(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(result.Content[0].(mcplib.TextContent).Text), &payload))
	assert.Equal(t, ".mcp.json", payload["config_file"])

	servers, ok := payload["servers"].([]any)
	require.True(t, ok)
	assert.Empty(t, servers)

	summary, ok := payload["summary"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), summary["total"])
	assert.Equal(t, float64(0), summary["scanned"])
	assert.Equal(t, float64(0), summary["errors"])
	assert.Equal(t, float64(0), summary["skipped"])
}

func TestHandleScanConfig_NoConfigFile(t *testing.T) {
	dir := t.TempDir()

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	isolateUserHome(t, dir)

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleScanConfig(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestSortedMCPServerNames_Deterministic(t *testing.T) {
	got := sortedMCPServerNames(map[string]mcpServerEntry{
		"zeta":  {Command: "node"},
		"alpha": {Command: "node"},
		"beta":  {Command: "node"},
	})

	assert.Equal(t, []string{"alpha", "beta", "zeta"}, got)
}

func TestScanOneServer_MissingCommandReturnsError(t *testing.T) {
	result := scanOneServer(context.Background(), "bad-server", mcpServerEntry{
		Args: []string{"server.js"},
	})

	assert.Equal(t, "bad-server", result.Server)
	assert.Equal(t, "error", result.Status)
	assert.Contains(t, result.Error, "empty server command")
}

func isolateUserHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")
}

func createTempEmptyMCPServer(t *testing.T) string {
	t.Helper()

	repoRoot, err := filepath.Abs(filepath.Join(".", "..", ".."))
	require.NoError(t, err)

	workDir := filepath.Join(repoRoot, "work")
	require.NoError(t, os.MkdirAll(workDir, 0o755))

	dir, err := os.MkdirTemp(workDir, "empty-mcp-server-")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

	const source = `package main

import (
	"log"

	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("empty-server", "1.0.0", server.WithToolCapabilities(true))
	if err := server.ServeStdio(s); err != nil {
		log.Fatal(err)
	}
}
`

	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o644))

	absDir, err := filepath.Abs(dir)
	require.NoError(t, err)
	return absDir
}

// ── Self-scan skip tests ────────────────────────────────────────────────────

func TestIsSelfEntry_ByName(t *testing.T) {
	assert.True(t, isSelfEntry("tooltrust", mcpServerEntry{Command: "node", Args: []string{"server.js"}}))
	assert.True(t, isSelfEntry("ToolTrust-Scanner", mcpServerEntry{Command: "node"}))
}

func TestIsSelfEntry_ByCommand(t *testing.T) {
	assert.True(t, isSelfEntry("my-scanner", mcpServerEntry{Command: "npx", Args: []string{"-y", "tooltrust-mcp"}}))
	assert.True(t, isSelfEntry("scanner", mcpServerEntry{Command: "tooltrust-mcp"}))
}

func TestIsSelfEntry_NotSelf(t *testing.T) {
	assert.False(t, isSelfEntry("filesystem", mcpServerEntry{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem"}}))
	assert.False(t, isSelfEntry("memory", mcpServerEntry{Command: "node", Args: []string{"server.js"}}))
}

func TestIsSelfEntry_DoesNotSkipUnrelatedTooltrustName(t *testing.T) {
	assert.False(t, isSelfEntry("tooltrust-helper", mcpServerEntry{Command: "node", Args: []string{"server.js"}}))
	assert.False(t, isSelfEntry("scanner", mcpServerEntry{Command: "go", Args: []string{"run", "/tmp/tooltrust-mcp-helper"}}))
}

// ── scanLiveServer tests ────────────────────────────────────────────────────

func TestScanLiveServer_EmptyArgs(t *testing.T) {
	_, err := scanLiveServer(context.Background(), []string{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty server command")
}

func TestScanLiveServer_NonexistentCommand(t *testing.T) {
	_, err := scanLiveServer(context.Background(), []string{"/nonexistent/binary"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start transport")
}

func TestScanLiveServer_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := scanLiveServer(ctx, []string{"echo"}, nil)
	require.Error(t, err)
}

func TestScanLiveServer_WithExtraEnv(t *testing.T) {
	// This tests that extra env doesn't cause a panic.
	// The command will fail (echo is not an MCP server), but we're testing
	// that env merging works without crashing.
	_, err := scanLiveServer(context.Background(), []string{"/nonexistent/binary"}, []string{"TEST_KEY=test_value"})
	require.Error(t, err)
}

// ── processToolsRaw tests ───────────────────────────────────────────────────

func TestProcessToolsRaw_EmptySlice(t *testing.T) {
	result, err := processToolsRaw(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Summary.Total)
}

func TestProcessToolsRaw_SingleCleanTool(t *testing.T) {
	tools := []model.UnifiedTool{
		{
			Name:        "read_file",
			Description: "Reads a file from disk and returns its contents.",
			InputSchema: jsonschema.Schema{
				Type: "object",
				Properties: map[string]jsonschema.Property{
					"path": {Type: "string"},
				},
			},
		},
	}
	result, err := processToolsRaw(context.Background(), tools)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Summary.Total)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
