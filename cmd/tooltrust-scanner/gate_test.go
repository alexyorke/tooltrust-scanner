package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kballard/go-shellquote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestDeriveServerName_Scoped(t *testing.T) {
	got := deriveServerName("@modelcontextprotocol/server-memory")
	want := "server-memory"
	if got != want {
		t.Errorf("deriveServerName(@modelcontextprotocol/server-memory) = %q, want %q", got, want)
	}
}

func TestDeriveServerName_Unscoped(t *testing.T) {
	got := deriveServerName("some-package")
	want := "some-package"
	if got != want {
		t.Errorf("deriveServerName(some-package) = %q, want %q", got, want)
	}
}

func TestDeriveServerName_StripsVersionSuffix(t *testing.T) {
	cases := map[string]string{
		"some-package@1.2.3":                        "some-package",
		"@modelcontextprotocol/server-memory@2.0.0": "server-memory",
	}
	for input, want := range cases {
		if got := deriveServerName(input); got != want {
			t.Fatalf("deriveServerName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBuildServerCommand_NoExtraArgs(t *testing.T) {
	got := buildServerCommand("@modelcontextprotocol/server-memory", nil)
	want := "npx -y @modelcontextprotocol/server-memory"
	if got != want {
		t.Errorf("buildServerCommand() = %q, want %q", got, want)
	}
}

func TestBuildServerCommand_WithExtraArgs(t *testing.T) {
	got := buildServerCommand("@modelcontextprotocol/server-filesystem", []string{"/tmp", "/home"})
	want := "npx -y @modelcontextprotocol/server-filesystem /tmp /home"
	if got != want {
		t.Errorf("buildServerCommand() = %q, want %q", got, want)
	}
}

func TestBuildServerCommand_PreservesExtraArgWithSpaces(t *testing.T) {
	got := buildServerCommand("@modelcontextprotocol/server-filesystem", []string{"C:/Users/Alice/My Project"})

	args, err := shellquote.Split(got)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"npx", "-y", "@modelcontextprotocol/server-filesystem", "C:/Users/Alice/My Project"}
	if len(args) != len(want) {
		t.Fatalf("args length = %d, want %d (%q)", len(args), len(want), got)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q (command %q)", i, args[i], want[i], got)
		}
	}
}

func TestGateDecision_GradeA_AutoProceed(t *testing.T) {
	got := gateDecision(model.GradeA, model.GradeF, false)
	if !got {
		t.Error("expected grade A to auto-proceed")
	}
}

func TestGateDecision_GradeB_AutoProceed(t *testing.T) {
	got := gateDecision(model.GradeB, model.GradeF, false)
	if !got {
		t.Error("expected grade B to auto-proceed")
	}
}

func TestGateDecision_GradeF_BlockedDefault(t *testing.T) {
	got := gateDecision(model.GradeF, model.GradeF, false)
	if got {
		t.Error("expected grade F to be blocked with default block-on=F")
	}
}

func TestGateDecision_GradeD_BlockedCustom(t *testing.T) {
	got := gateDecision(model.GradeD, model.GradeD, false)
	if got {
		t.Error("expected grade D to be blocked with block-on=D")
	}
}

func TestGateDecision_Force_Bypasses(t *testing.T) {
	got := gateDecision(model.GradeF, model.GradeF, true)
	if !got {
		t.Error("expected --force to bypass grade F block")
	}
}

func TestRunGate_DryRunStillValidatesBlockOn(t *testing.T) {
	prev := scanLiveServerFn
	scanLiveServerFn = func(context.Context, string) ([]model.UnifiedTool, error) {
		t.Fatal("scanLiveServerFn should not be called when --block-on is invalid")
		return nil, nil
	}
	t.Cleanup(func() {
		scanLiveServerFn = prev
	})

	err := runGate(context.Background(), gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		dryRun:      true,
		blockOn:     "bogus",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --block-on")
}

func TestRunGate_DryRunStillValidatesScope(t *testing.T) {
	prev := scanLiveServerFn
	scanLiveServerFn = func(context.Context, string) ([]model.UnifiedTool, error) {
		t.Fatal("scanLiveServerFn should not be called when --scope is invalid")
		return nil, nil
	}
	t.Cleanup(func() {
		scanLiveServerFn = prev
	})

	err := runGate(context.Background(), gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		dryRun:      true,
		blockOn:     "F",
		scope:       "bogus",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --scope")
}

func TestRunGate_RejectsWhitespaceOnlyExplicitServerName(t *testing.T) {
	prev := scanLiveServerFn
	scanLiveServerFn = func(context.Context, string) ([]model.UnifiedTool, error) {
		t.Fatal("scanLiveServerFn should not be called when --name is invalid")
		return nil, nil
	}
	t.Cleanup(func() {
		scanLiveServerFn = prev
	})

	err := runGate(context.Background(), gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		name:        "   ",
		blockOn:     "F",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --name")
}

func TestRunGate_RejectsWhitespaceOnlyPackageName(t *testing.T) {
	prev := scanLiveServerFn
	scanLiveServerFn = func(context.Context, string) ([]model.UnifiedTool, error) {
		t.Fatal("scanLiveServerFn should not be called when package name is invalid")
		return nil, nil
	}
	t.Cleanup(func() {
		scanLiveServerFn = prev
	})

	err := runGate(context.Background(), gateOpts{
		packageName: "   ",
		blockOn:     "F",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid package")
}

func TestRunGate_RejectsPackageNameThatDerivesBlankServerName(t *testing.T) {
	prev := scanLiveServerFn
	scanLiveServerFn = func(context.Context, string) ([]model.UnifiedTool, error) {
		t.Fatal("scanLiveServerFn should not be called when derived server name is invalid")
		return nil, nil
	}
	t.Cleanup(func() {
		scanLiveServerFn = prev
	})

	err := runGate(context.Background(), gateOpts{
		packageName: "@broken/",
		blockOn:     "F",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid package")
}

func TestRunGate_RejectsInstallWhenServerExposesNoTools(t *testing.T) {
	prev := scanLiveServerFn
	scanLiveServerFn = func(context.Context, string) ([]model.UnifiedTool, error) {
		return nil, nil
	}
	t.Cleanup(func() {
		scanLiveServerFn = prev
	})

	dir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	err = runGate(context.Background(), gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		blockOn:     "F",
		scope:       "project",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no tools")
	assert.NoFileExists(t, filepath.Join(dir, ".mcp.json"))
}

func TestInstallViaConfig_CreatesNew(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".mcp.json")

	opts := gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		extraArgs:   []string{"/tmp"},
		scope:       "project",
	}

	// Temporarily override resolveConfigPath by writing directly.
	cfg := mcpConfig{MCPServers: make(map[string]mcpServerEntry)}
	serverArgs := []string{"-y", opts.packageName}
	serverArgs = append(serverArgs, opts.extraArgs...)
	cfg.MCPServers["server-memory"] = mcpServerEntry{
		Command: "npx",
		Args:    serverArgs,
	}

	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if wErr := os.WriteFile(configPath, encoded, 0o644); wErr != nil {
		t.Fatal(wErr)
	}

	// Read it back and verify.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	var got mcpConfig
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}

	entry, ok := got.MCPServers["server-memory"]
	if !ok {
		t.Fatal("expected server-memory entry in config")
	}
	if entry.Command != "npx" {
		t.Errorf("command = %q, want %q", entry.Command, "npx")
	}
	wantArgs := []string{"-y", "@modelcontextprotocol/server-memory", "/tmp"}
	if len(entry.Args) != len(wantArgs) {
		t.Fatalf("args length = %d, want %d", len(entry.Args), len(wantArgs))
	}
	for i, arg := range wantArgs {
		if entry.Args[i] != arg {
			t.Errorf("args[%d] = %q, want %q", i, entry.Args[i], arg)
		}
	}
}

func TestInstallViaConfig_MergesExisting(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".mcp.json")

	// Write an existing config with another server.
	existing := mcpConfig{
		MCPServers: map[string]mcpServerEntry{
			"existing-server": {
				Command: "node",
				Args:    []string{"server.js"},
			},
		},
	}
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if wErr := os.WriteFile(configPath, data, 0o644); wErr != nil {
		t.Fatal(wErr)
	}

	// Simulate adding a new server by reading, merging, and writing.
	readData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg mcpConfig
	if uErr := json.Unmarshal(readData, &cfg); uErr != nil {
		t.Fatal(uErr)
	}

	cfg.MCPServers["server-memory"] = mcpServerEntry{
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-memory"},
	}

	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if wErr := os.WriteFile(configPath, encoded, 0o644); wErr != nil {
		t.Fatal(wErr)
	}

	// Read back and verify both servers exist.
	finalData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var got mcpConfig
	if err := json.Unmarshal(finalData, &got); err != nil {
		t.Fatal(err)
	}

	if len(got.MCPServers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(got.MCPServers))
	}
	if _, ok := got.MCPServers["existing-server"]; !ok {
		t.Error("existing-server was not preserved")
	}
	if _, ok := got.MCPServers["server-memory"]; !ok {
		t.Error("server-memory was not added")
	}
}

func TestInstallViaConfig_PreservesUserClaudeConfigFields(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	configPath := filepath.Join(dir, ".claude.json")
	existing := []byte(`{
  "projects": {
    "/repo": {
      "allowedTools": ["Read"]
    }
  },
  "mcpServers": {
    "existing-server": {
      "command": "node",
      "args": ["server.js"]
    }
  }
}`)
	if err := os.WriteFile(configPath, existing, 0o644); err != nil {
		t.Fatal(err)
	}

	err := installViaConfig("server-memory", gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		scope:       "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["projects"]; !ok {
		t.Fatal("projects field was not preserved")
	}

	var got mcpConfig
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.MCPServers["existing-server"]; !ok {
		t.Error("existing-server was not preserved")
	}
	if _, ok := got.MCPServers["server-memory"]; !ok {
		t.Error("server-memory was not added")
	}
}

func TestInstallViaConfig_ReadErrorOnExistingProjectConfigSurfaces(t *testing.T) {
	dir := t.TempDir()

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	require.NoError(t, os.Mkdir(".mcp.json", 0o755))

	err = installViaConfig("server-memory", gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		scope:       "project",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read existing config .mcp.json")
}

func TestInstallViaCLI_PassesProjectScopeExplicitly(t *testing.T) {
	dir := t.TempDir()
	fakeClaude := buildFakeClaude(t, dir)
	argvPath := filepath.Join(dir, "argv.txt")
	t.Setenv("CLAUDE_ARGV_OUT", argvPath)

	err := installViaCLI(context.Background(), fakeClaude, "server-memory", gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		scope:       "project",
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(argvPath)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(data))
	want := []string{"mcp", "add", "server-memory", "-s", "project", "--", "npx", "-y", "@modelcontextprotocol/server-memory"}
	if len(got) != len(want) {
		t.Fatalf("argv length = %d, want %d: %q", len(got), len(want), string(data))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q (argv %q)", i, got[i], want[i], string(data))
		}
	}
}

func TestInstallServer_FallsBackToConfigWhenClaudeCLIExecutionFails(t *testing.T) {
	dir := t.TempDir()
	fakeClaude := buildFailingClaude(t, dir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	err := installServer(context.Background(), gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		scope:       "project",
	}, "server-memory", "npx -y @modelcontextprotocol/server-memory")
	require.NoError(t, err)

	data, readErr := os.ReadFile(filepath.Join(dir, ".mcp.json"))
	require.NoError(t, readErr)

	var got mcpConfig
	require.NoError(t, json.Unmarshal(data, &got))
	entry, ok := got.MCPServers["server-memory"]
	require.True(t, ok)
	assert.Equal(t, "npx", entry.Command)
	assert.Equal(t, []string{"-y", "@modelcontextprotocol/server-memory"}, entry.Args)

	_ = fakeClaude
}

func buildFakeClaude(t *testing.T, dir string) string {
	t.Helper()

	sourcePath := filepath.Join(dir, "fake_claude.go")
	source := `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	path := os.Getenv("CLAUDE_ARGV_OUT")
	if path == "" {
		fmt.Fprintln(os.Stderr, "CLAUDE_ARGV_OUT is not set")
		os.Exit(2)
	}
	if err := os.WriteFile(path, []byte(strings.Join(os.Args[1:], " ")), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "fake-claude")
	if strings.EqualFold(filepath.Ext(os.Args[0]), ".exe") {
		binaryPath += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, sourcePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake claude: %v\n%s", err, out)
	}
	return binaryPath
}

func buildFailingClaude(t *testing.T, dir string) string {
	t.Helper()

	sourcePath := filepath.Join(dir, "failing_claude.go")
	source := `package main

import "os"

func main() {
	os.Exit(1)
}
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "claude")
	if strings.EqualFold(filepath.Ext(os.Args[0]), ".exe") {
		binaryPath += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, sourcePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failing claude: %v\n%s", err, out)
	}
	return binaryPath
}
