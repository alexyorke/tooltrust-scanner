package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestEnrichLiveToolsWithLocalDependencyMetadata_PreservesRepoURLNote(t *testing.T) {
	tmp := t.TempDir()

	prevWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() {
		_ = os.Chdir(prevWD)
	})

	tools := EnrichLiveToolsWithLocalDependencyMetadata([]string{"npx", "-y", "example-mcp"}, []model.UnifiedTool{
		{
			Name: "lookup_repo",
			Metadata: map[string]any{
				"repo_url": "https://github.com/example/repo",
			},
		},
	})

	require.Len(t, tools, 1)
	visibility, note := analyzer.DependencyVisibilityForTool(tools[0])
	assert.Equal(t, "Repo URL available", visibility)
	assert.Equal(t, "repo_url is available, so ToolTrust can try to inspect remote lockfiles for dependency evidence.", note)
}

func TestEnrichLiveToolsWithLocalDependencyMetadata_DetectsBarePythonScriptProjectRoot(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "server.py"), []byte("# stub\n"), 0o644))

	prevWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() {
		_ = os.Chdir(prevWD)
	})

	tools := EnrichLiveToolsWithLocalDependencyMetadata([]string{"python", "server.py"}, []model.UnifiedTool{
		{Name: "python_server"},
	})

	require.Len(t, tools, 1)
	visibility, note := analyzer.DependencyVisibilityForTool(tools[0])
	assert.Equal(t, "Verified from local lockfile", visibility)
	assert.Contains(t, note, "Local dependency artifacts scanned")
}

func TestParsePNPMLockKey_NPMAliasUsesRealPackageName(t *testing.T) {
	name, version, ok := parsePNPMLockKey(`/string-width-cjs@npm:string-width@^4.2.3:`)
	require.True(t, ok)
	assert.Equal(t, "string-width", name)
	assert.Equal(t, "^4.2.3", version)
}
