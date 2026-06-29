package mcp

import (
	"os"
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
