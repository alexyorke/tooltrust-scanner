package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestExtractDependencies_RejectsTopLevelNull(t *testing.T) {
	t.Parallel()

	_, err := extractDependencies(toolWithMetadataForTest(map[string]any{
		"dependencies": nil,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "supply_chain: dependencies metadata must be an array")
}

func TestCollectDependencies_SkipsNullMetadataEntries(t *testing.T) {
	t.Parallel()

	deps, err := collectDependencies(toolWithMetadataForTest(map[string]any{
		"dependencies": []any{
			nil,
			map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
		},
	}))
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "axios", deps[0].Name)
	assert.Equal(t, "1.14.1", deps[0].Version)
	assert.Equal(t, "npm", deps[0].Ecosystem)
	assert.Equal(t, "metadata", deps[0].Source)
}

func TestCollectDependencies_SkipsEntriesMissingRequiredFields(t *testing.T) {
	t.Parallel()

	deps, err := collectDependencies(toolWithMetadataForTest(map[string]any{
		"dependencies": []any{
			map[string]any{"name": "", "version": "1.14.1", "ecosystem": "npm"},
			map[string]any{"name": "axios", "version": "", "ecosystem": "npm"},
			map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": ""},
			map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
		},
	}))
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "axios", deps[0].Name)
	assert.Equal(t, "1.14.1", deps[0].Version)
	assert.Equal(t, "npm", deps[0].Ecosystem)
	assert.Equal(t, "metadata", deps[0].Source)
}

func toolWithMetadataForTest(meta map[string]any) model.UnifiedTool {
	return model.UnifiedTool{
		Name:     "test-tool",
		Metadata: meta,
	}
}
