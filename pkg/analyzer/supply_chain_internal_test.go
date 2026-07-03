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

func toolWithMetadataForTest(meta map[string]any) model.UnifiedTool {
	return model.UnifiedTool{
		Name:     "test-tool",
		Metadata: meta,
	}
}
