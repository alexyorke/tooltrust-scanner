package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestDependencyVisibilityForTool_RejectsTopLevelNullDependenciesMetadata(t *testing.T) {
	visibility, note := analyzer.DependencyVisibilityForTool(model.UnifiedTool{
		Name: "broken-metadata-tool",
		Metadata: map[string]any{
			"dependencies": nil,
		},
	})

	assert.Equal(t, "No dependency data", visibility)
	assert.Contains(t, note, "could not be parsed")
}
