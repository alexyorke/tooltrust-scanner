package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestInsufficientDataChecker_EmptyDescription(t *testing.T) {
	checker := analyzer.NewInsufficientDataChecker()

	tool := model.UnifiedTool{
		Name:        "test-tool",
		Description: "   ",
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)

	assert.Len(t, issues, 1)
	assert.Equal(t, "AS-007", issues[0].RuleID)
	assert.Equal(t, model.SeverityInfo, issues[0].Severity)
	assert.Equal(t, "INSUFFICIENT_TOOL_DATA", issues[0].Code)
	assert.Equal(t, "Tool 'test-tool' has no description - agents cannot reason about its purpose, and static analysis coverage is limited", issues[0].Description)
}

func TestInsufficientDataChecker_HasDescription(t *testing.T) {
	checker := analyzer.NewInsufficientDataChecker()

	tool := model.UnifiedTool{
		Name:        "test-tool",
		Description: "This tool does something useful",
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)

	assert.Empty(t, issues)
}
