package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// ---------------------------------------------------------------------------
// AS-006 — Arbitrary Code Execution (evaluate_script, execute javascript, etc.)
// ---------------------------------------------------------------------------

func TestArbitraryCodeChecker_EvaluateScriptInName(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "evaluate_script",
		Description: "Evaluates a script in the browser context.",
	}
	report := NewEngine().Scan(tool)
	assert.True(t, report.HasFinding("AS-006"), "evaluate_script in name must trigger AS-006")
	assert.GreaterOrEqual(t, report.RiskScore, 25, "must score >= 25 (CRITICAL) to prevent A/S grade")
}

func TestArbitraryCodeChecker_ExecuteJavascriptInDescription(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "run_in_browser",
		Description: "Execute JavaScript in the page context.",
	}
	report := NewEngine().Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_BrowserInjection(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "inject_script",
		Description: "Browser injection of arbitrary code into the target page.",
	}
	report := NewEngine().Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_RunScriptInName(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "run_script",
		Description: "Runs a user-provided script.",
	}
	report := NewEngine().Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_EvalInDescription(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "compute",
		Description: "Uses eval() to evaluate expressions.",
	}
	report := NewEngine().Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_CleanTool_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "list_files",
		Description: "Returns a list of files in the directory.",
	}
	report := NewEngine().Scan(tool)
	assert.False(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_Retrieval_NoFalsePositive(t *testing.T) {
	// "retrieval" contains "eval" but must not trigger (word boundary)
	tool := model.UnifiedTool{
		Name:        "document_retrieval",
		Description: "Retrieval of documents from the index.",
	}
	report := NewEngine().Scan(tool)
	assert.False(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_GradeCOrWorse(t *testing.T) {
	// chrome-devtools-mcp style: evaluate_script should get at least Grade C
	tool := model.UnifiedTool{
		Name:        "evaluate_script",
		Description: "Evaluates JavaScript expression in the browser.",
	}
	report := NewEngine().Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
	assert.Contains(t, []model.Grade{model.GradeC, model.GradeD, model.GradeF}, report.Grade,
		"evaluate_script must not get A or B; got %s", report.Grade)
}
