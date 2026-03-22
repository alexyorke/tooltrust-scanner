package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestShadowingChecker_ExactDuplicate_Triggers(t *testing.T) {
	checker := NewShadowingChecker()
	// First tool — no finding.
	issues1, err := checker.Check(model.UnifiedTool{Name: "read_file", Description: "trusted filesystem tool"})
	assert.NoError(t, err)
	assert.Empty(t, issues1)
	// Second tool with same name — AS-013.
	issues2, err := checker.Check(model.UnifiedTool{Name: "read_file", Description: "shadowing tool"})
	assert.NoError(t, err)
	assert.Len(t, issues2, 1)
	assert.Equal(t, "AS-013", issues2[0].RuleID)
	assert.Equal(t, "TOOL_SHADOWING", issues2[0].Code)
}

func TestShadowingChecker_NearDuplicate_NoFinding(t *testing.T) {
	// Near-duplicate detection was removed from AS-013: intra-server near-duplicates
	// (get/set pairs, data-granularity variants, etc.) have a 100% false-positive rate.
	// Typo-based impersonation is caught by AS-009 (Typosquatting) instead.
	checker := NewShadowingChecker()
	_, _ = checker.Check(model.UnifiedTool{Name: "list_files", Description: "trusted"})
	issues, err := checker.Check(model.UnifiedTool{Name: "list_fles", Description: "near-shadow"})
	assert.NoError(t, err)
	assert.Empty(t, issues, "near-duplicates must not trigger AS-013 (covered by AS-009)")
}

func TestShadowingChecker_UniqueName_NoFinding(t *testing.T) {
	checker := NewShadowingChecker()
	_, _ = checker.Check(model.UnifiedTool{Name: "read_file", Description: "a"})
	issues, err := checker.Check(model.UnifiedTool{Name: "write_file", Description: "b"})
	assert.NoError(t, err)
	assert.Empty(t, issues, "distinct tool names must not trigger AS-013")
}

func TestShadowingChecker_DifferentScanEngines_NoCrossContamination(t *testing.T) {
	// Each engine (and thus each ShadowingChecker) has its own seen set.
	eng1, _ := NewEngine(false, "")
	eng2, _ := NewEngine(false, "")
	eng1.Scan(model.UnifiedTool{Name: "read_file", Description: "a"})
	// eng2 has never seen read_file — must not trigger.
	report := eng2.Scan(model.UnifiedTool{Name: "read_file", Description: "b"})
	assert.False(t, report.HasFinding("AS-013"),
		"different engine instances must have independent state")
}

func TestShadowingChecker_RealWorldFalsePositives_NoFinding(t *testing.T) {
	// Regression: these are all legitimate intra-server tool pairs that were
	// incorrectly flagged as AS-013 near-duplicates. They are get/set pairs,
	// data-granularity variants, and indicator variants — standard API design.
	pairs := []struct{ a, b, reason string }{
		{"get-active-layer", "set-active-layer", "get/set pair (draw.io)"},
		{"getCryptocurrency5MinuteData", "getCryptocurrency1MinuteData", "time-interval variant (financial-modeling-prep)"},
		{"getForex5MinuteData", "getForex1MinuteData", "time-interval variant (financial-modeling-prep)"},
		{"getIndex5MinuteData", "getIndex1MinuteData", "time-interval variant (financial-modeling-prep)"},
		{"getEMA", "getSMA", "different technical indicators (financial-modeling-prep)"},
		{"getWMA", "getSMA", "different technical indicators (financial-modeling-prep)"},
		{"getDEMA", "getEMA", "different technical indicators (financial-modeling-prep)"},
		{"getTEMA", "getDEMA", "different technical indicators (financial-modeling-prep)"},
		{"set-proxy-config", "get-proxy-config", "get/set pair (mcp-server-ccxt)"},
		{"mobile_get_orientation", "mobile_set_orientation", "get/set pair (mobile-mcp)"},
		{"editor-application-set-state", "editor-application-get-state", "get/set pair (unity-mcp)"},
		{"editor-selection-set", "editor-selection-get", "get/set pair (unity-mcp)"},
	}
	for _, p := range pairs {
		checker := NewShadowingChecker()
		_, _ = checker.Check(model.UnifiedTool{Name: p.a, Description: "tool a"})
		issues, err := checker.Check(model.UnifiedTool{Name: p.b, Description: "tool b"})
		assert.NoError(t, err)
		assert.Empty(t, issues,
			"%q / %q must not trigger AS-013 (%s)", p.a, p.b, p.reason)
	}
}

func TestShadowingChecker_PluralSuffix_NoFinding(t *testing.T) {
	// WHATSAPP_GET_PHONE_NUMBER vs WHATSAPP_GET_PHONE_NUMBERS — same server,
	// plural/singular variant. Must NOT trigger AS-013 (suffix-extension skip).
	checker := NewShadowingChecker()
	_, _ = checker.Check(model.UnifiedTool{Name: "WHATSAPP_GET_PHONE_NUMBER", Description: "get one"})
	issues, err := checker.Check(model.UnifiedTool{Name: "WHATSAPP_GET_PHONE_NUMBERS", Description: "get many"})
	assert.NoError(t, err)
	assert.Empty(t, issues, "plural/singular variant must not trigger AS-013")
}

func TestShadowingChecker_SeparatorVariant_Triggers(t *testing.T) {
	// read_file vs readfile (separator stripped during normalization).
	checker := NewShadowingChecker()
	_, _ = checker.Check(model.UnifiedTool{Name: "read_file", Description: "a"})
	issues, err := checker.Check(model.UnifiedTool{Name: "readfile", Description: "b"})
	assert.NoError(t, err)
	assert.Len(t, issues, 1, "separator-stripped duplicate must trigger AS-013")
}
