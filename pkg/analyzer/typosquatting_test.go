package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestTyposquattingChecker_ExactMatch_NoFinding(t *testing.T) {
	// Exact popular tool names must not trigger — they ARE the canonical tool.
	for _, name := range []string{"list_files", "read_file", "brave_web_search"} {
		tool := model.UnifiedTool{Name: name, Description: "canonical tool"}
		eng, _ := NewEngine(false, "")
		report := eng.Scan(tool)
		assert.False(t, report.HasFinding("AS-009"),
			"exact match %q must not trigger AS-009", name)
	}
}

func TestTyposquattingChecker_EditDistance1_Triggers(t *testing.T) {
	cases := []struct {
		name    string
		similar string
	}{
		{"list_fles", "list_files"},               // dropped 'i'
		{"read_fle", "read_file"},                 // dropped 'i'
		{"brave_web_searrch", "brave_web_search"}, // double 'r'
	}
	for _, tc := range cases {
		tool := model.UnifiedTool{Name: tc.name, Description: "unknown tool"}
		eng, _ := NewEngine(false, "")
		report := eng.Scan(tool)
		assert.True(t, report.HasFinding("AS-009"),
			"%q (similar to %q) must trigger AS-009", tc.name, tc.similar)
	}
}

func TestTyposquattingChecker_EditDistance2_Triggers(t *testing.T) {
	tool := model.UnifiedTool{Name: "list_fils", Description: "file listing"} // 2 edits from list_files
	eng, _ := NewEngine(false, "")
	report := eng.Scan(tool)
	assert.True(t, report.HasFinding("AS-009"))
}

func TestTyposquattingChecker_EditDistance3_NoFinding(t *testing.T) {
	// 3+ edits from any known name must NOT trigger.
	tool := model.UnifiedTool{Name: "lst_fls", Description: "file listing"} // 3+ edits
	eng, _ := NewEngine(false, "")
	report := eng.Scan(tool)
	assert.False(t, report.HasFinding("AS-009"),
		"edit distance 3+ must not trigger AS-009")
}

func TestTyposquattingChecker_ShortName_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{Name: "run", Description: "run something"}
	eng, _ := NewEngine(false, "")
	report := eng.Scan(tool)
	assert.False(t, report.HasFinding("AS-009"),
		"short names must not trigger AS-009")
}

func TestTyposquattingChecker_UnrelatedName_NoFinding(t *testing.T) {
	for _, name := range []string{"send_email", "get_weather", "translate_text", "schedule_meeting"} {
		tool := model.UnifiedTool{Name: name, Description: "some tool"}
		eng, _ := NewEngine(false, "")
		report := eng.Scan(tool)
		assert.False(t, report.HasFinding("AS-009"),
			"unrelated name %q must not trigger AS-009", name)
	}
}
