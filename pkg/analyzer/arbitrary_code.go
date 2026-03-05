package analyzer

import (
	"regexp"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// arbitraryCodeKeywords are phrases that imply the tool can execute arbitrary
// script/code (danger equivalent to exec). Found in tool name or description.
var arbitraryCodeKeywords = []string{
	"evaluate_script",
	"evaluate script",
	"execute javascript",
	"run script",
	"execute script",
	"browser injection",
}

// evalWordBoundary matches "eval" as a whole word (avoids false positives like "retrieval").
var evalWordBoundary = regexp.MustCompile(`(?i)\beval\b`)

// ArbitraryCodeChecker detects tools that can execute arbitrary script or
// code (e.g. evaluate_script, execute JavaScript, browser injection).
// These are AS-006 with CRITICAL severity — equivalent risk to exec.
type ArbitraryCodeChecker struct{}

// NewArbitraryCodeChecker returns a new ArbitraryCodeChecker.
func NewArbitraryCodeChecker() *ArbitraryCodeChecker { return &ArbitraryCodeChecker{} }

// Check produces an AS-006 finding when name or description signals
// arbitrary code/script execution capability.
func (c *ArbitraryCodeChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	nameLower := strings.ToLower(strings.TrimSpace(tool.Name))
	descLower := strings.ToLower(strings.TrimSpace(tool.Description))

	for _, kw := range arbitraryCodeKeywords {
		kwNorm := strings.ReplaceAll(kw, " ", "")
		kwSnake := strings.ReplaceAll(kw, " ", "_")
		if strings.Contains(nameLower, kwNorm) || strings.Contains(nameLower, kwSnake) ||
			strings.Contains(descLower, kw) {
			return emitArbitraryCodeFinding(), nil
		}
	}
	// "eval" as whole word (avoids "retrieval", "evaluate" in isolation)
	if evalWordBoundary.MatchString(nameLower) || evalWordBoundary.MatchString(descLower) {
		return emitArbitraryCodeFinding(), nil
	}
	return nil, nil
}

func emitArbitraryCodeFinding() []model.Issue {
	return []model.Issue{{
		RuleID:      "AS-006",
		Severity:    model.SeverityCritical,
		Code:        "ARBITRARY_CODE_EXECUTION",
		Description: "tool name or description implies arbitrary script/code execution (evaluate_script, execute javascript, etc.)",
		Location:    "name,description",
	}}
}
