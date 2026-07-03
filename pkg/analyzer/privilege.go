package analyzer

import (
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// broadOAuthScopes are OAuth scope patterns that signal over-privileged access.
// Tools should declare the narrowest scope required for their stated purpose.
var broadOAuthScopes = []string{
	"admin",
	"write:*",
	"repo",   // GitHub full repo scope (prefer repo:read)
	"read:*", // broad wildcard reads
	"*",      // wildcard everything
	"root",
	"superuser",
	"all",
	"full_access",
	"manage",
	"https://www.googleapis.com/auth/drive",
}

// privilegedDescriptionPatterns detect tools that describe acquiring elevated
// privileges at runtime (distinct from AS-001 prompt-injection patterns).
var privilegedDescriptionPatterns = []string{
	"sudo",
	"run as root",
	"elevated privilege",
	"bypass permission",
	"bypass authorization",
	"escalate privilege",
	"gain admin",
	"impersonate",
}

// PrivilegeEscalationChecker detects OAuth/token scopes that are broader than
// necessary, and description-level signals of privilege escalation at runtime.
//
// Rule ID: AS-005.
type PrivilegeEscalationChecker struct{}

func (c *PrivilegeEscalationChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-005",
		Title:       "Privilege Escalation",
		Description: "Detects tools that acquire elevated access at runtime through broad OAuth scopes, sudo patterns, or admin-level permission requests.",
	}
}

// NewPrivilegeEscalationChecker returns a new PrivilegeEscalationChecker.
func NewPrivilegeEscalationChecker() *PrivilegeEscalationChecker {
	return &PrivilegeEscalationChecker{}
}

// Check inspects:
//  1. tool.Metadata["oauth_scopes"] ([]string) for over-broad OAuth scopes.
//  2. tool.Description for privilege-escalation language.
func (c *PrivilegeEscalationChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	var issues []model.Issue

	// 1. OAuth scope check
	if scopes := extractStringSlice(tool.Metadata, "oauth_scopes"); len(scopes) > 0 {
		for _, scope := range scopes {
			scopeLower := strings.ToLower(strings.TrimSpace(scope))
			if isBroadOAuthScope(scopeLower) {
				issues = append(issues, model.Issue{
					RuleID:      "AS-005",
					ToolName:    tool.Name,
					Severity:    model.SeverityHigh,
					Code:        "BROAD_OAUTH_SCOPE",
					Description: fmt.Sprintf("tool declares over-broad OAuth scope %q", scope),
					Location:    "metadata.oauth_scopes",
				})
			}
		}
	}

	// 2. Description-level privilege-escalation language
	descLower := strings.ToLower(tool.Description)
	for _, pattern := range privilegedDescriptionPatterns {
		if strings.Contains(descLower, pattern) {
			issues = append(issues, model.Issue{
				RuleID:      "AS-005",
				ToolName:    tool.Name,
				Severity:    model.SeverityHigh,
				Code:        "PRIVILEGE_ESCALATION",
				Description: fmt.Sprintf("tool description suggests privilege escalation: %q", pattern),
				Location:    "description",
			})
			break
		}
	}

	return issues, nil
}

func isBroadOAuthScope(scopeLower string) bool {
	for _, broad := range broadOAuthScopes {
		if scopeLower == broad {
			return true
		}
	}
	if strings.HasSuffix(scopeLower, ":write") {
		return true
	}
	for _, token := range strings.FieldsFunc(scopeLower, func(r rune) bool {
		return r == ':' || r == '/' || r == ' ' || r == ','
	}) {
		if token == "admin" {
			return true
		}
	}
	return false
}

// extractStringSlice is a helper that reads a []string from tool.Metadata.
func extractStringSlice(meta map[string]any, key string) []string {
	if meta == nil {
		return nil
	}
	raw, ok := meta[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
