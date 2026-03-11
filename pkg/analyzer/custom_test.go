package analyzer

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestCustomRuleChecker_Check_Locations(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "test-tool",
		Description: "this is a test desc",
		Permissions: []model.Permission{"exec", "read"},
	}

	tests := []struct {
		name     string
		location string
		pattern  string
		wantHit  bool
	}{
		{"match name", "name", "test-to.*", true},
		{"miss name", "name", "foo", false},
		{"match desc", "description", "test desc", true},
		{"miss desc", "description", "foo", false},
		{"match perms", "permissions", "exec", true},
		{"miss perms", "permissions", "write", false},
		{"fallback to desc", "unknown", "test desc", true},
		{"fallback to desc miss", "unknown", "test-tool", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			checker := &CustomRuleChecker{
				Rule: CustomRule{
					ID:       "TEST-001",
					Severity: "HIGH",
					Location: tc.location,
				},
				Re: re,
			}
			issues, err := checker.Check(tool)
			require.NoError(t, err)
			if tc.wantHit {
				require.Len(t, issues, 1)
				assert.Equal(t, "TEST-001", issues[0].RuleID)
				assert.Equal(t, model.SeverityHigh, issues[0].Severity)
			} else {
				assert.Empty(t, issues)
			}
		})
	}
}

func TestCustomRuleChecker_Check_Severities(t *testing.T) {
	tool := model.UnifiedTool{Description: "match me"}
	re := regexp.MustCompile("match")

	tests := []struct {
		sevIn  string
		sevOut model.Severity
	}{
		{"CRITICAL", model.SeverityCritical},
		{"HIGH", model.SeverityHigh},
		{"MEDIUM", model.SeverityMedium},
		{"LOW", model.SeverityLow},
		{"INFO", model.SeverityInfo},
		{"UNKNOWN", model.SeverityMedium},
		{"", model.SeverityMedium},
	}

	for _, tc := range tests {
		t.Run(tc.sevIn, func(t *testing.T) {
			checker := &CustomRuleChecker{
				Rule: CustomRule{ID: "TEST", Severity: tc.sevIn, Location: "description"},
				Re:   re,
			}
			issues, err := checker.Check(tool)
			require.NoError(t, err)
			require.Len(t, issues, 1)
			assert.Equal(t, tc.sevOut, issues[0].Severity)
		})
	}
}

func TestLoadCustomRules(t *testing.T) {
	t.Run("empty dir", func(t *testing.T) {
		checkers, err := LoadCustomRules("")
		require.NoError(t, err)
		assert.Empty(t, checkers)
	})

	t.Run("dir does not exist", func(t *testing.T) {
		checkers, err := LoadCustomRules("/path/to/nowhere/that/does/not/exist/123")
		require.NoError(t, err)
		assert.Empty(t, checkers)
	})

	t.Run("not a dir", func(t *testing.T) {
		f, err := os.CreateTemp("", "file.txt")
		require.NoError(t, err)
		f.Close()
		defer os.Remove(f.Name())

		_, err = LoadCustomRules(f.Name())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is not a directory")
	})

	t.Run("valid and invalid rules in dir", func(t *testing.T) {
		dir := t.TempDir()

		// 1. Valid array YAML
		err := os.WriteFile(filepath.Join(dir, "rules1.yml"), []byte(`
- id: "RULE-1"
  pattern: "foo"
- id: "RULE-2"
  pattern: "bar"
`), 0o644)
		require.NoError(t, err)

		// 2. Valid single object YAML
		err = os.WriteFile(filepath.Join(dir, "rules2.yaml"), []byte(`
id: "RULE-3"
pattern: "baz"
`), 0o644)
		require.NoError(t, err)

		// 3. Invalid YAML
		err = os.WriteFile(filepath.Join(dir, "rules3.yaml"), []byte(`
- id: "RULE-4
  pattern: "missing quote
`), 0o644)
		require.NoError(t, err)

		// 4. Invalid Regex
		err = os.WriteFile(filepath.Join(dir, "rules4.yml"), []byte(`
- id: "RULE-5"
  pattern: "["
`), 0o644)
		require.NoError(t, err)

		// 5. Missing ID or Pattern
		err = os.WriteFile(filepath.Join(dir, "rules5.yml"), []byte(`
- id: ""
  pattern: "baz"
- id: "RULE-6"
  pattern: ""
`), 0o644)
		require.NoError(t, err)

		// Should fail due to invalid regex or yaml depending on walk order
		// We expect an error. Let's create a cleaner dir for success cases.
		_, err = LoadCustomRules(dir)
		assert.Error(t, err)
	})

	t.Run("successful loading", func(t *testing.T) {
		dir := t.TempDir()
		err := os.WriteFile(filepath.Join(dir, "rules1.yml"), []byte(`
- id: "RULE-1"
  pattern: "foo"
`), 0o644)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(dir, "rules2.yaml"), []byte(`
id: "RULE-2"
pattern: "bar"
`), 0o644)
		require.NoError(t, err)
		// Ignore non-yaml
		err = os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte(`text`), 0o644)
		require.NoError(t, err)

		checkers, err := LoadCustomRules(dir)
		require.NoError(t, err)
		require.Len(t, checkers, 2)
	})
}
