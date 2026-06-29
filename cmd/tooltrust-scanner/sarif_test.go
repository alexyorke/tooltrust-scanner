package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestWriteSarifOutput_RegistersAllEmittedRuleIDs(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "scan.sarif")

	report := ScanReport{
		SchemaVersion: "1.0",
		Policies: []model.GatewayPolicy{
			{
				ToolName: "compromised_package",
				Score: model.RiskScore{
					Issues: []model.Issue{
						{RuleID: "AS-008", Severity: model.SeverityCritical, Description: "known compromised package"},
						{RuleID: "AS-016", Severity: model.SeverityCritical, Description: "npm IOC dependency"},
					},
				},
			},
		},
	}

	require.NoError(t, writeSarifOutput(scanOpts{outputFile: out}, report))

	raw, err := os.ReadFile(out)
	require.NoError(t, err)

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex *int   `json:"ruleIndex,omitempty"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.Len(t, doc.Runs, 1)

	rules := map[string]bool{}
	for _, rule := range doc.Runs[0].Tool.Driver.Rules {
		rules[rule.ID] = true
	}

	assert.True(t, rules["AS-008"], "SARIF rules must include known compromised package findings")
	assert.True(t, rules["AS-016"], "SARIF rules must include npm IOC findings")
	require.Len(t, doc.Runs[0].Results, 2)
	for _, result := range doc.Runs[0].Results {
		assert.Nil(t, result.RuleIndex)
	}
}
