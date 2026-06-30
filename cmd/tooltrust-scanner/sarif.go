package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

var sarifRuleDefinitions = []struct {
	id    string
	title string
}{
	{"AS-001", "Prompt Injection"},
	{"AS-002", "Permission and Capability Surface"},
	{"AS-003", "Scope Mismatch"},
	{"AS-004", "Supply Chain CVE"},
	{"AS-005", "Privilege Escalation"},
	{"AS-006", "Arbitrary Code Execution"},
	{"AS-007", "Insufficient Tool Data"},
	{"AS-008", "Known Compromised Package"},
	{"AS-009", "Typosquatting"},
	{"AS-010", "Secret Handling"},
	{"AS-011", "DoS Resilience"},
	{"AS-012", "Tool Drift"},
	{"AS-013", "Tool Shadowing"},
	{"AS-014", "Dependency Inventory Unavailable"},
	{"AS-015", "Suspicious NPM Lifecycle Script"},
	{"AS-016", "Suspicious NPM IOC Dependency"},
	{"AS-017", "Suspicious Data Exfiltration Description"},
	{"AS-018", "Embedded MCP Server Detected"},
	{"AS-019", "Unauthenticated MCP Route Exposure"},
}

// writeSarifOutput converts the ScanReport to SARIF format and prints/writes it.
func writeSarifOutput(opts scanOpts, report ScanReport) error {
	sarifReport, err := sarif.New(sarif.Version210)
	if err != nil {
		return fmt.Errorf("failed to create sarif report: %w", err)
	}

	run := sarif.NewRunWithInformationURI("ToolTrust Scanner", "https://github.com/AgentSafe-AI/tooltrust-scanner")

	for _, rule := range sarifRuleDefinitions {
		run.AddRule(rule.id).
			WithShortDescription(sarif.NewMultiformatMessageString(rule.title)).
			WithHelpURI("https://github.com/AgentSafe-AI/tooltrust-scanner")
	}

	sarifReport.AddRun(run)

	for i := range report.Policies {
		policy := report.Policies[i]
		for _, issue := range policy.Score.Issues {
			level := "note"
			switch issue.Severity {
			case model.SeverityCritical, model.SeverityHigh:
				level = "error"
			case model.SeverityMedium:
				level = "warning"
			case model.SeverityLow, model.SeverityInfo:
				level = "note"
			}

			ruleId := issue.RuleID
			if ruleId == "" {
				ruleId = issue.Code // fallback if rule ID is missing
			}

			loc := sarif.NewLocationWithPhysicalLocation(sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(policy.ToolName)))

			result := sarif.NewRuleResult(ruleId).
				WithMessage(sarif.NewTextMessage(issue.Description)).
				WithLevel(level).
				WithLocations([]*sarif.Location{loc})

			run.AddResult(result)
			// go-sarif assigns 'unit(-1)' to RuleIndex if the rule isn't found in tool.driver.rules,
			// causing a uint64 underflow in JSON. We explicitly nil it out.
			result.RuleIndex = nil
		}
	}

	encoded, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sarif json: %w", err)
	}

	if opts.outputFile != "" {
		if writeErr := os.WriteFile(opts.outputFile, encoded, 0o600); writeErr != nil {
			return fmt.Errorf("failed to write output file: %w", writeErr)
		}
	} else {
		fmt.Println(string(encoded))
	}
	return nil
}
