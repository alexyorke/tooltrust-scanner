package analyzer

import (
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

var dataExfiltrationDescriptionHints = []string{
	"transmit", "send", "forward", "post", "upload", "pipe",
	"data", "info", "content",
	"https://", "http://", "external", "remote", "attacker", "base64",
}

var dataExfiltrationDescriptionTriggers = []string{
	"transmit", "send", "forward", "post", "upload", "pipe",
}

var dataExfiltrationDescriptionPayloads = []string{
	"data", "info", "content",
}

var dataExfiltrationDescriptionDestinations = []string{
	"https://", "http://", "external", "remote", "attacker", "base64",
}

type DataExfilDescriptionChecker struct{}

func NewDataExfilDescriptionChecker() *DataExfilDescriptionChecker {
	return &DataExfilDescriptionChecker{}
}

func (c *DataExfilDescriptionChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-017",
		Title:       "Suspicious Data Exfiltration Description",
		Description: "Detects tool descriptions that suggest sending conversation, content, or user data to explicit external endpoints.",
	}
}

func (c *DataExfilDescriptionChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	desc := strings.TrimSpace(tool.Description)
	if desc == "" || isDataMovementTool(tool.Name) {
		return nil, nil
	}
	descLower := strings.ToLower(desc)
	if !containsAny(descLower, dataExfiltrationDescriptionHints...) {
		return nil, nil
	}

	if matched, ok := matchSuspiciousDataExfilDescription(descLower); ok {
		return []model.Issue{{
			RuleID:      "AS-017",
			ToolName:    tool.Name,
			Severity:    model.SeverityMedium,
			Code:        "SUSPICIOUS_DATA_EXFIL_DESCRIPTION",
			Description: "possible external data exfiltration language detected in tool description",
			Location:    "description",
			Evidence: []model.Evidence{
				{Kind: "description_pattern", Value: "ordered trigger/payload/destination keywords"},
				{Kind: "description_match", Value: matched},
			},
		}}, nil
	}

	return nil, nil
}

func matchSuspiciousDataExfilDescription(descLower string) (string, bool) {
	for _, trigger := range dataExfiltrationDescriptionTriggers {
		triggerPos := strings.Index(descLower, trigger)
		if triggerPos < 0 {
			continue
		}
		searchFrom := triggerPos + len(trigger)
		for {
			payloadPos := indexAnyAfter(descLower, dataExfiltrationDescriptionPayloads, searchFrom)
			if payloadPos < 0 {
				break
			}
			toPos := strings.Index(descLower[payloadPos:], "to ")
			if toPos < 0 {
				searchFrom = payloadPos + 1
				continue
			}
			destStart := payloadPos + toPos + len("to ")
			destPos, destLen := indexAnyAfterWithLen(descLower, dataExfiltrationDescriptionDestinations, destStart)
			if destPos >= 0 {
				return descLower[triggerPos : destPos+destLen], true
			}
			searchFrom = payloadPos + 1
		}
	}
	return "", false
}

func indexAnyAfter(text string, needles []string, start int) int {
	pos, _ := indexAnyAfterWithLen(text, needles, start)
	return pos
}

func indexAnyAfterWithLen(text string, needles []string, start int) (int, int) {
	bestPos := -1
	bestLen := 0
	for _, needle := range needles {
		pos := strings.Index(text[start:], needle)
		if pos < 0 {
			continue
		}
		pos += start
		if bestPos < 0 || pos < bestPos {
			bestPos = pos
			bestLen = len(needle)
		}
	}
	return bestPos, bestLen
}
