package analyzer

import (
	"regexp"
	"sort"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

var (
	hardcodedURLPattern  = regexp.MustCompile(`https?://[^\s"'<>]+`)
	hardcodedHostPattern = regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`)
)

var dynamicURLPropertyHints = []string{
	"url", "uri", "endpoint", "host", "webhook", "callback", "attachmenturl", "attachment_url",
}

var dynamicEmailPropertyHints = []string{
	"email", "recipient", "to", "bcc", "cc",
}

var readFileSignals = []string{
	"read", "list", "get", "open", "search",
}

var writeFileSignals = []string{
	"write", "edit", "create", "delete", "remove", "move", "save", "upload",
}

var executeSignals = []string{
	"execute", "exec", "command", "shell", "script", "terminal", "subprocess", "run command",
}

var envSignals = []string{
	"process.env", "environment variable", "env var", "read env", "reads env",
}

// SummarizeToolContext derives high-confidence static behavior and destination
// hints from the tool's declared permissions, schema, description, and raw source.
func SummarizeToolContext(tool model.UnifiedTool) (behavior, destinations []string) {
	behaviorSet := map[string]bool{}
	destinationSet := map[string]bool{}

	nameLower := strings.ToLower(tool.Name)
	descLower := strings.ToLower(tool.Description)
	rawLower := strings.ToLower(string(tool.RawSource))

	if tool.HasPermission(model.PermissionNetwork) || tool.HasPermission(model.PermissionHTTP) {
		behaviorSet["uses_network"] = true
	}
	if tool.HasPermission(model.PermissionEnv) || containsAny(descLower, envSignals...) || strings.Contains(rawLower, "process.env") {
		behaviorSet["reads_env"] = true
	}
	if tool.HasPermission(model.PermissionExec) || containsAny(nameLower, executeSignals...) || containsAny(descLower, executeSignals...) {
		behaviorSet["executes_commands"] = true
	}
	if tool.HasPermission(model.PermissionFS) {
		if containsAny(nameLower, writeFileSignals...) || containsAny(descLower, writeFileSignals...) {
			behaviorSet["writes_files"] = true
		} else if containsAny(nameLower, readFileSignals...) || containsAny(descLower, readFileSignals...) {
			behaviorSet["reads_files"] = true
		}
	}

	for propName := range tool.InputSchema.Properties {
		propLower := strings.ToLower(propName)
		if containsAny(propLower, dynamicURLPropertyHints...) {
			destinationSet["dynamic URL input ("+propName+")"] = true
		}
		if containsAny(propLower, dynamicEmailPropertyHints...) {
			destinationSet["dynamic email recipient ("+propName+")"] = true
		}
	}

	for _, match := range hardcodedURLPattern.FindAllString(string(tool.RawSource), -1) {
		addHardcodedDomain(destinationSet, match)
	}
	for _, match := range hardcodedURLPattern.FindAllString(tool.Description, -1) {
		addHardcodedDomain(destinationSet, match)
	}
	for _, match := range hardcodedHostPattern.FindAllString(string(tool.RawSource), -1) {
		addHardcodedDomain(destinationSet, match)
	}
	for _, match := range hardcodedHostPattern.FindAllString(tool.Description, -1) {
		addHardcodedDomain(destinationSet, match)
	}

	behavior = sortedKeys(behaviorSet)
	destinations = sortedKeys(destinationSet)
	return behavior, destinations
}

func addHardcodedDomain(destinations map[string]bool, match string) {
	host := strings.TrimSpace(match)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.SplitN(host, "/", 2)[0]
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return
	}
	destinations["hardcoded domain: "+host] = true
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
