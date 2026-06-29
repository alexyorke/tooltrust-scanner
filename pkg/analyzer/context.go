package analyzer

import (
	"regexp"
	"sort"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/jsonschema"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

var (
	hardcodedURLPattern   = regexp.MustCompile(`https?://[^\s"'<>]+`)
	hardcodedHostPattern  = regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`)
	hardcodedEmailPattern = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
)

var dynamicURLPropertyHints = []string{
	"url", "uri", "endpoint", "host", "webhook", "callback", "attachmenturl", "attachment_url",
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

	rawSource := string(tool.RawSource)
	nameLower := strings.ToLower(tool.Name)
	descLower := strings.ToLower(tool.Description)
	rawLower := strings.ToLower(rawSource)

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

	for _, propName := range schemaPropertyPaths(tool.InputSchema) {
		if label := classifyDynamicDestination(propName); label != "" {
			destinationSet[label] = true
		}
	}

	addHardcodedMatches(destinationSet, rawSource)
	addHardcodedMatches(destinationSet, tool.Description)

	behavior = sortedKeys(behaviorSet)
	destinations = sortedKeys(destinationSet)
	return behavior, destinations
}

func addHardcodedMatches(destinations map[string]bool, text string) {
	for _, match := range hardcodedURLPattern.FindAllString(text, -1) {
		addHardcodedDestination(destinations, match)
	}
	for _, match := range hardcodedHostPattern.FindAllString(text, -1) {
		addHardcodedDestination(destinations, match)
	}
	for _, match := range hardcodedEmailPattern.FindAllString(text, -1) {
		addHardcodedEmailRecipient(destinations, match)
	}
}

func addHardcodedDestination(destinations map[string]bool, match string) {
	host := normalizeHost(match)
	if host == "" {
		return
	}
	if shouldIgnoreHost(host) {
		return
	}
	switch classifyHardcodedDestination(match, host) {
	case "webhook":
		destinations["hardcoded webhook endpoint: "+host] = true
	case "api":
		destinations["hardcoded API endpoint: "+host] = true
	default:
		destinations["hardcoded domain: "+host] = true
	}
}

func classifyDynamicDestination(propName string) string {
	propLower := strings.ToLower(propName)

	if isEmailRecipientProperty(propLower) {
		return "dynamic email recipient (" + propName + ")"
	}
	if strings.Contains(propLower, "webhook") {
		return "dynamic webhook destination (" + propName + ")"
	}
	if strings.Contains(propLower, "callback") {
		return "dynamic callback destination (" + propName + ")"
	}
	if strings.Contains(propLower, "smtp") && strings.Contains(propLower, "host") {
		return "dynamic SMTP host (" + propName + ")"
	}
	if containsAny(propLower, dynamicURLPropertyHints...) {
		return "dynamic URL input (" + propName + ")"
	}
	return ""
}

func isEmailRecipientProperty(propLower string) bool {
	if strings.Contains(propLower, "email") || strings.Contains(propLower, "recipient") {
		return true
	}
	for _, token := range splitIdentifier(propLower) {
		switch token {
		case "to", "cc", "bcc":
			return true
		}
	}
	return false
}

func schemaPropertyPaths(schema jsonschema.Schema) []string {
	if len(schema.Properties) == 0 {
		return nil
	}
	var paths []string
	for name, prop := range schema.Properties {
		paths = append(paths, propertyPaths(name, prop)...)
	}
	sort.Strings(paths)
	return paths
}

func propertyPaths(path string, prop jsonschema.Property) []string {
	paths := []string{path}
	for name, nested := range prop.Properties {
		paths = append(paths, propertyPaths(path+"."+name, nested)...)
	}
	if prop.Items != nil {
		for name, nested := range prop.Items.Properties {
			paths = append(paths, propertyPaths(path+"[]."+name, nested)...)
		}
	}
	return paths
}

func schemaLeafPropertyPaths(schema jsonschema.Schema) []string {
	if len(schema.Properties) == 0 {
		return nil
	}
	var paths []string
	for name, prop := range schema.Properties {
		paths = append(paths, leafPropertyPaths(name, prop)...)
	}
	sort.Strings(paths)
	return paths
}

func leafPropertyPaths(path string, prop jsonschema.Property) []string {
	var paths []string
	for name, nested := range prop.Properties {
		paths = append(paths, leafPropertyPaths(path+"."+name, nested)...)
	}
	if prop.Items != nil {
		for name, nested := range prop.Items.Properties {
			paths = append(paths, leafPropertyPaths(path+"[]."+name, nested)...)
		}
	}
	if len(paths) == 0 {
		return []string{path}
	}
	return paths
}

func splitIdentifier(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}

func addHardcodedEmailRecipient(destinations map[string]bool, match string) {
	email := strings.TrimSpace(match)
	email = strings.Trim(email, `"'<>.,;:()[]{} `)
	if email == "" {
		return
	}
	destinations["hardcoded email recipient: "+email] = true
	if parts := strings.SplitN(email, "@", 2); len(parts) == 2 {
		addHardcodedDestination(destinations, parts[1])
	}
}

func normalizeHost(match string) string {
	host := strings.TrimSpace(match)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.SplitN(host, "/", 2)[0]
	host = strings.TrimSuffix(host, ".")
	return host
}

func classifyHardcodedDestination(raw, host string) string {
	rawLower := strings.ToLower(raw)
	hostLower := strings.ToLower(host)

	if strings.Contains(rawLower, "webhook") || strings.Contains(hostLower, "hooks.") || strings.Contains(hostLower, "webhook") {
		return "webhook"
	}
	if strings.Contains(hostLower, "api.") || strings.Contains(rawLower, "/api/") {
		return "api"
	}
	return "domain"
}

func shouldIgnoreHost(host string) bool {
	switch strings.ToLower(host) {
	case "process.env", "inputschema.properties", "metadata.dependencies":
		return true
	default:
		return false
	}
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
