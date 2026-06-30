package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/jsonschema"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

var filesystemNameContextTerms = []string{
	"file", "files", "folder", "folders", "dir", "dirs", "directory", "directories", "path", "filesystem",
}

var networkNameContextTerms = []string{
	"url", "uri", "host", "endpoint", "remote", "network", "http", "https", "api", "web", "webhook",
}

// Adapter converts MCP tools/list payloads into []model.UnifiedTool.
type Adapter struct{}

// NewAdapter returns a new MCP Adapter.
func NewAdapter() *Adapter { return &Adapter{} }

// Protocol implements adapter.Adapter.
func (a *Adapter) Protocol() model.ProtocolType { return model.ProtocolMCP }

// Parse implements adapter.Adapter for the MCP tools/list response format.
func (a *Adapter) Parse(_ context.Context, data []byte) ([]model.UnifiedTool, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err == nil {
		if _, ok := envelope["mcpServers"]; ok {
			return nil, fmt.Errorf("mcp adapter: expected MCP tools/list JSON, got MCP server config")
		}
	}

	var resp ListToolsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("mcp adapter: failed to parse tools/list response: %w", err)
	}

	tools := make([]model.UnifiedTool, 0, len(resp.Tools))
	for i := range resp.Tools {
		t := resp.Tools[i]
		raw, err := json.Marshal(t)
		if err != nil {
			// Marshalling a plain struct with only string fields should never fail.
			return nil, fmt.Errorf("mcp adapter: failed to marshal tool %q: %w", t.Name, err)
		}
		unified := model.UnifiedTool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: convertSchema(t.InputSchema),
			Protocol:    model.ProtocolMCP,
			RawSource:   raw,
			Metadata:    buildMetadata(t),
		}
		unified.Permissions = inferPermissions(t)
		tools = append(tools, unified)
	}
	return tools, nil
}

func buildMetadata(t Tool) map[string]any {
	meta := map[string]any{}

	repoURL := strings.TrimSpace(t.Metadata.RepoURL)
	if repoURL == "" {
		repoURL = strings.TrimSpace(t.RepoURL)
	}
	if repoURL != "" {
		meta["repo_url"] = repoURL
	}

	if len(t.Metadata.Dependencies) > 0 {
		deps := make([]map[string]any, 0, len(t.Metadata.Dependencies))
		for _, dep := range t.Metadata.Dependencies {
			if dep.Name == "" || dep.Version == "" || dep.Ecosystem == "" {
				continue
			}
			deps = append(deps, map[string]any{
				"name":      dep.Name,
				"version":   dep.Version,
				"ecosystem": dep.Ecosystem,
			})
		}
		if len(deps) > 0 {
			meta["dependencies"] = deps
		}
	}

	if len(meta) == 0 {
		return nil
	}
	return meta
}

// convertSchema maps an MCP InputSchema to the internal jsonschema.Schema.
func convertSchema(s InputSchema) jsonschema.Schema {
	props := make(map[string]jsonschema.Property, len(s.Properties))
	for k, v := range s.Properties {
		props[k] = convertProperty(v)
	}
	schema := jsonschema.Schema{
		Type:        string(s.Type),
		Description: s.Description,
		Properties:  props,
		Required:    s.Required,
	}
	if s.Items != nil {
		items := convertProperty(*s.Items)
		schema.Items = &items
	}
	return schema
}

func convertProperty(p SchemaProperty) jsonschema.Property {
	prop := jsonschema.Property{
		Type:        string(p.Type),
		Description: p.Description,
		Enum:        p.Enum,
	}
	if len(p.Properties) > 0 {
		prop.Properties = make(map[string]jsonschema.Property, len(p.Properties))
		for k, v := range p.Properties {
			prop.Properties[k] = convertProperty(v)
		}
	}
	if p.Items != nil {
		items := convertProperty(*p.Items)
		prop.Items = &items
	}
	return prop
}

// permissionRule maps keyword signals to a Permission.
type permissionRule struct {
	propKeys     []string         // property names that imply this permission
	descKeywords []string         // description substrings (lowercased) that imply it
	nameKeywords []string         // tool name substrings (lowercased) that imply it
	matchAny     []*regexp.Regexp // precise (word-boundary) patterns matched against
	// the lowercased "name + " " + description" combined string
}

var permissionRules = []struct {
	permission model.Permission
	rule       permissionRule
}{
	{
		model.PermissionFS,
		permissionRule{
			propKeys:     []string{"path", "filepath", "filename", "file", "dir", "directory"},
			descKeywords: []string{"file", "filesystem", "directory", "folder", "read file", "write file"},
			nameKeywords: []string{"create", "delete", "update", "push", "fork", "write", "upload", "remove"},
		},
	},
	{
		model.PermissionNetwork,
		permissionRule{
			propKeys:     []string{"url", "uri", "endpoint", "host"},
			descKeywords: []string{"url", "network", "http", "https", "fetch", "remote", "download"},
			nameKeywords: []string{"fetch", "scrape", "crawl", "download", "search", "api", "request"},
		},
	},
	{
		model.PermissionExec,
		permissionRule{
			propKeys: []string{"command", "cmd", "shell", "script"},
			descKeywords: []string{"execute", "run command", "shell", "subprocess", "exec", "terminal",
				"evaluate_script", "execute javascript", "run script", "execute script", "browser injection"},
			nameKeywords: []string{"evaluate_script", "execute_javascript", "evaluatescript", "executejavascript",
				"run_script", "runscript", "execute_script", "executescript", "browser_injection", "browserinjection"},
			matchAny: []*regexp.Regexp{
				regexp.MustCompile(`(?i)\beval\b`), // standalone "eval" word — NOT evaluate/retrieval/cloud_eval
				regexp.MustCompile(`(?i)eval\(`),   // eval( call syntax
			},
		},
	},
	{
		model.PermissionDB,
		permissionRule{
			propKeys:     []string{"sql", "database"},
			descKeywords: []string{"database", "sql", "query"},
		},
	},
	{
		model.PermissionEnv,
		permissionRule{
			propKeys:     []string{"env", "environment", "envvar"},
			descKeywords: []string{"environment variable", "env var", "process env"},
		},
	},
	{
		model.PermissionHTTP,
		permissionRule{
			propKeys:     []string{"headers", "method", "body", "payload"},
			descKeywords: []string{"http request", "api call", "rest", "webhook"},
		},
	},
}

// inferPermissions inspects a tool's schema properties, description, and name to
// derive a best-effort list of Permissions.
func inferPermissions(t Tool) []model.Permission {
	descLower := strings.ToLower(t.Description)
	nameLower := strings.ToLower(t.Name)
	combined := nameLower + " " + descLower

	seen := map[model.Permission]bool{}
	var perms []model.Permission

	add := func(p model.Permission) {
		if !seen[p] {
			seen[p] = true
			perms = append(perms, p)
		}
	}

	for _, entry := range permissionRules {
		// Check schema property names
		for _, propKey := range inputSchemaPropertyPaths(t.InputSchema) {
			for _, ruleKey := range entry.rule.propKeys {
				if propertyNameMatchesRule(propKey, ruleKey, entry.permission) {
					add(entry.permission)
				}
			}
		}
		// Check description keywords
		for _, kw := range entry.rule.descKeywords {
			if descriptionMatchesRule(descLower, kw, entry.permission) {
				add(entry.permission)
			}
		}
		// Check tool name keywords
		for _, kw := range entry.rule.nameKeywords {
			if nameMatchesRule(nameLower, kw, entry.permission) {
				add(entry.permission)
			}
		}
		// Check precise word-boundary / call-syntax patterns
		for _, re := range entry.rule.matchAny {
			if re.MatchString(combined) {
				add(entry.permission)
			}
		}
	}
	return perms
}

func nameMatchesRule(nameLower, keyword string, permission model.Permission) bool {
	switch permission {
	case model.PermissionFS:
		if !containsAnyTerm(nameLower, filesystemNameContextTerms) {
			return false
		}
	case model.PermissionNetwork:
		if !containsAnyTerm(nameLower, networkNameContextTerms) {
			return false
		}
	}
	return strings.Contains(nameLower, keyword)
}

func containsAnyTerm(s string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(s, term) {
			return true
		}
	}
	return false
}

func propertyNameMatchesRule(propName, ruleKey string, permission model.Permission) bool {
	propLower := strings.ToLower(propName)
	if propLower == ruleKey {
		return true
	}
	for _, token := range propertyNameTokens(propName) {
		if token == ruleKey {
			return true
		}
	}
	return false
}

func descriptionMatchesRule(descLower, keyword string, permission model.Permission) bool {
	if permission == model.PermissionDB && keyword == "query" {
		return containsToken(descLower, "query") &&
			(containsToken(descLower, "database") || containsToken(descLower, "sql"))
	}
	if permission == model.PermissionFS {
		switch keyword {
		case "file":
			return containsToken(descLower, "file") || containsToken(descLower, "files")
		case "directory":
			return containsToken(descLower, "directory") || containsToken(descLower, "directories")
		case "folder":
			return containsToken(descLower, "folder") || containsToken(descLower, "folders")
		}
	}
	return strings.Contains(descLower, keyword)
}

func containsToken(s, token string) bool {
	for _, field := range strings.FieldsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if field == token {
			return true
		}
	}
	return false
}

func propertyNameTokens(name string) []string {
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	tokens := make([]string, 0, len(parts)*2)
	for _, part := range parts {
		tokens = append(tokens, camelCaseTokens(part)...)
	}
	return tokens
}

func camelCaseTokens(part string) []string {
	if part == "" {
		return nil
	}
	var tokens []string
	start := 0
	for i := 1; i < len(part); i++ {
		prev := part[i-1]
		curr := part[i]
		nextUpperBoundary := prev >= 'a' && prev <= 'z' && curr >= 'A' && curr <= 'Z'
		acronymBoundary := prev >= 'A' && prev <= 'Z' && curr >= 'A' && curr <= 'Z' && i+1 < len(part) && part[i+1] >= 'a' && part[i+1] <= 'z'
		if nextUpperBoundary || acronymBoundary {
			tokens = append(tokens, strings.ToLower(part[start:i]))
			start = i
		}
	}
	tokens = append(tokens, strings.ToLower(part[start:]))
	return tokens
}

func inputSchemaPropertyPaths(schema InputSchema) []string {
	if len(schema.Properties) == 0 && schema.Items == nil {
		return nil
	}
	var paths []string
	for name, prop := range schema.Properties {
		paths = append(paths, schemaPropertyPaths(name, prop)...)
	}
	if schema.Items != nil {
		paths = append(paths, schemaPropertyPaths("[]", *schema.Items)...)
	}
	return paths
}

func schemaPropertyPaths(path string, prop SchemaProperty) []string {
	paths := []string{path}
	for name, nested := range prop.Properties {
		paths = append(paths, schemaPropertyPaths(path+"."+name, nested)...)
	}
	if prop.Items != nil {
		for name, nested := range prop.Items.Properties {
			paths = append(paths, schemaPropertyPaths(path+"[]."+name, nested)...)
		}
	}
	return paths
}
