// Package mcp provides an Adapter that parses MCP tools/list responses.
package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FlexType is a JSON Schema "type" value that accepts either a plain string
// ("string") or an array of strings (["string", "null"]).
// When an array is encountered the first non-"null" element is used; if all
// elements are "null" the value is set to "null".
type FlexType string

// UnmarshalJSON implements json.Unmarshaler for FlexType.
func (ft *FlexType) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 {
		return nil
	}
	if string(b) == "null" {
		return fmt.Errorf("FlexType: null is not a valid schema type")
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("FlexType: %w", err)
		}
		*ft = FlexType(s)
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return fmt.Errorf("FlexType: %w", err)
		}
		for _, v := range arr {
			if v != "null" {
				*ft = FlexType(v)
				return nil
			}
		}
		return fmt.Errorf("FlexType: schema type array must contain at least one non-null type")
	}
	return fmt.Errorf("FlexType: unsupported JSON token %q", string(b))
}

// ListToolsResponse is the top-level MCP tools/list wire format.
type ListToolsResponse struct {
	Tools []Tool `json:"tools"`
}

// Tool is a single tool entry in the MCP tools/list response.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
	RepoURL     string      `json:"repo_url,omitempty"`
	Metadata    ToolMeta    `json:"metadata,omitempty"`
}

// ToolMeta carries optional metadata used by downstream analyzers.
type ToolMeta struct {
	RepoURL      string               `json:"repo_url,omitempty"`
	Dependencies []DependencyMetadata `json:"dependencies,omitempty"`
}

// DependencyMetadata is the MCP-side representation of a package dependency.
type DependencyMetadata struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// InputSchema is the JSON Schema fragment embedded in an MCP Tool.
type InputSchema struct {
	Type        FlexType                  `json:"type,omitempty"`
	Properties  map[string]SchemaProperty `json:"properties,omitempty"`
	Required    []string                  `json:"required,omitempty"`
	Description string                    `json:"description,omitempty"`
	Items       *SchemaProperty           `json:"items,omitempty"`
}

// SchemaProperty describes a single property within an InputSchema.
type SchemaProperty struct {
	Type        FlexType                  `json:"type,omitempty"`
	Description string                    `json:"description,omitempty"`
	Enum        []any                     `json:"enum,omitempty"`
	Properties  map[string]SchemaProperty `json:"properties,omitempty"`
	Items       *SchemaProperty           `json:"items,omitempty"`
}
