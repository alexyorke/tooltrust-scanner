package analyzer

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// DependencyVisibilityForTool summarizes how much dependency evidence the tool
// exposes through metadata, lockfiles, or repository links.
func DependencyVisibilityForTool(tool model.UnifiedTool) (visibility, note string) {
	if tool.Metadata == nil {
		return "No dependency data", "No metadata.dependencies or repo_url were exposed by this MCP server."
	}

	sources, depsParseFailed := dependencySourcesFromMetadata(tool.Metadata)
	if len(sources) == 0 {
		note = metadataString(tool.Metadata, "dependency_visibility_note")
		if note == "" {
			if depsParseFailed {
				note = "Tool exposed dependency metadata, but it could not be parsed, so supply-chain coverage is limited."
			} else {
				note = "No metadata.dependencies or repo_url were exposed by this MCP server."
			}
		}
		return "No dependency data", note
	}
	return formatDependencyVisibility(sources), visibilityNote(tool.Metadata, sources, depsParseFailed)
}

func dependencySourcesFromMetadata(meta map[string]any) ([]string, bool) {
	seen := map[string]bool{}
	var sources []string
	depsParseFailed := false

	if raw, ok := meta["dependencies"]; ok {
		b, err := json.Marshal(raw)
		if err == nil {
			var deps []map[string]any
			if err := json.Unmarshal(b, &deps); err == nil {
				if deps == nil && bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
					depsParseFailed = true
				}
				for _, dep := range deps {
					if dep == nil {
						depsParseFailed = true
						continue
					}

					source, hasSource := dep["source"].(string)
					source = strings.TrimSpace(source)
					if hasSource {
						if source == "" {
							source = "metadata"
						}
						if !seen[source] {
							seen[source] = true
							sources = append(sources, source)
						}
						continue
					}

					name := visibilityStringValue(dep, "name")
					version := visibilityStringValue(dep, "version")
					ecosystem := visibilityStringValue(dep, "ecosystem")
					if strings.TrimSpace(name) == "" || strings.TrimSpace(version) == "" || strings.TrimSpace(ecosystem) == "" {
						depsParseFailed = true
						continue
					}

					source = "metadata"
					if !seen[source] {
						seen[source] = true
						sources = append(sources, source)
					}
				}
			} else {
				depsParseFailed = true
			}
		} else {
			depsParseFailed = true
		}
	}

	if repoURL, ok := meta["repo_url"].(string); ok && strings.TrimSpace(repoURL) != "" {
		if !seen["repo_url"] {
			sources = append(sources, "repo_url")
		}
	}

	return sources, depsParseFailed
}

func visibilityNote(meta map[string]any, sources []string, depsParseFailed bool) string {
	if note := metadataString(meta, "dependency_visibility_note"); note != "" {
		if depsParseFailed && !strings.Contains(strings.ToLower(note), "could not be parsed") {
			return note + " Tool exposed dependency metadata, but it could not be parsed, so supply-chain coverage is limited."
		}
		return note
	}
	if len(sources) == 1 && sources[0] == "repo_url" {
		if depsParseFailed {
			return "repo_url is available, so ToolTrust can try to inspect remote lockfiles for dependency evidence. Tool exposed dependency metadata, but it could not be parsed, so supply-chain coverage is limited."
		}
		return "repo_url is available, so ToolTrust can try to inspect remote lockfiles for dependency evidence."
	}
	if depsParseFailed {
		return "Tool exposed dependency metadata, but it could not be parsed, so supply-chain coverage is limited."
	}
	return ""
}

func formatDependencyVisibility(sources []string) string {
	labels := make([]string, 0, len(sources))
	for _, source := range sources {
		switch source {
		case "metadata":
			labels = append(labels, "Declared by MCP metadata")
		case "local_lockfile":
			labels = append(labels, "Verified from local lockfile")
		case "lockfile":
			labels = append(labels, "Verified from remote lockfile")
		case "repo_url":
			labels = append(labels, "Repo URL available")
		default:
			labels = append(labels, source)
		}
	}
	return strings.Join(labels, " + ")
}

func metadataString(meta map[string]any, key string) string {
	if value, ok := meta[key].(string); ok {
		return value
	}
	return ""
}

func visibilityStringValue(dep map[string]any, key string) string {
	if value, ok := dep[key].(string); ok {
		return value
	}
	return ""
}
