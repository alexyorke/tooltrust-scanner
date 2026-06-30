package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// EnrichLiveToolsWithLocalDependencyMetadata augments live-scanned tools with
// dependency evidence inferred from local lockfiles near the launch command.
func EnrichLiveToolsWithLocalDependencyMetadata(args []string, tools []model.UnifiedTool) []model.UnifiedTool {
	root := detectLocalProjectRoot(args)
	if root == "" {
		for i := range tools {
			ensureMetadata(&tools[i])
			if !hasDependencyMetadata(tools[i].Metadata) && !hasRepoURL(tools[i].Metadata) {
				tools[i].Metadata["dependency_visibility_note"] = "No metadata.dependencies or repo_url were exposed by this MCP server, and no local project manifest could be inferred from the launch command."
			}
		}
		return tools
	}

	artifacts := findLocalDependencyArtifacts(root)
	if len(artifacts) == 0 {
		for i := range tools {
			ensureMetadata(&tools[i])
			if !hasDependencyMetadata(tools[i].Metadata) && !hasRepoURL(tools[i].Metadata) {
				tools[i].Metadata["dependency_visibility_note"] = fmt.Sprintf("Local project detected at %s, but no supported dependency artifact was found.", root)
			}
		}
		return tools
	}

	var merged []localDependency
	var scanned []string
	for _, artifact := range artifacts {
		deps, err := parseDependencyArtifact(artifact)
		if err != nil || len(deps) == 0 {
			continue
		}
		merged = append(merged, deps...)
		scanned = append(scanned, artifact.path)
	}
	if len(merged) == 0 {
		for i := range tools {
			ensureMetadata(&tools[i])
			if !hasDependencyMetadata(tools[i].Metadata) && !hasRepoURL(tools[i].Metadata) {
				tools[i].Metadata["dependency_visibility_note"] = fmt.Sprintf("Local dependency artifacts were found under %s, but ToolTrust could not extract usable dependencies.", root)
			}
		}
		return tools
	}

	for i := range tools {
		ensureMetadata(&tools[i])
		mergeDependencies(&tools[i], merged)
		tools[i].Metadata["dependency_visibility_note"] = fmt.Sprintf("Local dependency artifacts scanned from %s.", strings.Join(scanned, ", "))
	}
	return tools
}

type dependencyArtifact struct {
	path string
	kind string
}

type localDependency struct {
	Name      string
	Version   string
	Ecosystem string
	Source    string
}

type nodeLockfile struct {
	Packages     map[string]nodeLockEntry `json:"packages"`
	Dependencies map[string]nodeLockEntry `json:"dependencies"`
}

type nodeLockEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func ensureMetadata(tool *model.UnifiedTool) {
	if tool.Metadata == nil {
		tool.Metadata = map[string]any{}
	}
}

func hasDependencyMetadata(meta map[string]any) bool {
	raw, ok := meta["dependencies"]
	if !ok {
		return false
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return false
	}
	var deps []map[string]any
	if err := json.Unmarshal(b, &deps); err != nil {
		return false
	}
	return len(deps) > 0
}

func hasRepoURL(meta map[string]any) bool {
	repoURL, ok := meta["repo_url"].(string)
	return ok && strings.TrimSpace(repoURL) != ""
}

func mergeDependencies(tool *model.UnifiedTool, deps []localDependency) {
	var existing []map[string]any
	if raw, ok := tool.Metadata["dependencies"]; ok {
		b, err := json.Marshal(raw)
		if err == nil {
			if err := json.Unmarshal(b, &existing); err != nil {
				existing = nil
			}
		}
	}

	seen := map[string]map[string]any{}
	for _, dep := range existing {
		name := stringMapValue(dep, "name")
		version := stringMapValue(dep, "version")
		ecosystem := stringMapValue(dep, "ecosystem")
		if dep["source"] == nil || dep["source"] == "" {
			dep["source"] = "metadata"
		}
		seen[ecosystem+":"+name+"@"+version] = dep
	}

	for _, dep := range deps {
		key := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
		if existingDep, ok := seen[key]; ok {
			if dependencySourceRank(dep.Source) > dependencySourceRank(stringMapValue(existingDep, "source")) {
				existingDep["source"] = dep.Source
			}
			continue
		}
		newDep := map[string]any{
			"name":      dep.Name,
			"version":   dep.Version,
			"ecosystem": dep.Ecosystem,
			"source":    dep.Source,
		}
		existing = append(existing, newDep)
		seen[key] = newDep
	}

	if len(existing) > 0 {
		tool.Metadata["dependencies"] = existing
	}
}

func dependencySourceRank(source string) int {
	switch source {
	case "local_lockfile":
		return 2
	case "metadata":
		return 1
	default:
		return 0
	}
}

func parseDependencyArtifact(artifact dependencyArtifact) ([]localDependency, error) {
	switch artifact.kind {
	case "npm-lock":
		return parseNodeLockfile(artifact.path)
	case "go-sum":
		return parseGoSumFile(artifact.path)
	case "requirements":
		return parseRequirementsFile(artifact.path)
	case "pnpm-lock":
		return parsePNPMLockfile(artifact.path)
	case "yarn-lock":
		return parseYarnLockfile(artifact.path)
	default:
		return nil, fmt.Errorf("unsupported dependency artifact kind %q", artifact.kind)
	}
}

func parseNodeLockfile(path string) ([]localDependency, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a discovered local dependency artifact.
	if err != nil {
		return nil, fmt.Errorf("read node lockfile %s: %w", path, err)
	}
	var lock nodeLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse node lockfile %s: %w", path, err)
	}

	seen := map[string]bool{}
	var deps []localDependency
	if len(lock.Packages) > 0 {
		for key, entry := range lock.Packages {
			if key == "" || entry.Version == "" {
				continue
			}
			name := key
			if idx := strings.LastIndex(key, "node_modules/"); idx >= 0 {
				name = key[idx+len("node_modules/"):]
			}
			if entry.Name != "" {
				name = entry.Name
			}
			if name == "" {
				continue
			}
			k := name + "@" + entry.Version
			if seen[k] {
				continue
			}
			seen[k] = true
			deps = append(deps, localDependency{Name: name, Version: entry.Version, Ecosystem: "npm", Source: "local_lockfile"})
		}
		return deps, nil
	}

	for name, entry := range lock.Dependencies {
		if entry.Name != "" {
			name = entry.Name
		}
		if name == "" || entry.Version == "" {
			continue
		}
		k := name + "@" + entry.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		deps = append(deps, localDependency{Name: name, Version: entry.Version, Ecosystem: "npm", Source: "local_lockfile"})
	}
	return deps, nil
}

func detectLocalProjectRoot(args []string) string {
	candidates := []string{}
	for _, arg := range args {
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg, string(os.PathSeparator)) || strings.HasPrefix(arg, ".") {
			candidates = append(candidates, arg)
		}
		if hasLocalSourceFileExtension(arg) {
			candidates = append(candidates, arg)
		}
	}

	seen := map[string]bool{}
	for _, candidate := range candidates {
		resolved := candidate
		if !filepath.IsAbs(resolved) {
			if cwd, err := os.Getwd(); err == nil {
				resolved = filepath.Join(cwd, resolved)
			}
		}
		info, err := os.Stat(resolved)
		if err != nil {
			continue
		}
		dir := resolved
		if !info.IsDir() {
			dir = filepath.Dir(resolved)
		}
		for current := dir; current != "" && current != filepath.Dir(current); current = filepath.Dir(current) {
			if seen[current] {
				break
			}
			seen[current] = true
			if fileExists(filepath.Join(current, "package.json")) || fileExists(filepath.Join(current, "go.mod")) || fileExists(filepath.Join(current, "requirements.txt")) || fileExists(filepath.Join(current, "pyproject.toml")) {
				return current
			}
		}
	}
	return ""
}

func hasLocalSourceFileExtension(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".mjs", ".cjs", ".ts", ".py", ".go":
		return true
	default:
		return false
	}
}

func findLocalDependencyArtifacts(root string) []dependencyArtifact {
	specs := []dependencyArtifact{
		{path: filepath.Join(root, "package-lock.json"), kind: "npm-lock"},
		{path: filepath.Join(root, "npm-shrinkwrap.json"), kind: "npm-lock"},
		{path: filepath.Join(root, "pnpm-lock.yaml"), kind: "pnpm-lock"},
		{path: filepath.Join(root, "yarn.lock"), kind: "yarn-lock"},
		{path: filepath.Join(root, "go.sum"), kind: "go-sum"},
		{path: filepath.Join(root, "requirements.txt"), kind: "requirements"},
	}
	var found []dependencyArtifact
	for _, spec := range specs {
		if fileExists(spec.path) {
			found = append(found, spec)
		}
	}
	return found
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info != nil && !info.IsDir()
}

func stringMapValue(m map[string]any, key string) string {
	if value, ok := m[key].(string); ok {
		return value
	}
	return ""
}

func parseGoSumFile(path string) ([]localDependency, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a discovered local dependency artifact.
	if err != nil {
		return nil, fmt.Errorf("read go.sum %s: %w", path, err)
	}
	seen := map[string]bool{}
	var deps []localDependency
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		module, version := parts[0], strings.TrimSuffix(parts[1], "+incompatible")
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		k := module + "@" + version
		if seen[k] {
			continue
		}
		seen[k] = true
		deps = append(deps, localDependency{Name: module, Version: version, Ecosystem: "Go", Source: "local_lockfile"})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan go.sum %s: %w", path, err)
	}
	return deps, nil
}

func parseRequirementsFile(path string) ([]localDependency, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a discovered local dependency artifact.
	if err != nil {
		return nil, fmt.Errorf("read requirements.txt %s: %w", path, err)
	}
	var deps []localDependency
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, "=="); i > 0 {
			name := normalizeRequirementName(line[:i])
			version := strings.TrimSpace(line[i+2:])
			if marker := strings.IndexByte(version, ';'); marker >= 0 {
				version = strings.TrimSpace(version[:marker])
			}
			if comment := strings.IndexByte(version, '#'); comment >= 0 {
				version = strings.TrimSpace(version[:comment])
			}
			if name != "" && version != "" {
				deps = append(deps, localDependency{Name: name, Version: version, Ecosystem: "PyPI", Source: "local_lockfile"})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan requirements.txt %s: %w", path, err)
	}
	return deps, nil
}

func normalizeRequirementName(raw string) string {
	name := strings.TrimSpace(raw)
	if idx := strings.IndexByte(name, '['); idx >= 0 {
		name = strings.TrimSpace(name[:idx])
	}
	return name
}

func parsePNPMLockfile(path string) ([]localDependency, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a discovered local dependency artifact.
	if err != nil {
		return nil, fmt.Errorf("read pnpm lockfile %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	seen := map[string]bool{}
	var deps []localDependency
	for _, line := range lines {
		name, version, ok := parsePNPMLockKey(line)
		if !ok {
			continue
		}
		k := name + "@" + version
		if seen[k] {
			continue
		}
		seen[k] = true
		deps = append(deps, localDependency{Name: name, Version: version, Ecosystem: "npm", Source: "local_lockfile"})
	}
	return deps, nil
}

func parsePNPMLockKey(line string) (name, version string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasSuffix(trimmed, ":") {
		return "", "", false
	}
	trimmed = strings.TrimSuffix(trimmed, ":")
	trimmed = strings.Trim(trimmed, "'\"")
	trimmed = strings.TrimPrefix(trimmed, "/")
	if trimmed == "" {
		return "", "", false
	}
	if idx := strings.Index(trimmed, "@npm:"); idx >= 0 {
		trimmed = trimmed[idx+len("@npm:"):]
	}
	if idx := strings.Index(trimmed, "("); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	idx := strings.LastIndex(trimmed, "@")
	if idx <= 0 || idx == len(trimmed)-1 {
		return "", "", false
	}
	return trimmed[:idx], trimmed[idx+1:], true
}

func parseYarnLockfile(path string) ([]localDependency, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a discovered local dependency artifact.
	if err != nil {
		return nil, fmt.Errorf("read yarn.lock %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	seen := map[string]bool{}
	var deps []localDependency
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasSuffix(line, ":") {
			continue
		}
		if strings.Contains(line, " version ") {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			next := strings.TrimSpace(lines[j])
			if next == "" {
				break
			}
			if strings.HasPrefix(next, "version ") {
				version := strings.Trim(next[len("version "):], "\"")
				specs := strings.Split(strings.TrimSuffix(line, ":"), ",")
				for _, spec := range specs {
					spec = strings.Trim(strings.TrimSpace(spec), "\"")
					if spec == "" {
						continue
					}
					name, ok := yarnLockSpecPackageName(spec)
					if !ok {
						continue
					}
					k := name + "@" + version
					if seen[k] {
						continue
					}
					seen[k] = true
					deps = append(deps, localDependency{Name: name, Version: version, Ecosystem: "npm", Source: "local_lockfile"})
				}
				break
			}
			if !strings.HasPrefix(lines[j], " ") && !strings.HasPrefix(lines[j], "\t") {
				break
			}
		}
	}
	return deps, nil
}

func yarnLockSpecPackageName(spec string) (string, bool) {
	if aliasIdx := strings.Index(spec, "@npm:"); aliasIdx >= 0 {
		spec = spec[aliasIdx+len("@npm:"):]
	}
	idx := strings.LastIndex(spec, "@")
	if idx <= 0 || idx == len(spec)-1 {
		return "", false
	}
	return spec[:idx], true
}
