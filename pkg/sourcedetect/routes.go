package sourcedetect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

type routeRegistration struct {
	File        string
	Line        int
	Path        string
	Handler     string
	HasAuth     bool
	HasIPFilter bool
	Block       string
}

var (
	routeStartPattern         = regexp.MustCompile(`\.\s*(?:Any|GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle)\s*\(`)
	quotedPathPattern         = regexp.MustCompile("[\"`](/[^\"`]+)[\"`]")
	handlerCallPattern        = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.]*)\s*\(\s*c\s*\)`)
	handlerArgPattern         = regexp.MustCompile("[\"`](/[^\"`]+)[\"`]\\s*,\\s*([A-Za-z_][A-Za-z0-9_.]*)\\b")
	wrappedHandlerArgPattern  = regexp.MustCompile("[\"`](/[^\"`]+)[\"`]\\s*,\\s*[A-Za-z_][A-Za-z0-9_.]*\\s*\\([^)]*?([A-Za-z_][A-Za-z0-9_.]*)\\s*\\)")
	trailingHandlerArgPattern = regexp.MustCompile(`,\s*([A-Za-z_][A-Za-z0-9_.]*)\s*(?:,|\))`)
)

func detectRouteAuthAsymmetry(root string, opts Options) ([]RouteFinding, []model.Issue, error) {
	var routes []routeRegistration
	failOpenEvidence := map[string]Evidence{}

	filesScanned, err := walkSourceFiles(root, opts, func(rel, abs string, _ fs.DirEntry) error {
		if strings.ToLower(filepath.Ext(rel)) != ".go" {
			return nil
		}
		// #nosec G304 -- abs is produced by walkSourceFiles under the requested repo root.
		content, readErr := os.ReadFile(abs)
		if readErr != nil {
			return nil
		}
		text := string(content)
		routes = append(routes, extractRouteRegistrations(rel, text)...)
		if ev, ok := findFailOpenWhitelistEvidence(text); ok {
			failOpenEvidence[rel] = ev
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	_ = filesScanned

	findings, issues := correlateRouteRegistrations(routes, failOpenEvidence)
	return findings, issues, nil
}

func extractRouteRegistrations(rel, text string) []routeRegistration {
	var out []routeRegistration
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		loc := routeStartPattern.FindStringIndex(line)
		if loc == nil {
			continue
		}

		startLine := i + 1
		block, endLine := captureCallBlock(lines, i)
		if block == "" {
			continue
		}
		i = endLine

		path := extractMCPRoutePath(block)
		if path == "" {
			continue
		}
		handler := extractHandlerCall(block, path)
		if handler == "" {
			continue
		}

		out = append(out, routeRegistration{
			File:        rel,
			Line:        startLine,
			Path:        path,
			Handler:     handler,
			HasAuth:     strings.Contains(block, "AuthRequired("),
			HasIPFilter: hasIPFilterCall(block),
			Block:       block,
		})
	}
	return out
}

func extractMCPRoutePath(block string) string {
	matches := quotedPathPattern.FindAllStringSubmatch(block, -1)
	for _, match := range matches {
		if len(match) >= 2 && strings.Contains(strings.ToLower(match[1]), "mcp") {
			return match[1]
		}
	}
	return ""
}

func captureCallBlock(lines []string, start int) (block string, endLine int) {
	var b strings.Builder
	depth := 0
	started := false
	for i := start; i < len(lines); i++ {
		line := lines[i]
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
		for _, ch := range line {
			switch ch {
			case '(':
				depth++
				started = true
			case ')':
				if depth > 0 {
					depth--
				}
			}
		}
		if started && depth == 0 {
			return b.String(), i
		}
	}
	return "", start
}

func extractHandlerCall(block, path string) string {
	matches := handlerCallPattern.FindAllStringSubmatch(block, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		handler := match[1]
		if isRouteMiddleware(handler) {
			continue
		}
		return handler
	}
	for _, match := range handlerArgPattern.FindAllStringSubmatch(block, -1) {
		if len(match) < 3 || match[1] != path {
			continue
		}
		handler := match[2]
		if isRouteMiddleware(handler) {
			continue
		}
		return handler
	}
	for _, match := range wrappedHandlerArgPattern.FindAllStringSubmatch(block, -1) {
		if len(match) < 3 || match[1] != path {
			continue
		}
		handler := match[2]
		if isRouteMiddleware(handler) {
			continue
		}
		return handler
	}
	if strings.Contains(block, path) {
		var handler string
		for _, match := range trailingHandlerArgPattern.FindAllStringSubmatch(block, -1) {
			if len(match) < 2 || isRouteMiddleware(match[1]) {
				continue
			}
			handler = match[1]
		}
		if handler != "" {
			return handler
		}
	}
	return ""
}

func hasIPFilterCall(block string) bool {
	return strings.Contains(block, "IPWhiteList(") || strings.Contains(block, "IPWhitelist(")
}

func isRouteMiddleware(handler string) bool {
	return strings.Contains(handler, "AuthRequired") ||
		strings.Contains(handler, "IPWhiteList") ||
		strings.Contains(handler, "IPWhitelist")
}

func findFailOpenWhitelistEvidence(text string) (Evidence, bool) {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if !strings.Contains(line, "IPWhiteList") && !strings.Contains(line, "IPWhitelist") {
			continue
		}
		window := strings.Join(lines[i:intMin(i+12, len(lines))], "\n")
		if strings.Contains(window, "len(") && strings.Contains(window, "== 0") && strings.Contains(window, "c.Next()") {
			return Evidence{
				Kind:    "fail_open_whitelist",
				Line:    i + 1,
				Snippet: strings.TrimSpace(line),
			}, true
		}
	}
	return Evidence{}, false
}

func correlateRouteRegistrations(routes []routeRegistration, failOpen map[string]Evidence) ([]RouteFinding, []model.Issue) {
	type pairKey struct {
		file    string
		handler string
	}
	byKey := map[pairKey][]routeRegistration{}
	for _, route := range routes {
		byKey[pairKey{file: route.File, handler: route.Handler}] = append(byKey[pairKey{file: route.File, handler: route.Handler}], route)
	}

	var findings []RouteFinding
	var issues []model.Issue
	seen := map[string]bool{}

	for key, regs := range byKey {
		var authRoute *routeRegistration
		var unauthRoute *routeRegistration
		for i := range regs {
			reg := regs[i]
			if reg.HasAuth && authRoute == nil {
				authRoute = &reg
			}
			if !reg.HasAuth && unauthRoute == nil {
				unauthRoute = &reg
			}
		}
		if authRoute == nil || unauthRoute == nil {
			continue
		}
		if !strings.Contains(strings.ToLower(unauthRoute.Path), "mcp") {
			continue
		}

		findKey := fmt.Sprintf("%s|%s|%s|%s", key.file, key.handler, authRoute.Path, unauthRoute.Path)
		if seen[findKey] {
			continue
		}
		seen[findKey] = true

		rf := RouteFinding{
			Language: "go",
			File:     key.file,
			Authenticated: RouteMatch{
				Path:    authRoute.Path,
				Line:    authRoute.Line,
				Handler: authRoute.Handler,
			},
			Unauthenticated: RouteMatch{
				Path:    unauthRoute.Path,
				Line:    unauthRoute.Line,
				Handler: unauthRoute.Handler,
			},
		}
		if ev, ok := failOpen[key.file]; ok {
			evCopy := ev
			rf.FailOpenEvidence = &evCopy
		} else if unauthRoute.HasIPFilter || authRoute.HasIPFilter {
			for _, ev := range failOpen {
				evCopy := ev
				rf.FailOpenEvidence = &evCopy
				break
			}
		}
		findings = append(findings, rf)

		severity := model.SeverityHigh
		desc := fmt.Sprintf("MCP route %s reaches %s without the authentication middleware applied on %s.", unauthRoute.Path, unauthRoute.Handler, authRoute.Path)
		if rf.FailOpenEvidence != nil || strings.EqualFold(unauthRoute.Path, "/mcp_message") {
			severity = model.SeverityCritical
			desc = fmt.Sprintf("MCP route %s appears reachable without authentication while %s protects the same handler %s. This may allow unauthenticated remote MCP tool invocation.", unauthRoute.Path, authRoute.Path, unauthRoute.Handler)
		}

		evidence := []model.Evidence{
			{Kind: "authenticated_route", Value: fmt.Sprintf("%s:%d", authRoute.File, authRoute.Line)},
			{Kind: "unauthenticated_route", Value: fmt.Sprintf("%s:%d", unauthRoute.File, unauthRoute.Line)},
		}
		if rf.FailOpenEvidence != nil {
			evidence = append(evidence, model.Evidence{
				Kind:  "fail_open_whitelist",
				Value: fmt.Sprintf("%s:%d", key.file, rf.FailOpenEvidence.Line),
			})
		}

		issues = append(issues, model.Issue{
			RuleID:      "AS-019",
			Severity:    severity,
			Code:        "MCP_AUTH_ASYMMETRY",
			Description: desc,
			Location:    key.file,
			Evidence:    evidence,
		})
	}

	return findings, issues
}

func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
