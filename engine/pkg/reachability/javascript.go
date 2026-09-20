// Package reachability analyzes optional source context independently of rules.
package reachability

import (
	"regexp"
	"strings"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

var importPattern = regexp.MustCompile(`(?m)(?:from\s+|require\s*\(\s*|import\s*\(\s*|^\s*import\s+)["']([^"']+)["']`)

func Analyze(graph model.DependencyGraph, sources []model.SourceFile) model.DependencyGraph {
	observed := map[string][]model.ReachabilityEvidence{}
	for _, source := range sources {
		for _, match := range importPattern.FindAllStringSubmatchIndex(source.Content, -1) {
			spec := source.Content[match[2]:match[3]]
			name := packageName(spec)
			if name == "" {
				continue
			}
			line := strings.Count(source.Content[:match[0]], "\n") + 1
			observed[name] = append(observed[name], model.ReachabilityEvidence{SourceFile: source.Path, Line: line, ImportKind: "import", ImportedPackage: name, Explanation: source.Path + " imports " + spec})
		}
	}
	complete := len(sources) > 0
	for i, dep := range graph.Dependencies {
		evidence := observed[dep.Name]
		state := "unknown"
		if len(evidence) > 0 {
			state = "reachable"
		} else if complete {
			state = "not_observed"
		}
		if dep.Depth > 0 && len(dep.Via) > 0 && len(observed[dep.Via[0]]) > 0 {
			state = "potentially_reachable"
			evidence = observed[dep.Via[0]]
			for j := range evidence {
				evidence[j].DependencyPath = append(append([]string{}, dep.Via...), dep.Name)
			}
		}
		graph.Dependencies[i].AutomatedReachability = state
		graph.Dependencies[i].ReachabilityEvidence = evidence
	}
	return graph
}
func packageName(spec string) string {
	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "node:") {
		return ""
	}
	if strings.HasPrefix(spec, "@") {
		parts := strings.Split(spec, "/")
		if len(parts) >= 2 {
			return strings.Join(parts[:2], "/")
		}
		return ""
	}
	return strings.Split(spec, "/")[0]
}
