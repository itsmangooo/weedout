// Package scanner orchestrates parsers, advisory sources, matching,
// reachability, rules, and explanations into one deterministic result.
package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/itsmangooo/weedout-engine/pkg/advisory"
	"github.com/itsmangooo/weedout-engine/pkg/manifest"
	"github.com/itsmangooo/weedout-engine/pkg/matching"
	"github.com/itsmangooo/weedout-engine/pkg/model"
	"github.com/itsmangooo/weedout-engine/pkg/reachability"
	"github.com/itsmangooo/weedout-engine/pkg/rules"
)

type Clock func() time.Time
type Scanner struct {
	Parsers    *manifest.Registry
	Advisories advisory.Source
	Rules      rules.Engine
	Version    string
	Now        Clock
}

func (s Scanner) Ready(ctx context.Context) error {
	if health, ok := s.Advisories.(interface{ Ping(context.Context) error }); ok {
		return health.Ping(ctx)
	}
	return nil
}

func (s Scanner) Scan(ctx context.Context, request model.ScanRequest) (model.ScanResult, error) {
	if s.Parsers == nil {
		return model.ScanResult{}, fmt.Errorf("parser registry is required")
	}
	if s.Advisories == nil {
		s.Advisories = advisory.MemorySource{Items: request.Advisories.Inline}
	}
	if s.Rules == nil {
		s.Rules = rules.DefaultEngine{}
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Version == "" {
		s.Version = "dev"
	}
	canonical, _ := json.Marshal(request)
	digest := sha256.Sum256(canonical)
	result := model.ScanResult{SchemaVersion: model.SchemaVersion, EngineVersion: s.Version, RequestID: request.RequestID, InputDigest: hex.EncodeToString(digest[:]), GeneratedAt: s.Now().UTC(), Findings: []model.Finding{}, Warnings: []string{}}
	for _, input := range request.Manifests {
		parsed, err := s.Parsers.Parse(ctx, input)
		if err != nil {
			return model.ScanResult{}, fmt.Errorf("parse %s: %w", input.Path, err)
		}
		result.Graph.Dependencies = append(result.Graph.Dependencies, parsed.Graph.Dependencies...)
		result.Warnings = append(result.Warnings, parsed.Warnings...)
	}
	result.Graph.Dependencies = dedupe(result.Graph.Dependencies)
	result.Graph = reachability.Analyze(result.Graph, request.Sources)
	queries := make([]advisory.Query, 0, len(result.Graph.Dependencies))
	for _, dep := range result.Graph.Dependencies {
		if request.Rules.MaxDepth != nil && dep.Depth > *request.Rules.MaxDepth {
			result.Stats.UnreachedByDepth++
			continue
		}
		queries = append(queries, advisory.Query{Ecosystem: dep.Ecosystem, Name: dep.Name})
	}
	items, err := s.Advisories.Advisories(ctx, queries)
	if err != nil {
		return model.ScanResult{}, fmt.Errorf("load advisories: %w", err)
	}
	for _, dep := range result.Graph.Dependencies {
		if request.Rules.MaxDepth != nil && dep.Depth > *request.Rules.MaxDepth {
			continue
		}
		for _, item := range items {
			ok, reason, fixed := matching.Match(dep, item)
			if !ok {
				continue
			}
			evaluation := s.Rules.Evaluate(ctx, rules.Context{Dependency: dep, Advisory: item}, request.Rules)
			finding := buildFinding(dep, item, reason, fixed, evaluation)
			result.Findings = append(result.Findings, finding)
			result.Stats.Matched++
			switch evaluation.Verdict {
			case "actionable":
				result.Stats.Actionable++
			case "blocking":
				result.Stats.Blocking++
			default:
				result.Stats.Filtered++
			}
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if verdictRank(a.Verdict) != verdictRank(b.Verdict) {
			return verdictRank(a.Verdict) > verdictRank(b.Verdict)
		}
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		return a.ID < b.ID
	})
	result.Stats.Manifests = len(request.Manifests)
	result.Stats.Dependencies = len(result.Graph.Dependencies)
	return result, nil
}

func buildFinding(dep model.Dependency, item model.Advisory, reason, fixed string, evaluation rules.Evaluation) model.Finding {
	id := item.ID + ":" + string(dep.Ecosystem) + ":" + dep.Name + ":" + dep.Version
	remediation := "Review the advisory and dependency path."
	if fixed != "" {
		remediation = "Upgrade " + dep.Name + " to " + fixed + " or later."
	} else if strings.HasPrefix(strings.ToUpper(item.ID), "MAL-") {
		remediation = "Remove the malicious package."
	}
	explanation := dep.Name + " " + dep.Version + " matches " + item.ID + "; "
	if evaluation.Verdict == "filtered" {
		explanation += evaluation.FilteringReason
	} else {
		explanation += "the configured rules surfaced it"
	}
	return model.Finding{ID: id, Dependency: dep, Advisory: item, Severity: strings.ToLower(item.Severity), Verdict: evaluation.Verdict, Affected: true, AffectedReason: reason, FixedVersion: fixed, KnownExploited: item.KnownExploited, Reachability: dep.AutomatedReachability, Evidence: dep.ReachabilityEvidence, RuleDecisions: evaluation.Decisions, FilteringReason: evaluation.FilteringReason, Remediation: remediation, Explanation: explanation}
}
func dedupe(items []model.Dependency) []model.Dependency {
	seen := map[string]model.Dependency{}
	for _, item := range items {
		key := string(item.Ecosystem) + "\x00" + strings.ToLower(item.Name) + "\x00" + item.Version
		if old, ok := seen[key]; !ok || item.Depth < old.Depth {
			seen[key] = item
		}
	}
	out := make([]model.Dependency, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}
func verdictRank(v string) int {
	switch v {
	case "blocking":
		return 3
	case "actionable":
		return 2
	default:
		return 1
	}
}
func severityRank(v string) int {
	switch strings.ToLower(v) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
