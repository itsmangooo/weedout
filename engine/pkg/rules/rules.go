// Package rules provides deterministic, composable finding policy.
package rules

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

type Context struct {
	Dependency model.Dependency
	Advisory   model.Advisory
}
type Evaluation struct {
	Verdict, FilteringReason string
	Decisions                []model.RuleDecision
}
type Rule interface {
	Name() string
	Evaluate(context.Context, Context, model.RuleConfig) *model.RuleDecision
}
type Engine interface {
	Evaluate(context.Context, Context, model.RuleConfig) Evaluation
}

type DefaultEngine struct{ Extensions []Rule }

func (engine DefaultEngine) Evaluate(ctx context.Context, input Context, config model.RuleConfig) Evaluation {
	direct, transitive := config.DirectThreshold, config.TransitiveThreshold
	if direct == "" {
		direct = "high"
	}
	if transitive == "" {
		transitive = "critical"
	}
	alwaysKEV := true
	if config.AlwaysAlertOnKEV != nil {
		alwaysKEV = *config.AlwaysAlertOnKEV
	}
	decisions := []model.RuleDecision{}
	if strings.HasPrefix(strings.ToUpper(input.Advisory.ID), "MAL-") {
		explanation := "the package is identified as malicious and must be removed"
		decisions = append(decisions, model.RuleDecision{Rule: "malicious_package", Outcome: "actionable", Explanation: explanation})
		return Evaluation{Verdict: "actionable", Decisions: decisions}
	}
	for _, ignore := range config.Ignored {
		matched := false
		if ignore.AdvisoryID != "" {
			for _, id := range append([]string{input.Advisory.ID}, input.Advisory.Aliases...) {
				if strings.EqualFold(id, ignore.AdvisoryID) {
					matched = true
					break
				}
			}
		}
		if ignore.Package != "" {
			matched, _ = filepath.Match(strings.ToLower(ignore.Package), strings.ToLower(input.Dependency.Name))
		}
		if matched && !(alwaysKEV && input.Advisory.KnownExploited) {
			explanation := "ignored by deterministic policy: " + ignore.Reason
			decisions = append(decisions, model.RuleDecision{Rule: "ignore", Outcome: "filtered", Explanation: explanation})
			return Evaluation{Verdict: "filtered", FilteringReason: explanation, Decisions: decisions}
		}
	}
	if alwaysKEV && input.Advisory.KnownExploited {
		verdict := "actionable"
		if config.BlockOnKEV {
			verdict = "blocking"
		}
		decisions = append(decisions, model.RuleDecision{Rule: "known_exploited", Outcome: verdict, Explanation: "advisory is listed as known exploited"})
		return Evaluation{Verdict: verdict, Decisions: decisions}
	}
	if config.EPSSAlertAbove != nil && input.Advisory.EPSSScore != nil && *input.Advisory.EPSSScore >= *config.EPSSAlertAbove {
		explanation := "EPSS score meets the configured alert threshold"
		decisions = append(decisions, model.RuleDecision{Rule: "epss_threshold", Outcome: "actionable", Explanation: explanation})
		return Evaluation{Verdict: "actionable", Decisions: decisions}
	}
	threshold := transitive
	if input.Dependency.Scope == "runtime_direct" {
		threshold = direct
	}
	if input.Dependency.Scope == "dev_only" {
		if config.DevThreshold == "" {
			explanation := "development-only dependency is filtered by default"
			decisions = append(decisions, model.RuleDecision{Rule: "development_scope", Outcome: "filtered", Explanation: explanation})
			return Evaluation{Verdict: "filtered", FilteringReason: explanation, Decisions: decisions}
		}
		threshold = config.DevThreshold
	}
	if severityRank(input.Advisory.Severity) >= severityRank(threshold) {
		explanation := "severity meets the " + threshold + " threshold for " + input.Dependency.Scope
		decisions = append(decisions, model.RuleDecision{Rule: "severity_threshold", Outcome: "actionable", Explanation: explanation})
		return Evaluation{Verdict: "actionable", Decisions: decisions}
	}
	explanation := "severity is below the " + threshold + " threshold for " + input.Dependency.Scope
	decisions = append(decisions, model.RuleDecision{Rule: "severity_threshold", Outcome: "filtered", Explanation: explanation})
	for _, extension := range engine.Extensions {
		if d := extension.Evaluate(ctx, input, config); d != nil {
			decisions = append(decisions, *d)
		}
	}
	return Evaluation{Verdict: "filtered", FilteringReason: explanation, Decisions: decisions}
}
func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "moderate":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
