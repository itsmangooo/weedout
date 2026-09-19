package rules

import (
	"context"
	"testing"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

func decision(known bool, severity, scope string, config model.RuleConfig) Evaluation {
	return (DefaultEngine{}).Evaluate(context.Background(), Context{Dependency: model.Dependency{Name: "demo", Scope: scope}, Advisory: model.Advisory{ID: "CVE-DEMO", Severity: severity, KnownExploited: known}}, config)
}
func TestKnownExploitedOverridesIgnore(t *testing.T) {
	got := decision(true, "low", "dev_only", model.RuleConfig{Ignored: []model.IgnoreRule{{AdvisoryID: "CVE-DEMO", Reason: "accepted"}}})
	if got.Verdict != "actionable" {
		t.Fatalf("got %s", got.Verdict)
	}
}
func TestIgnoreExplainsFiltering(t *testing.T) {
	got := decision(false, "critical", "runtime_direct", model.RuleConfig{Ignored: []model.IgnoreRule{{Package: "demo", Reason: "not deployed"}}})
	if got.Verdict != "filtered" || got.FilteringReason == "" {
		t.Fatalf("%#v", got)
	}
}
func TestEPSSCanSurfaceBelowSeverity(t *testing.T) {
	score := 0.8
	threshold := 0.5
	engine := DefaultEngine{}
	got := engine.Evaluate(context.Background(), Context{Dependency: model.Dependency{Name: "demo", Scope: "runtime_transitive"}, Advisory: model.Advisory{ID: "CVE-DEMO", Severity: "low", EPSSScore: &score}}, model.RuleConfig{EPSSAlertAbove: &threshold})
	if got.Verdict != "actionable" {
		t.Fatalf("got %s", got.Verdict)
	}
}
