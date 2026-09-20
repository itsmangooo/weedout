package reachability

import (
	"testing"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

func TestIncompleteInventoryDoesNotClaimUnobservedDependencyIsAbsent(t *testing.T) {
	graph := model.DependencyGraph{Dependencies: []model.Dependency{{Name: "lodash", Ecosystem: model.EcosystemNPM}}}
	got, notes := Analyze(graph, []model.SourceFile{{Path: "src/index.js", Content: "console.log('hello')"}}, model.SourceContext{})
	if got.Dependencies[0].AutomatedReachability != "unknown" {
		t.Fatalf("reachability = %q, want unknown", got.Dependencies[0].AutomatedReachability)
	}
	if len(notes) == 0 {
		t.Fatal("expected an incomplete-inventory note")
	}
}

func TestCompleteInventoryCanMarkUnobservedDependency(t *testing.T) {
	graph := model.DependencyGraph{Dependencies: []model.Dependency{{Name: "lodash", Ecosystem: model.EcosystemNPM}}}
	got, _ := Analyze(graph, []model.SourceFile{{Path: "src/index.js", Content: "console.log('hello')"}}, model.SourceContext{Complete: true})
	if got.Dependencies[0].AutomatedReachability != "not_observed" {
		t.Fatalf("reachability = %q, want not_observed", got.Dependencies[0].AutomatedReachability)
	}
}
