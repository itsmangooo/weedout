package scanner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/itsmangooo/weedout-engine/pkg/ecosystems/builtin"
	"github.com/itsmangooo/weedout-engine/pkg/model"
	"github.com/itsmangooo/weedout-engine/pkg/scanner"
)

type parityFixture struct {
	Request  model.ScanRequest `json:"request"`
	Expected struct {
		Dependencies []string `json:"dependencies"`
		Findings     []struct {
			ID             string `json:"id"`
			Verdict        string `json:"verdict"`
			FixedVersion   string `json:"fixed_version"`
			KnownExploited bool   `json:"known_exploited"`
			Reachability   string `json:"reachability"`
		} `json:"findings"`
	} `json:"expected"`
}

func TestLegacyParityFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "parity", "npm-direct-kev.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture parityFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	engine := scanner.Scanner{Parsers: builtin.Registry(), Version: "test", Now: func() time.Time { return time.Unix(0, 0) }}
	result, err := engine.Scan(context.Background(), fixture.Request)
	if err != nil {
		t.Fatal(err)
	}
	deps := make([]string, 0, len(result.Graph.Dependencies))
	for _, dep := range result.Graph.Dependencies {
		deps = append(deps, dep.Name+"@"+dep.Version)
	}
	sort.Strings(deps)
	if !reflect.DeepEqual(deps, fixture.Expected.Dependencies) {
		t.Fatalf("dependencies mismatch: %#v", deps)
	}
	if len(result.Findings) != len(fixture.Expected.Findings) {
		t.Fatalf("findings: got %d want %d", len(result.Findings), len(fixture.Expected.Findings))
	}
	for index, expected := range fixture.Expected.Findings {
		actual := result.Findings[index]
		if actual.ID != expected.ID || actual.Verdict != expected.Verdict || actual.FixedVersion != expected.FixedVersion || actual.KnownExploited != expected.KnownExploited || actual.Reachability != expected.Reachability {
			t.Fatalf("finding mismatch: %#v", actual)
		}
	}
}

func TestSameInputProducesSameDecision(t *testing.T) {
	request := model.ScanRequest{Manifests: []model.ManifestInput{{Path: "requirements.txt", Content: "Django==4.2.0"}}, Advisories: model.AdvisoryConfig{Inline: []model.Advisory{{ID: "CVE-TEST", Severity: "critical", Affected: []model.AffectedPackage{{Ecosystem: model.EcosystemPyPI, Name: "django", Ranges: []model.AffectedRange{{Introduced: "0", Fixed: "4.2.2"}}}}}}}}
	engine := scanner.Scanner{Parsers: builtin.Registry(), Now: func() time.Time { return time.Unix(0, 0) }}
	first, err := engine.Scan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Scan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	if string(left) != string(right) {
		t.Fatal("scan result is not deterministic")
	}
}
