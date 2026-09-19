package postgres

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeAffectedPairsOSVEvents(t *testing.T) {
	payload := json.RawMessage(`[{"package":{"ecosystem":"npm","name":"demo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"},{"introduced":"2.0.0"},{"last_affected":"2.0.4"}]}]}]`)
	items, err := decodeAffected(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].Ranges) != 2 {
		t.Fatalf("%#v", items)
	}
	if items[0].Ranges[0].Fixed != "1.2.3" || items[0].Ranges[1].LastAffected != "2.0.4" {
		t.Fatalf("%#v", items[0].Ranges)
	}
}

func TestQueryIsLimitedToAdvisoryMirrorTables(t *testing.T) {
	lower := strings.ToLower(query)
	for _, required := range []string{"vulnerabilities", "vulnerability_affected", "kev_entries", "epss_scores"} {
		if !strings.Contains(lower, required) {
			t.Fatalf("query does not use %s", required)
		}
	}
	for _, forbidden := range []string{"users", "projects", "sessions", "findings", "billing"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("query crossed product-data boundary through %s", forbidden)
		}
	}
}
