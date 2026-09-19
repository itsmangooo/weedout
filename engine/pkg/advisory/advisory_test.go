package advisory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

func TestFileSourceIsAReplaceableProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "advisories.json")
	payload := `[{"id":"CVE-DEMO","severity":"high","affected":[{"ecosystem":"npm","name":"demo"}]}]`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := (FileSource{Path: path}).Advisories(context.Background(), []Query{{Ecosystem: model.EcosystemNPM, Name: "demo"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "CVE-DEMO" {
		t.Fatalf("%#v", items)
	}
}
