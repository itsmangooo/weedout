package matching

import (
	"testing"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

func TestVersionOrderingParity(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{{"1.0.0", "1.0.1", -1}, {"1.9.0", "1.10.0", -1}, {"1.0.0-alpha", "1.0.0", -1}, {"1.0.0", "1.0.0-rc.1", 1}, {"1.0a1", "1.0", -1}, {"1.0", "1.0.post1", -1}, {"1.0.dev1", "1.0a1", -1}, {"1!1.0", "2.0", 1}, {"5.3.20.RELEASE", "5.3.21", -1}}
	for _, item := range cases {
		if got := Compare(model.EcosystemNPM, item.left, item.right); got != item.want {
			t.Errorf("Compare(%q,%q)=%d want %d", item.left, item.right, got, item.want)
		}
	}
}

func TestAffectedRangeIsHalfOpen(t *testing.T) {
	affected := model.AffectedPackage{Ecosystem: model.EcosystemNPM, Name: "demo", Ranges: []model.AffectedRange{{Introduced: "1.0.0", Fixed: "1.5.0"}}}
	if ok, _ := affectedBy("1.4.9", model.EcosystemNPM, affected); !ok {
		t.Fatal("version before fix should match")
	}
	if ok, _ := affectedBy("1.5.0", model.EcosystemNPM, affected); ok {
		t.Fatal("fixed version must not match")
	}
}
