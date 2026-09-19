package builtin

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

var versionToken = regexp.MustCompile(`(?i)v?(\d+(?:\.\d+){0,3}(?:[-+][0-9a-z.-]+)?)`)

func dependency(ecosystem model.Ecosystem, name, version, spec, scope string, exact bool, depth int, via ...string) model.Dependency {
	return model.Dependency{Ecosystem: ecosystem, Name: name, Version: strings.TrimPrefix(version, "v"), VersionSpec: spec, VersionExact: exact, Scope: scope, Depth: depth, Via: via, AutomatedReachability: "unknown"}
}

func floor(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	exact := !strings.ContainsAny(value, "^~*xX<>, ")
	m := versionToken.FindStringSubmatch(value)
	if len(m) < 2 {
		return "", false
	}
	parts := strings.Split(m[1], ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
		exact = false
	}
	return strings.Join(parts, "."), exact
}

func dedupe(items []model.Dependency) []model.Dependency {
	seen := map[string]model.Dependency{}
	for _, item := range items {
		key := fmt.Sprintf("%s\x00%s\x00%s", item.Ecosystem, strings.ToLower(item.Name), item.Version)
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
