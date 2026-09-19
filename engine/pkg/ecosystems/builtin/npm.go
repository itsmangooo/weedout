package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/itsmangooo/weedout-engine/pkg/manifest"
	"github.com/itsmangooo/weedout-engine/pkg/model"
)

type PackageJSONParser struct{}

func (PackageJSONParser) Name() string { return "package.json" }
func (PackageJSONParser) Detect(path string, _ []byte) bool {
	return manifest.Base(path) == "package.json"
}
func (PackageJSONParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	var data map[string]any
	if err := json.Unmarshal([]byte(input.Content), &data); err != nil {
		return manifest.Result{}, fmt.Errorf("package.json: %w", err)
	}
	var deps []model.Dependency
	for _, section := range []struct{ name, scope string }{{"dependencies", "runtime_direct"}, {"optionalDependencies", "runtime_direct"}, {"peerDependencies", "runtime_direct"}, {"devDependencies", "dev_only"}} {
		block, _ := data[section.name].(map[string]any)
		for name, raw := range block {
			spec, ok := raw.(string)
			if !ok {
				continue
			}
			version, exact := floor(spec)
			if version == "" {
				continue
			}
			deps = append(deps, dependency(model.EcosystemNPM, name, version, spec, section.scope, exact, 0))
		}
	}
	return manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}}, nil
}

type PackageLockParser struct{}

func (PackageLockParser) Name() string { return "package-lock.json" }
func (PackageLockParser) Detect(path string, _ []byte) bool {
	return manifest.Base(path) == "package-lock.json"
}
func (PackageLockParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	var data struct {
		Packages     map[string]map[string]any `json:"packages"`
		Dependencies map[string]lockDependency `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(input.Content), &data); err != nil {
		return manifest.Result{}, fmt.Errorf("package-lock.json: %w", err)
	}
	var deps []model.Dependency
	if len(data.Packages) > 0 {
		root := data.Packages[""]
		direct := map[string]bool{}
		for _, section := range []string{"dependencies", "optionalDependencies", "peerDependencies"} {
			if values, ok := root[section].(map[string]any); ok {
				for name := range values {
					direct[name] = true
				}
			}
		}
		for path, entry := range data.Packages {
			if path == "" {
				continue
			}
			version, _ := entry["version"].(string)
			if version == "" {
				continue
			}
			name, _ := entry["name"].(string)
			if name == "" {
				name = lockName(path)
			}
			if name == "" {
				continue
			}
			scope, depth := "runtime_transitive", strings.Count(path, "node_modules/")-1
			if direct[name] {
				scope, depth = "runtime_direct", 0
			}
			if dev, _ := entry["dev"].(bool); dev {
				scope = "dev_only"
			}
			deps = append(deps, dependency(model.EcosystemNPM, name, version, version, scope, true, max(depth, 0)))
		}
	} else {
		walkLock(&deps, data.Dependencies, nil, 0)
	}
	if len(deps) == 0 {
		return manifest.Result{}, fmt.Errorf("package-lock.json has no resolved dependencies")
	}
	return manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}}, nil
}

type lockDependency struct {
	Version      string                    `json:"version"`
	Dev          bool                      `json:"dev"`
	Dependencies map[string]lockDependency `json:"dependencies"`
}

func walkLock(out *[]model.Dependency, items map[string]lockDependency, via []string, depth int) {
	for name, entry := range items {
		scope := "runtime_transitive"
		if depth == 0 {
			scope = "runtime_direct"
		}
		if entry.Dev {
			scope = "dev_only"
		}
		*out = append(*out, dependency(model.EcosystemNPM, name, entry.Version, entry.Version, scope, true, depth, via...))
		walkLock(out, entry.Dependencies, append(append([]string{}, via...), name), depth+1)
	}
}
func lockName(path string) string {
	index := strings.LastIndex(filepathSlash(path), "node_modules/")
	if index < 0 {
		return ""
	}
	return filepathSlash(path)[index+len("node_modules/"):]
}
func filepathSlash(path string) string { return strings.ReplaceAll(path, "\\", "/") }
