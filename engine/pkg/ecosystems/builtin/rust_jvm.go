package builtin

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/itsmangooo/weedout-engine/pkg/manifest"
	"github.com/itsmangooo/weedout-engine/pkg/model"
	"github.com/pelletier/go-toml/v2"
)

type CargoLockParser struct{}

func (CargoLockParser) Name() string                      { return "Cargo.lock" }
func (CargoLockParser) Detect(path string, _ []byte) bool { return manifest.Base(path) == "cargo.lock" }
func (CargoLockParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	var lock struct {
		Packages []struct {
			Name         string   `toml:"name"`
			Version      string   `toml:"version"`
			Source       string   `toml:"source"`
			Dependencies []string `toml:"dependencies"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal([]byte(input.Content), &lock); err != nil {
		return manifest.Result{}, fmt.Errorf("Cargo.lock is not valid TOML: %w", err)
	}
	if len(lock.Packages) == 0 {
		return manifest.Result{}, fmt.Errorf("Cargo.lock has no [[package]] entries")
	}

	local := map[string]struct{}{}
	for _, item := range lock.Packages {
		if item.Source == "" && item.Name != "" {
			local[item.Name] = struct{}{}
		}
	}
	direct := map[string]struct{}{}
	for _, item := range lock.Packages {
		if _, ok := local[item.Name]; !ok {
			continue
		}
		for _, spec := range item.Dependencies {
			name, _, _ := strings.Cut(spec, " ")
			direct[name] = struct{}{}
		}
	}

	deps := make([]model.Dependency, 0, len(lock.Packages))
	for _, item := range lock.Packages {
		if item.Name == "" || item.Version == "" {
			continue
		}
		if _, ok := local[item.Name]; ok {
			continue
		}
		scope, depth := "runtime_transitive", 1
		if _, ok := direct[item.Name]; ok {
			scope, depth = "runtime_direct", 0
		}
		deps = append(deps, dependency(model.EcosystemCargo, item.Name, item.Version, item.Version, scope, true, depth))
	}
	result := manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}}
	if len(result.Graph.Dependencies) == 0 {
		result.Warnings = append(result.Warnings, "Cargo.lock lists no dependencies outside the workspace")
	}
	return result, nil
}

type POMParser struct{}

func (POMParser) Name() string                      { return "pom.xml" }
func (POMParser) Detect(path string, _ []byte) bool { return manifest.Base(path) == "pom.xml" }

type pomProject struct {
	Dependencies []struct {
		Group, Artifact, Version, Scope string `xml:",chardata"`
	} `xml:"dependencies>dependency"`
}

func (POMParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	var raw struct {
		Dependencies []struct {
			Group    string `xml:"groupId"`
			Artifact string `xml:"artifactId"`
			Version  string `xml:"version"`
			Scope    string `xml:"scope"`
		} `xml:"dependencies>dependency"`
	}
	decoder := xml.NewDecoder(strings.NewReader(input.Content))
	decoder.Strict = true
	if err := decoder.Decode(&raw); err != nil {
		return manifest.Result{}, fmt.Errorf("pom.xml: %w", err)
	}
	var deps []model.Dependency
	for _, item := range raw.Dependencies {
		if item.Group == "" || item.Artifact == "" || item.Version == "" || strings.Contains(item.Version, "${") {
			continue
		}
		scope := "runtime_direct"
		if item.Scope == "test" || item.Scope == "provided" {
			scope = "dev_only"
		}
		version, exact := floor(item.Version)
		deps = append(deps, dependency(model.EcosystemMaven, item.Group+":"+item.Artifact, version, item.Version, scope, exact, 0))
	}
	return manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}}, nil
}

type GradleLockParser struct{}

func (GradleLockParser) Name() string { return "gradle.lockfile" }
func (GradleLockParser) Detect(path string, _ []byte) bool {
	base := manifest.Base(path)
	return base == "gradle.lockfile" || strings.HasSuffix(base, ".lockfile")
}
func (GradleLockParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	var deps []model.Dependency
	scanner := bufio.NewScanner(strings.NewReader(input.Content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		coordinate, configs, _ := strings.Cut(line, "=")
		parts := strings.Split(coordinate, ":")
		if len(parts) < 3 {
			continue
		}
		scope := "runtime_transitive"
		if strings.Contains(strings.ToLower(configs), "test") {
			scope = "dev_only"
		}
		deps = append(deps, dependency(model.EcosystemMaven, parts[0]+":"+parts[1], parts[2], parts[2], scope, true, 1))
	}
	return manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}}, scanner.Err()
}

type SBTLockParser struct{}

func (SBTLockParser) Name() string { return "build.sbt.lock" }
func (SBTLockParser) Detect(path string, _ []byte) bool {
	return manifest.Base(path) == "build.sbt.lock"
}
func (SBTLockParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	var raw any
	if err := json.Unmarshal([]byte(input.Content), &raw); err != nil {
		return manifest.Result{}, fmt.Errorf("build.sbt.lock: %w", err)
	}
	var deps []model.Dependency
	walkJSONCoordinates(raw, &deps)
	if len(deps) == 0 {
		return manifest.Result{}, fmt.Errorf("build.sbt.lock has no resolved modules")
	}
	return manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}}, nil
}
func walkJSONCoordinates(value any, out *[]model.Dependency) {
	switch typed := value.(type) {
	case map[string]any:
		group, _ := typed["organization"].(string)
		name, _ := typed["name"].(string)
		version, _ := typed["version"].(string)
		if group != "" && name != "" && version != "" {
			*out = append(*out, dependency(model.EcosystemMaven, group+":"+name, version, version, "runtime_transitive", true, 1))
		}
		for _, child := range typed {
			walkJSONCoordinates(child, out)
		}
	case []any:
		for _, child := range typed {
			walkJSONCoordinates(child, out)
		}
	}
}
