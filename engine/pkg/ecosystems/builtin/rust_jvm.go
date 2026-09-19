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
)

type CargoLockParser struct{}

func (CargoLockParser) Name() string                      { return "Cargo.lock" }
func (CargoLockParser) Detect(path string, _ []byte) bool { return manifest.Base(path) == "cargo.lock" }
func (CargoLockParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	var deps []model.Dependency
	var name, version string
	flush := func() {
		if name != "" && version != "" {
			deps = append(deps, dependency(model.EcosystemCargo, name, version, version, "runtime_transitive", true, 1))
		}
		name, version = "", ""
	}
	for _, raw := range strings.Split(input.Content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "[[package]]" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = unquote(strings.TrimPrefix(line, "name = "))
		}
		if strings.HasPrefix(line, "version = ") {
			version = unquote(strings.TrimPrefix(line, "version = "))
		}
	}
	flush()
	if len(deps) == 0 {
		return manifest.Result{}, fmt.Errorf("Cargo.lock has no packages")
	}
	return manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}}, nil
}
func unquote(value string) string { return strings.Trim(strings.TrimSpace(value), `"`) }

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
