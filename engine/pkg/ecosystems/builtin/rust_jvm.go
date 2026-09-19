package builtin

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
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

type xmlNode struct {
	XMLName  xml.Name
	Content  string    `xml:",chardata"`
	Children []xmlNode `xml:",any"`
}

func (n xmlNode) child(name string) *xmlNode {
	for index := range n.Children {
		if n.Children[index].XMLName.Local == name {
			return &n.Children[index]
		}
	}
	return nil
}
func (n xmlNode) text(name string) string {
	if child := n.child(name); child != nil {
		return strings.TrimSpace(child.Content)
	}
	return ""
}

func (POMParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	if regexp.MustCompile(`(?i)<!\s*(DOCTYPE|ENTITY)`).MatchString(input.Content) {
		return manifest.Result{}, fmt.Errorf("pom.xml document type declarations are not allowed")
	}
	var raw xmlNode
	decoder := xml.NewDecoder(strings.NewReader(input.Content))
	decoder.Strict = true
	if err := decoder.Decode(&raw); err != nil {
		return manifest.Result{}, fmt.Errorf("pom.xml is not valid XML: %w", err)
	}
	if raw.XMLName.Local != "project" {
		return manifest.Result{}, fmt.Errorf("XML has no Maven project root")
	}
	properties := map[string]string{}
	if block := raw.child("properties"); block != nil {
		for _, item := range block.Children {
			properties[item.XMLName.Local] = strings.TrimSpace(item.Content)
		}
	}
	resolve := func(value string) string {
		for range 5 {
			if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
				break
			}
			next, ok := properties[value[2:len(value)-1]]
			if !ok {
				break
			}
			value = next
		}
		return value
	}
	type declaration struct{ name, version, scope string }
	managed := map[string]string{}
	declared := []declaration{}
	readBlock := func(block *xmlNode, management bool) {
		if block == nil {
			return
		}
		for _, item := range block.Children {
			if item.XMLName.Local != "dependency" {
				continue
			}
			group, artifact := resolve(item.text("groupId")), resolve(item.text("artifactId"))
			if group == "" || artifact == "" {
				continue
			}
			entry := declaration{name: strings.TrimSpace(group) + ":" + strings.TrimSpace(artifact), version: resolve(item.text("version")), scope: strings.ToLower(item.text("scope"))}
			if management {
				if entry.version != "" {
					managed[entry.name] = entry.version
				}
			} else {
				declared = append(declared, entry)
			}
		}
	}
	readBlock(raw.child("dependencies"), false)
	if management := raw.child("dependencyManagement"); management != nil {
		readBlock(management.child("dependencies"), true)
	}

	var deps []model.Dependency
	warnings := []string{}
	for _, item := range declared {
		if item.version == "" {
			item.version = managed[item.name]
		}
		if item.version == "" || strings.HasPrefix(item.version, "${") || strings.HasPrefix(item.version, "[") || strings.HasPrefix(item.version, "(") {
			warnings = append(warnings, item.name+" has no locally resolvable exact version")
			continue
		}
		scope := "runtime_direct"
		if item.scope == "test" || item.scope == "provided" {
			scope = "dev_only"
		}
		deps = append(deps, dependency(model.EcosystemMaven, item.name, item.version, item.version, scope, true, 0))
	}
	if len(deps) == 0 && len(warnings) == 0 {
		warnings = append(warnings, "This POM declares no dependencies")
	}
	return manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}, Warnings: warnings}, nil
}

type GradleLockParser struct{}

func (GradleLockParser) Name() string { return "gradle.lockfile" }
func (GradleLockParser) Detect(path string, _ []byte) bool {
	base := manifest.Base(path)
	return base == "gradle.lockfile" || strings.HasSuffix(base, ".lockfile")
}
func (GradleLockParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	devMarkers := []string{"test", "checkstyle", "pmd", "spotbugs", "jacoco", "annotationprocessor"}
	var deps []model.Dependency
	scanner := bufio.NewScanner(strings.NewReader(input.Content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") || !strings.Contains(line, "=") {
			continue
		}
		coordinate, configs, _ := strings.Cut(line, "=")
		parts := strings.Split(coordinate, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			continue
		}
		ships := false
		for _, configuration := range strings.Split(strings.ToLower(configs), ",") {
			configuration = strings.TrimSpace(configuration)
			if configuration == "" {
				continue
			}
			dev := false
			for _, marker := range devMarkers {
				dev = dev || strings.Contains(configuration, marker)
			}
			ships = ships || !dev
		}
		scope := "dev_only"
		if ships {
			scope = "runtime_transitive"
		}
		deps = append(deps, dependency(model.EcosystemMaven, parts[0]+":"+parts[1], parts[2], parts[2], scope, true, 1))
	}
	if err := scanner.Err(); err != nil {
		return manifest.Result{}, err
	}
	if len(deps) == 0 {
		return manifest.Result{}, fmt.Errorf("no dependency coordinates in Gradle lockfile")
	}
	return manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}}, nil
}

type SBTLockParser struct{}

func (SBTLockParser) Name() string { return "build.sbt.lock" }
func (SBTLockParser) Detect(path string, _ []byte) bool {
	return manifest.Base(path) == "build.sbt.lock"
}
func (SBTLockParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(input.Content), &raw); err != nil {
		return manifest.Result{}, fmt.Errorf("build.sbt.lock: %w", err)
	}
	entries, ok := raw["dependencies"].([]any)
	if !ok {
		return manifest.Result{}, fmt.Errorf("build.sbt.lock has no dependencies list")
	}
	var deps []model.Dependency
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			continue
		}
		group, _ := entry["org"].(string)
		if group == "" {
			group, _ = entry["organization"].(string)
		}
		name, _ := entry["name"].(string)
		if name == "" {
			name, _ = entry["artifact"].(string)
		}
		version, _ := entry["version"].(string)
		if group != "" && name != "" && version != "" {
			scope := "runtime_transitive"
			configs := []any{}
			switch value := entry["configurations"].(type) {
			case []any:
				configs = value
			case string:
				configs = []any{value}
			}
			if len(configs) > 0 {
				devOnly := true
				for _, config := range configs {
					devOnly = devOnly && strings.Contains(strings.ToLower(fmt.Sprint(config)), "test")
				}
				if devOnly {
					scope = "dev_only"
				}
			}
			deps = append(deps, dependency(model.EcosystemMaven, group+":"+name, version, version, scope, true, 1))
		}
	}
	result := manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}}
	if len(deps) == 0 {
		result.Warnings = append(result.Warnings, "build.sbt.lock lists no dependencies")
	}
	return result, nil
}
