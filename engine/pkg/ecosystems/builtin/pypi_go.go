package builtin

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/itsmangooo/weedout-engine/pkg/manifest"
	"github.com/itsmangooo/weedout-engine/pkg/model"
)

type RequirementsParser struct{}

func (RequirementsParser) Name() string { return "requirements.txt" }
func (RequirementsParser) Detect(path string, _ []byte) bool {
	return strings.HasPrefix(manifest.Base(path), "requirements") && strings.HasSuffix(manifest.Base(path), ".txt")
}
func (RequirementsParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	var deps []model.Dependency
	var warnings []string
	scanner := bufio.NewScanner(strings.NewReader(input.Content))
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(strings.Split(scanner.Text(), "#")[0])
		if raw == "" || strings.HasPrefix(raw, "-") {
			continue
		}
		nameEnd := strings.IndexAny(raw, "<>=!~[ ;@")
		if nameEnd < 0 {
			warnings = append(warnings, fmt.Sprintf("line %d has no version", line))
			continue
		}
		name, spec := strings.TrimSpace(raw[:nameEnd]), strings.TrimSpace(raw[nameEnd:])
		if i := strings.Index(name, "["); i >= 0 {
			name = name[:i]
		}
		version, exact := floor(spec)
		if version == "" {
			warnings = append(warnings, fmt.Sprintf("line %d has no usable version", line))
			continue
		}
		deps = append(deps, dependency(model.EcosystemPyPI, normalizePyPI(name), version, spec, "runtime_direct", exact, 0))
	}
	return manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}, Warnings: warnings}, scanner.Err()
}
func normalizePyPI(name string) string {
	return regexp.MustCompile(`[-_.]+`).ReplaceAllString(strings.ToLower(name), "-")
}

type GoModParser struct{}

func (GoModParser) Name() string                      { return "go.mod" }
func (GoModParser) Detect(path string, _ []byte) bool { return manifest.Base(path) == "go.mod" }
func (GoModParser) Parse(_ context.Context, input model.ManifestInput) (manifest.Result, error) {
	var deps []model.Dependency
	inRequire := false
	for _, source := range strings.Split(input.Content, "\n") {
		line := strings.TrimSpace(strings.Split(source, "//")[0])
		if line == "" {
			continue
		}
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inRequire {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		deps = append(deps, dependency(model.EcosystemGo, parts[0], strings.TrimPrefix(parts[1], "v"), parts[1], "runtime_direct", true, 0))
	}
	if len(deps) == 0 {
		return manifest.Result{}, fmt.Errorf("go.mod has no requirements")
	}
	return manifest.Result{Graph: model.DependencyGraph{Dependencies: dedupe(deps)}}, nil
}
