// Package matching evaluates normalized advisory ranges without knowing where
// advisories or dependencies are stored.
package matching

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

var numeric = regexp.MustCompile(`\d+|[A-Za-z]+`)
var releasePrefix = regexp.MustCompile(`^\d+(?:\.\d+)*`)

type token struct {
	number *int64
	text   string
}

func tokens(raw string) []token {
	value := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	parts := numeric.FindAllString(value, -1)
	out := make([]token, 0, len(parts))
	for _, part := range parts {
		if n, err := strconv.ParseInt(part, 10, 64); err == nil {
			copy := n
			out = append(out, token{number: &copy})
		} else {
			out = append(out, token{text: strings.ToLower(part)})
		}
	}
	for len(out) > 0 {
		last := out[len(out)-1]
		if last.number != nil && *last.number == 0 {
			out = out[:len(out)-1]
		} else {
			break
		}
	}
	return out
}

type parsedVersion struct {
	release   []int64
	qualifier int
	detail    []token
}

func parseVersion(raw string) parsedVersion {
	value := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	value = strings.TrimSuffix(value, "+incompatible")
	value = strings.SplitN(value, "+", 2)[0]
	epoch := int64(0)
	if before, after, ok := strings.Cut(value, "!"); ok {
		epoch, _ = strconv.ParseInt(before, 10, 64)
		value = after
	}
	releaseRaw := releasePrefix.FindString(value)
	release := []int64{epoch}
	for _, part := range strings.Split(releaseRaw, ".") {
		value, _ := strconv.ParseInt(part, 10, 64)
		release = append(release, value)
	}
	for len(release) > 1 && release[len(release)-1] == 0 {
		release = release[:len(release)-1]
	}
	suffix := strings.TrimLeft(strings.TrimPrefix(value, releaseRaw), ".-_+")
	lower := strings.ToLower(suffix)
	qualifier := 0 // stable
	switch {
	case lower == "", lower == "release", lower == "final", lower == "ga":
		qualifier = 0
	case strings.HasPrefix(lower, "post"), strings.HasPrefix(lower, "rev"):
		qualifier = 1
	case strings.HasPrefix(lower, "dev"):
		qualifier = -2
	default:
		qualifier = -1
	}
	return parsedVersion{release: release, qualifier: qualifier, detail: tokens(suffix)}
}

func Compare(_ model.Ecosystem, left, right string) int {
	a, b := parseVersion(left), parseVersion(right)
	for i := 0; i < max(len(a.release), len(b.release)); i++ {
		var x, y int64
		if i < len(a.release) {
			x = a.release[i]
		}
		if i < len(b.release) {
			y = b.release[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	if a.qualifier < b.qualifier {
		return -1
	}
	if a.qualifier > b.qualifier {
		return 1
	}
	for i := 0; i < max(len(a.detail), len(b.detail)); i++ {
		var x, y token
		if i < len(a.detail) {
			x = a.detail[i]
		}
		if i < len(b.detail) {
			y = b.detail[i]
		}
		if x.number != nil && y.number != nil {
			if *x.number < *y.number {
				return -1
			}
			if *x.number > *y.number {
				return 1
			}
			continue
		}
		if x.number != nil {
			return -1
		}
		if y.number != nil {
			return 1
		}
		if x.text < y.text {
			return -1
		}
		if x.text > y.text {
			return 1
		}
	}
	return 0
}

func affectedBy(version string, ecosystem model.Ecosystem, affected model.AffectedPackage) (bool, string) {
	for _, candidate := range affected.Versions {
		if Compare(ecosystem, version, candidate) == 0 {
			return true, fmt.Sprintf("%s is explicitly listed as affected", version)
		}
	}
	for _, r := range affected.Ranges {
		lower := r.Introduced == "" || r.Introduced == "0" || Compare(ecosystem, version, r.Introduced) >= 0
		upper := true
		if r.Fixed != "" {
			upper = Compare(ecosystem, version, r.Fixed) < 0
		} else if r.LastAffected != "" {
			upper = Compare(ecosystem, version, r.LastAffected) <= 0
		}
		if lower && upper {
			return true, fmt.Sprintf("%s is inside the advisory affected range", version)
		}
	}
	return false, fmt.Sprintf("%s is outside the advisory affected range", version)
}

func Match(dep model.Dependency, item model.Advisory) (bool, string, string) {
	if item.Withdrawn {
		return false, "advisory is withdrawn", ""
	}
	fixes := []string{}
	for _, affected := range item.Affected {
		if affected.Ecosystem != dep.Ecosystem || !strings.EqualFold(affected.Name, dep.Name) {
			continue
		}
		ok, reason := affectedBy(dep.Version, dep.Ecosystem, affected)
		if !ok {
			continue
		}
		for _, r := range affected.Ranges {
			if r.Fixed != "" && Compare(dep.Ecosystem, r.Fixed, dep.Version) > 0 {
				fixes = append(fixes, r.Fixed)
			}
		}
		sort.Slice(fixes, func(i, j int) bool { return Compare(dep.Ecosystem, fixes[i], fixes[j]) < 0 })
		fix := ""
		if len(fixes) > 0 {
			fix = fixes[0]
		}
		return true, reason, fix
	}
	return false, "package or version did not match", ""
}
