// Package manifest provides an extensible registry of dependency parsers.
package manifest

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

var ErrUnsupported = errors.New("unsupported manifest")

type Result struct {
	Graph    model.DependencyGraph
	Warnings []string
}

// Parser is the only contract required to add an ecosystem or manifest format.
type Parser interface {
	Name() string
	Detect(path string, content []byte) bool
	Parse(context.Context, model.ManifestInput) (Result, error)
}

type Registry struct {
	mu      sync.RWMutex
	parsers []Parser
}

func NewRegistry(parsers ...Parser) *Registry {
	r := &Registry{}
	for _, parser := range parsers {
		r.Register(parser)
	}
	return r
}

func (r *Registry) Register(parser Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsers = append(r.parsers, parser)
	sort.SliceStable(r.parsers, func(i, j int) bool { return r.parsers[i].Name() < r.parsers[j].Name() })
}

func (r *Registry) Parse(ctx context.Context, input model.ManifestInput) (Result, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, parser := range r.parsers {
		if input.Kind == parser.Name() || (input.Kind == "" && parser.Detect(input.Path, []byte(input.Content))) {
			return parser.Parse(ctx, input)
		}
	}
	return Result{}, fmt.Errorf("%w: %s", ErrUnsupported, filepath.Base(input.Path))
}

func Base(path string) string { return strings.ToLower(filepath.Base(filepath.ToSlash(path))) }
