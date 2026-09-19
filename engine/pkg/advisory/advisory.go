// Package advisory defines replaceable normalized advisory providers.
package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

type Query struct {
	Ecosystem model.Ecosystem
	Name      string
}

// Source may be backed by an OSV mirror, a fixture, a filesystem, or a custom store.
type Source interface {
	Advisories(context.Context, []Query) ([]model.Advisory, error)
}

type MemorySource struct{ Items []model.Advisory }

// FileSource is useful for offline scanners, fixtures, and private mirrors that
// export the normalized public advisory model as a JSON array.
type FileSource struct{ Path string }

func (f FileSource) Advisories(ctx context.Context, queries []Query) ([]model.Advisory, error) {
	payload, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("read advisory file: %w", err)
	}
	var items []model.Advisory
	if err := json.Unmarshal(payload, &items); err != nil {
		return nil, fmt.Errorf("decode advisory file: %w", err)
	}
	return (MemorySource{Items: items}).Advisories(ctx, queries)
}

func (m MemorySource) Advisories(_ context.Context, queries []Query) ([]model.Advisory, error) {
	wanted := map[string]struct{}{}
	for _, query := range queries {
		wanted[string(query.Ecosystem)+"\x00"+strings.ToLower(query.Name)] = struct{}{}
	}
	out := make([]model.Advisory, 0)
	for _, item := range m.Items {
		for _, affected := range item.Affected {
			if _, ok := wanted[string(affected.Ecosystem)+"\x00"+strings.ToLower(affected.Name)]; ok {
				out = append(out, item)
				break
			}
		}
	}
	return out, nil
}
