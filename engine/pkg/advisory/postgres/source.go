// Package postgres adapts Weedout's normalized PostgreSQL advisory mirror to
// the public advisory.Source interface. It queries advisory tables only and
// has no access to users, projects, sessions, findings, or billing data.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/itsmangooo/weedout-engine/pkg/advisory"
	"github.com/itsmangooo/weedout-engine/pkg/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Source struct{ pool *pgxpool.Pool }

func Open(ctx context.Context, databaseURL string) (*Source, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("configure advisory mirror: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect advisory mirror: %w", err)
	}
	return &Source{pool: pool}, nil
}

func (s *Source) Close() { s.pool.Close() }

// Ping verifies both database connectivity and that the mirror contains an
// indexed advisory. An empty mirror must not make the engine look ready: that
// state would make every project appear clean.
func (s *Source) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping advisory mirror: %w", err)
	}
	var populated bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM vulnerability_affected LIMIT 1)`).Scan(&populated); err != nil {
		return fmt.Errorf("check advisory mirror: %w", err)
	}
	if !populated {
		return fmt.Errorf("advisory mirror is empty")
	}
	return nil
}

const query = `
WITH requested(ecosystem, package_name) AS (
  SELECT * FROM unnest($1::text[], $2::text[])
)
SELECT DISTINCT
  v.id, v.aliases, v.summary, v.details, v.severity::text,
  v.cvss_score, v.cvss_vector, v.affected, v.references, v.cwe_ids,
  v.withdrawn,
  EXISTS (
    SELECT 1 FROM jsonb_array_elements_text(v.cve_ids) cve
    JOIN kev_entries kev ON kev.cve_id = upper(cve.value)
  ) AS known_exploited,
  EXISTS (
    SELECT 1 FROM jsonb_array_elements_text(v.cve_ids) cve
    JOIN kev_entries kev ON kev.cve_id = upper(cve.value)
    WHERE kev.known_ransomware_use = true
  ) AS ransomware,
  (
    SELECT epss.score FROM jsonb_array_elements_text(v.cve_ids) cve
    JOIN epss_scores epss ON epss.cve_id = upper(cve.value)
    ORDER BY epss.score DESC LIMIT 1
  ) AS epss_score,
  (
    SELECT epss.percentile FROM jsonb_array_elements_text(v.cve_ids) cve
    JOIN epss_scores epss ON epss.cve_id = upper(cve.value)
    ORDER BY epss.score DESC LIMIT 1
  ) AS epss_percentile
FROM requested request
JOIN vulnerability_affected affected
  ON affected.ecosystem::text = request.ecosystem
 AND affected.package_name = request.package_name
JOIN vulnerabilities v ON v.id = affected.vulnerability_id
WHERE v.withdrawn = false
ORDER BY v.id`

func (s *Source) Advisories(ctx context.Context, queries []advisory.Query) ([]model.Advisory, error) {
	if len(queries) == 0 {
		return []model.Advisory{}, nil
	}
	ecosystems := make([]string, 0, len(queries))
	names := make([]string, 0, len(queries))
	seen := map[string]struct{}{}
	for _, item := range queries {
		key := string(item.Ecosystem) + "\x00" + strings.ToLower(item.Name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ecosystems = append(ecosystems, string(item.Ecosystem))
		names = append(names, strings.ToLower(item.Name))
	}
	rows, err := s.pool.Query(ctx, query, ecosystems, names)
	if err != nil {
		return nil, fmt.Errorf("query advisory mirror: %w", err)
	}
	defer rows.Close()
	items := []model.Advisory{}
	for rows.Next() {
		var item model.Advisory
		var affected json.RawMessage
		if err := rows.Scan(&item.ID, &item.Aliases, &item.Summary, &item.Details, &item.Severity, &item.CVSSScore, &item.CVSSVector, &affected, &item.References, &item.CWEIDs, &item.Withdrawn, &item.KnownExploited, &item.KnownRansomwareUse, &item.EPSSScore, &item.EPSSPercentile); err != nil {
			return nil, fmt.Errorf("read advisory mirror row: %w", err)
		}
		parsed, err := decodeAffected(affected)
		if err != nil {
			return nil, fmt.Errorf("decode %s affected data: %w", item.ID, err)
		}
		item.Affected = parsed
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate advisory mirror: %w", err)
	}
	return items, nil
}

type storedAffected struct {
	Package struct {
		Ecosystem model.Ecosystem `json:"ecosystem"`
		Name      string          `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

func decodeAffected(payload []byte) ([]model.AffectedPackage, error) {
	var stored []storedAffected
	if err := json.Unmarshal(payload, &stored); err != nil {
		return nil, err
	}
	out := []model.AffectedPackage{}
	for _, entry := range stored {
		affected := model.AffectedPackage{Ecosystem: entry.Package.Ecosystem, Name: entry.Package.Name, Versions: entry.Versions}
		for _, r := range entry.Ranges {
			introduced := ""
			open := false
			for _, event := range r.Events {
				if value, ok := event["introduced"]; ok {
					if open {
						affected.Ranges = append(affected.Ranges, model.AffectedRange{Introduced: introduced})
					}
					introduced = value
					open = true
					continue
				}
				if value, ok := event["fixed"]; ok && open {
					affected.Ranges = append(affected.Ranges, model.AffectedRange{Introduced: introduced, Fixed: value})
					open = false
					continue
				}
				if value, ok := event["last_affected"]; ok && open {
					affected.Ranges = append(affected.Ranges, model.AffectedRange{Introduced: introduced, LastAffected: value})
					open = false
				}
			}
			if open {
				affected.Ranges = append(affected.Ranges, model.AffectedRange{Introduced: introduced})
			}
		}
		if affected.Name != "" && (len(affected.Ranges) > 0 || len(affected.Versions) > 0) {
			out = append(out, affected)
		}
	}
	return out, nil
}
