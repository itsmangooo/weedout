// Package model defines the versioned public contract shared by engine consumers.
// It deliberately contains no database, account, project, or web-product types.
package model

import "time"

const SchemaVersion = "v1"

type Ecosystem string

const (
	EcosystemNPM   Ecosystem = "npm"
	EcosystemPyPI  Ecosystem = "PyPI"
	EcosystemGo    Ecosystem = "Go"
	EcosystemCargo Ecosystem = "crates.io"
	EcosystemMaven Ecosystem = "Maven"
)

type ManifestInput struct {
	Path      string    `json:"path"`
	Kind      string    `json:"kind,omitempty"`
	Ecosystem Ecosystem `json:"ecosystem,omitempty"`
	Content   string    `json:"content"`
}

type SourceFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type ReachabilityEvidence struct {
	SourceFile      string   `json:"source_file"`
	Line            int      `json:"line,omitempty"`
	ImportKind      string   `json:"import_kind"`
	ImportedPackage string   `json:"imported_package"`
	DependencyPath  []string `json:"dependency_path,omitempty"`
	Explanation     string   `json:"explanation"`
}

type Dependency struct {
	Ecosystem             Ecosystem              `json:"ecosystem"`
	Name                  string                 `json:"name"`
	Version               string                 `json:"version"`
	VersionSpec           string                 `json:"version_spec,omitempty"`
	VersionExact          bool                   `json:"version_exact"`
	Scope                 string                 `json:"scope"`
	Depth                 int                    `json:"depth"`
	Via                   []string               `json:"via,omitempty"`
	AutomatedReachability string                 `json:"automated_reachability"`
	ReachabilityEvidence  []ReachabilityEvidence `json:"reachability_evidence,omitempty"`
}

type DependencyGraph struct {
	Dependencies []Dependency `json:"dependencies"`
}

type AffectedRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type AffectedPackage struct {
	Ecosystem Ecosystem       `json:"ecosystem"`
	Name      string          `json:"name"`
	Ranges    []AffectedRange `json:"ranges,omitempty"`
	Versions  []string        `json:"versions,omitempty"`
}

type Advisory struct {
	ID                 string            `json:"id"`
	Aliases            []string          `json:"aliases,omitempty"`
	Summary            string            `json:"summary,omitempty"`
	Details            string            `json:"details,omitempty"`
	Severity           string            `json:"severity"`
	CVSSScore          *float64          `json:"cvss_score,omitempty"`
	CVSSVector         string            `json:"cvss_vector,omitempty"`
	Affected           []AffectedPackage `json:"affected"`
	References         []string          `json:"references,omitempty"`
	CWEIDs             []string          `json:"cwe_ids,omitempty"`
	Withdrawn          bool              `json:"withdrawn,omitempty"`
	KnownExploited     bool              `json:"known_exploited,omitempty"`
	KnownRansomwareUse bool              `json:"known_ransomware_use,omitempty"`
	EPSSScore          *float64          `json:"epss_score,omitempty"`
	EPSSPercentile     *float64          `json:"epss_percentile,omitempty"`
}

type IgnoreRule struct {
	AdvisoryID string `json:"advisory_id,omitempty"`
	Package    string `json:"package,omitempty"`
	Reason     string `json:"reason"`
}

type RuleConfig struct {
	DirectThreshold     string       `json:"direct_threshold,omitempty"`
	TransitiveThreshold string       `json:"transitive_threshold,omitempty"`
	DevThreshold        string       `json:"dev_threshold,omitempty"`
	EPSSAlertAbove      *float64     `json:"epss_alert_above,omitempty"`
	AlwaysAlertOnKEV    *bool        `json:"always_alert_on_kev,omitempty"`
	BlockOnKEV          bool         `json:"block_on_kev,omitempty"`
	Ignored             []IgnoreRule `json:"ignored,omitempty"`
	MaxDepth            *int         `json:"max_depth,omitempty"`
}

type RuleDecision struct {
	Rule        string `json:"rule"`
	Outcome     string `json:"outcome"`
	Explanation string `json:"explanation"`
}

type Finding struct {
	ID              string                 `json:"id"`
	Dependency      Dependency             `json:"dependency"`
	Advisory        Advisory               `json:"advisory"`
	Severity        string                 `json:"severity"`
	Verdict         string                 `json:"verdict"`
	Affected        bool                   `json:"affected"`
	AffectedReason  string                 `json:"affected_reason"`
	FixedVersion    string                 `json:"fixed_version,omitempty"`
	KnownExploited  bool                   `json:"known_exploited"`
	Reachability    string                 `json:"reachability"`
	Evidence        []ReachabilityEvidence `json:"evidence,omitempty"`
	RuleDecisions   []RuleDecision         `json:"rule_decisions"`
	FilteringReason string                 `json:"filtering_reason,omitempty"`
	Remediation     string                 `json:"remediation"`
	Explanation     string                 `json:"explanation"`
}

type AdvisoryConfig struct {
	Provider string     `json:"provider,omitempty"`
	Inline   []Advisory `json:"inline,omitempty"`
}

type ScanRequest struct {
	SchemaVersion string          `json:"schema_version,omitempty"`
	RequestID     string          `json:"request_id,omitempty"`
	Manifests     []ManifestInput `json:"manifests"`
	Sources       []SourceFile    `json:"sources,omitempty"`
	SourceContext SourceContext   `json:"source_context,omitempty"`
	Rules         RuleConfig      `json:"rules,omitempty"`
	Advisories    AdvisoryConfig  `json:"advisories,omitempty"`
}

// SourceContext describes the source inventory supplied by a caller. Complete
// means discovery and reads finished within the caller's documented limits;
// it does not claim that static analysis understands every possible program.
type SourceContext struct {
	Complete bool     `json:"complete,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

type ScanStats struct {
	Manifests        int `json:"manifests"`
	Dependencies     int `json:"dependencies"`
	Matched          int `json:"matched"`
	Actionable       int `json:"actionable"`
	Filtered         int `json:"filtered"`
	Blocking         int `json:"blocking"`
	UnreachedByDepth int `json:"unreached_by_depth"`
}

type ScanResult struct {
	SchemaVersion string          `json:"schema_version"`
	EngineVersion string          `json:"engine_version"`
	RequestID     string          `json:"request_id,omitempty"`
	InputDigest   string          `json:"input_digest"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Graph         DependencyGraph `json:"graph"`
	Findings      []Finding       `json:"findings"`
	Stats         ScanStats       `json:"stats"`
	Warnings      []string        `json:"warnings,omitempty"`
}
