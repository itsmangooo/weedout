export type Ecosystem = "npm" | "PyPI" | "Go" | "crates.io" | "Maven";

export type ScanRequest = {
  schema_version?: "v1";
  request_id?: string;
  manifests: Array<{ path: string; kind?: string; ecosystem?: Ecosystem; content: string }>;
  sources?: Array<{ path: string; content: string }>;
  source_context?: { complete?: boolean; notes?: string[] };
  rules?: Record<string, unknown>;
  advisories?: { provider?: string; inline?: Array<Record<string, unknown>> };
};

export type ScanResult = {
  schema_version: "v1";
  engine_version: string;
  request_id?: string;
  input_digest: string;
  graph: { dependencies: Dependency[] };
  findings: Finding[];
  stats: {
    manifests: number;
    dependencies: number;
    matched: number;
    actionable: number;
    filtered: number;
    blocking: number;
    unreached_by_depth: number;
  };
  warnings?: string[];
};

export type ReachabilityEvidence = {
  source_file: string;
  line?: number;
  import_kind: string;
  imported_package: string;
  dependency_path?: string[];
  explanation: string;
};

export type Dependency = {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  version_spec?: string;
  version_exact: boolean;
  scope: string;
  depth: number;
  via?: string[];
  automated_reachability: string;
  reachability_evidence?: ReachabilityEvidence[];
};

export type Advisory = {
  id: string;
  aliases?: string[];
  summary?: string;
  severity: string;
  known_exploited?: boolean;
  epss_score?: number;
  epss_percentile?: number;
};

export type Finding = {
  id: string;
  dependency: Dependency;
  advisory: Advisory;
  severity: string;
  verdict: string;
  fixed_version?: string;
  known_exploited: boolean;
  reachability: string;
  evidence?: ReachabilityEvidence[];
  rule_decisions: Array<{ rule: string; outcome: string; explanation: string }>;
  filtering_reason?: string;
  remediation: string;
  explanation: string;
};
