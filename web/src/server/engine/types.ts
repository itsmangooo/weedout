export type Ecosystem = "npm" | "PyPI" | "Go" | "crates.io" | "Maven";

export type ScanRequest = {
  schema_version?: "v1";
  request_id?: string;
  manifests: Array<{ path: string; kind?: string; ecosystem?: Ecosystem; content: string }>;
  sources?: Array<{ path: string; content: string }>;
  rules?: Record<string, unknown>;
  advisories?: { provider?: string; inline?: Array<Record<string, unknown>> };
};

export type ScanResult = {
  schema_version: "v1";
  engine_version: string;
  request_id?: string;
  input_digest: string;
  graph: { dependencies: Array<Record<string, unknown>> };
  findings: Array<Record<string, unknown>>;
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
