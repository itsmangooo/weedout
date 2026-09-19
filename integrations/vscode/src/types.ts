export interface Finding {
  id?: number;
  package: string;
  version: string;
  cve: string;
  advisory?: string;
  severity: string;
  exploited: boolean;
  malicious?: boolean;
  fixed_in?: string | null;
  summary?: string;
  via?: string[];
  reachability?: string;
  reachability_evidence?: string[];
  reason?: string;
}

export interface ScanResponse {
  new: number;
  resolved: number;
  findings: Finding[];
  dashboard_url: string;
}

export interface FindingsResponse {
  count: number;
  findings: Finding[];
}

export interface ProjectBinding {
  id: number;
  name: string;
  workspace: string;
}

export interface DependencyOccurrence {
  package: string;
  start: number;
  end: number;
  line: number;
}
