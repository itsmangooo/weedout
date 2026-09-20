import "server-only";

import { db } from "@/server/db/client";

export const findingViews = ["open", "filtered", "dismissed", "resolved"] as const;
export type FindingView = (typeof findingViews)[number];
export const MAX_FINDING_LIMIT = 200;
export const DEFAULT_FINDING_LIMIT = 25;
export const HISTORY_DAYS = 365;

type FindingRow = {
  id: number;
  project_id: number;
  project_name: string;
  vulnerability_id: string;
  cve_ids: string[] | null;
  package_name: string;
  package_version: string;
  severity: string;
  is_kev: boolean;
  automated_reachability: string;
  reachability_evidence: Array<Record<string, unknown>> | null;
  reachability: string;
  status: string;
  fixed_version: string | null;
  first_seen_at: Date;
};

export async function findingsFor(userId: number, show: FindingView, requestedLimit: number) {
  const sql = db();
  const limit = Math.min(Math.max(requestedLimit, 1), MAX_FINDING_LIMIT);
  let rows: FindingRow[];
  const columns = sql`
    SELECT m.id, t.id AS project_id, t.name AS project_name,
           m.vulnerability_id, v.cve_ids, m.package_name, m.package_version,
           m.severity, m.is_kev, m.automated_reachability,
           m.reachability_evidence, m.reachability, m.status, m.fixed_version, m.first_seen_at
    FROM cve_matches m
    JOIN tracked_targets t ON t.id = m.target_id
    JOIN vulnerabilities v ON v.id = m.vulnerability_id
  `;
  const order = sql`
    ORDER BY m.is_kev DESC,
      CASE m.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
      m.first_seen_at DESC
    LIMIT ${limit}
  `;
  if (show === "open") {
    rows = await sql<FindingRow[]>`${columns} WHERE t.user_id = ${userId} AND m.verdict = 'actionable' AND m.status = 'open' ${order}`;
  } else if (show === "filtered") {
    rows = await sql<FindingRow[]>`${columns} WHERE t.user_id = ${userId} AND m.verdict = 'suppressed' AND m.status = 'filtered' ${order}`;
  } else if (show === "dismissed") {
    rows = await sql<FindingRow[]>`${columns} WHERE t.user_id = ${userId} AND m.status = 'dismissed' AND (m.dismissed_at IS NULL OR m.dismissed_at >= now() - (${HISTORY_DAYS} * interval '1 day')) ${order}`;
  } else {
    rows = await sql<FindingRow[]>`${columns} WHERE t.user_id = ${userId} AND m.status = 'resolved' AND (m.resolved_at IS NULL OR m.resolved_at >= now() - (${HISTORY_DAYS} * interval '1 day')) ${order}`;
  }

  return {
    data: rows.map((row) => ({
      id: row.id,
      project: { id: row.project_id, name: row.project_name },
      identifier: row.cve_ids?.[0] ?? row.vulnerability_id,
      package_name: row.package_name,
      installed_version: row.package_version,
      severity: row.severity,
      is_exploited: row.is_kev,
      reachability: row.automated_reachability,
      reachability_evidence: row.reachability_evidence ?? [],
      dependency_relationship: row.reachability,
      fixed_version: row.fixed_version,
      status: row.status,
      detected_at: row.first_seen_at,
    })),
    meta: {
      show,
      limit,
      count: rows.length,
      history_days: show === "dismissed" || show === "resolved" ? HISTORY_DAYS : null,
    },
  };
}
