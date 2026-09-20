import "server-only";

import { db } from "@/server/db/client";
import { number } from "@/server/http/responses";

type SummaryRow = {
  projects: string | number;
  dependencies: string | number;
  open_findings: string | number;
  exploited_findings: string | number;
  critical_findings: string | number;
  filtered_findings: string | number;
  dismissed_findings: string | number;
  resolved_findings: string | number;
};

type ProjectRow = {
  id: number;
  name: string;
  ecosystem: string;
  manifest_kind: string | null;
  dependency_count: number;
  is_active: boolean;
  has_manifest: boolean;
  last_scanned_at: Date | null;
  last_scan_failed: boolean;
  open_findings: string | number;
  exploited_findings: string | number;
  filtered_findings: string | number;
};

export async function dashboardFor(userId: number) {
  const sql = db();
  const [summaryRows, projects] = await Promise.all([
    sql<SummaryRow[]>`
      SELECT
        count(DISTINCT t.id) AS projects,
        coalesce(max(totals.dependencies), 0) AS dependencies,
        count(m.id) FILTER (WHERE m.verdict = 'actionable' AND m.status = 'open') AS open_findings,
        count(m.id) FILTER (WHERE m.verdict = 'actionable' AND m.status = 'open' AND m.is_kev) AS exploited_findings,
        count(m.id) FILTER (WHERE m.verdict = 'actionable' AND m.status = 'open' AND m.severity = 'critical') AS critical_findings,
        count(m.id) FILTER (WHERE m.verdict = 'suppressed' AND m.status = 'filtered') AS filtered_findings,
        count(m.id) FILTER (WHERE m.status = 'dismissed') AS dismissed_findings,
        count(m.id) FILTER (WHERE m.status = 'resolved') AS resolved_findings
      FROM tracked_targets t
      CROSS JOIN LATERAL (
        SELECT coalesce(sum(dependency_count), 0) AS dependencies
        FROM tracked_targets WHERE user_id = ${userId}
      ) totals
      LEFT JOIN cve_matches m ON m.target_id = t.id
      WHERE t.user_id = ${userId}
    `,
    sql<ProjectRow[]>`
      SELECT t.id, t.name, t.ecosystem, t.manifest_kind, t.dependency_count,
             t.is_active, (t.manifest_content IS NOT NULL) AS has_manifest,
             t.last_scanned_at, (t.last_scan_error IS NOT NULL) AS last_scan_failed,
             count(m.id) FILTER (WHERE m.verdict = 'actionable' AND m.status = 'open') AS open_findings,
             count(m.id) FILTER (WHERE m.verdict = 'actionable' AND m.status = 'open' AND m.is_kev) AS exploited_findings,
             count(m.id) FILTER (WHERE m.verdict = 'suppressed' AND m.status = 'filtered') AS filtered_findings
      FROM tracked_targets t
      LEFT JOIN cve_matches m ON m.target_id = t.id
      WHERE t.user_id = ${userId}
      GROUP BY t.id
      ORDER BY t.created_at DESC
    `,
  ]);

  const row = summaryRows[0] ?? {
    projects: 0, dependencies: 0, open_findings: 0, exploited_findings: 0,
    critical_findings: 0, filtered_findings: 0, dismissed_findings: 0, resolved_findings: 0,
  };
  const open = number(row.open_findings);
  const filtered = number(row.filtered_findings);
  return {
    data: {
      summary: {
        projects: number(row.projects),
        dependencies: number(row.dependencies),
        open_findings: open,
        exploited_findings: number(row.exploited_findings),
        critical_findings: number(row.critical_findings),
        filtered_findings: filtered,
        dismissed_findings: number(row.dismissed_findings),
        resolved_findings: number(row.resolved_findings),
        filter_rate_percent: open + filtered === 0 ? 0 : Math.round((filtered / (open + filtered)) * 100),
      },
      projects: projects.map((project) => ({
        id: project.id,
        name: project.name,
        ecosystem: project.ecosystem,
        manifest_kind: project.manifest_kind,
        dependency_count: project.dependency_count,
        is_active: project.is_active,
        has_manifest: project.has_manifest,
        last_scanned_at: project.last_scanned_at,
        last_scan_failed: project.last_scan_failed,
        findings: {
          open: number(project.open_findings),
          exploited: number(project.exploited_findings),
          filtered: number(project.filtered_findings),
        },
      })),
    },
  };
}
