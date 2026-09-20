import { db } from "@/server/db/client";
import { number, publicResponse } from "@/server/http/responses";
export async function GET() {
  const sql = db();
  try {
    const [stats, findings, cves, packages, usedBy, docs] = await Promise.all([
      sql<Array<{ matched: string | number; filtered: string | number; dependencies: string | number; kev: string | number }>>`
        SELECT (SELECT count(*) FROM cve_matches) AS matched,
               (SELECT count(*) FROM cve_matches WHERE verdict = 'suppressed' AND status = 'filtered') AS filtered,
               (SELECT coalesce(sum(dependency_count),0) FROM tracked_targets) AS dependencies,
               (SELECT count(*) FROM kev_entries) AS kev
      `,
      sql<Array<{ cve_id: string[]; package: string; version: string; severity: string; is_kev: boolean; summary: string }>>`
        SELECT v.cve_ids AS cve_id, m.package_name AS package, m.package_version AS version,
               m.severity, m.is_kev, v.summary
        FROM cve_matches m JOIN vulnerabilities v ON v.id = m.vulnerability_id
        JOIN tracked_targets t ON t.id = m.target_id JOIN users u ON u.id = t.user_id
        WHERE m.verdict = 'actionable' AND m.status = 'open' AND (m.severity = 'critical' OR m.is_kev)
          AND NOT v.withdrawn AND u.is_active AND NOT u.is_suspended
        ORDER BY m.first_seen_at DESC LIMIT 12
      `,
      sql<Array<{ cve_id: string[]; summary: string; severity: string; is_kev: boolean; project_count: string | number }>>`
        SELECT v.cve_ids AS cve_id, v.summary, m.severity, m.is_kev, count(DISTINCT m.target_id) AS project_count
        FROM cve_matches m JOIN vulnerabilities v ON v.id = m.vulnerability_id
        JOIN tracked_targets t ON t.id = m.target_id
        WHERE m.first_seen_at >= now() - interval '7 days' AND m.verdict = 'actionable' AND (m.severity = 'critical' OR m.is_kev)
        GROUP BY v.cve_ids, v.summary, m.severity, m.is_kev HAVING count(DISTINCT t.user_id) >= 2
        ORDER BY project_count DESC LIMIT 6
      `,
      sql<Array<{ ecosystem: string; name: string; project_count: string | number; advisory_count: string | number }>>`
        SELECT m.ecosystem, m.package_name AS name, count(DISTINCT m.target_id) AS project_count,
               count(DISTINCT m.vulnerability_id) AS advisory_count
        FROM cve_matches m JOIN tracked_targets t ON t.id = m.target_id
        WHERE m.first_seen_at >= now() - interval '7 days' AND m.verdict = 'actionable' AND (m.severity = 'critical' OR m.is_kev)
        GROUP BY m.ecosystem, m.package_name HAVING count(DISTINCT t.user_id) >= 2
        ORDER BY project_count DESC LIMIT 6
      `,
      sql<Array<{ name: string; website: string | null }>>`SELECT organisation_name AS name, organisation_website AS website FROM users WHERE showcase_opt_in AND showcase_approved_at IS NOT NULL AND organisation_name IS NOT NULL ORDER BY organisation_name`,
      sql<Array<{ slug: string; title: string }>>`SELECT slug, title FROM doc_pages WHERE published ORDER BY position, title`,
    ]);
    const totals = stats[0]; const matched = number(totals.matched); const filtered = number(totals.filtered);
    return publicResponse({ data: {
      stats: { advisories_matched: matched, filtered_out: filtered, filtered_share: matched ? Math.round(filtered / matched * 100) : 0, dependencies_watched: number(totals.dependencies), kev_entries: number(totals.kev) },
      findings: findings.map((row) => ({ ...row, cve_id: row.cve_id?.[0] ?? "—" })),
      trending_cves: cves.map((row) => ({ ...row, cve_id: row.cve_id?.[0] ?? "—", project_count: number(row.project_count) })),
      trending_packages: packages.map((row) => ({ ...row, project_count: number(row.project_count), advisory_count: number(row.advisory_count) })),
      used_by: usedBy, docs,
    } }, 300);
  } catch {
    return publicResponse({ data: { stats: { advisories_matched: 0, filtered_out: 0, filtered_share: 0, dependencies_watched: 0, kev_entries: 0 }, findings: [], trending_cves: [], trending_packages: [], used_by: [], docs: [] } }, 300);
  }
}
