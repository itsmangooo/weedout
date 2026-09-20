import { db } from "@/server/db/client";
import { number, publicResponse } from "@/server/http/responses";
type Feed = { name: string; last_success_at: Date | null; record_count: number };
const stale: Record<string, number> = { osv_npm: 24, osv_pypi: 24, osv_go: 24, osv_crates: 24, osv_maven: 24, kev: 48, epss: 48 };
export async function GET() {
  const sql = db();
  const [feeds, stats] = await Promise.all([
    sql<Feed[]>`SELECT name, last_success_at, record_count FROM feed_syncs WHERE name <> 'backup' ORDER BY name`,
    sql<Array<{ scans: string | number; advisories: string | number; accounts: string | number; projects: string | number }>>`
      SELECT (SELECT count(*) FROM scan_runs WHERE started_at >= now() - interval '24 hours' AND status IN ('ok','success')) AS scans,
             (SELECT count(*) FROM vulnerabilities) AS advisories,
             (SELECT count(*) FROM users) AS accounts,
             (SELECT count(*) FROM tracked_targets) AS projects
    `,
  ]);
  const now = Date.now();
  const views = feeds.map((feed) => {
    const hours = feed.last_success_at ? Math.round(((now - feed.last_success_at.getTime()) / 3_600_000) * 10) / 10 : null;
    const threshold = stale[feed.name] ?? 24;
    return { label: feed.name.replaceAll("_", " "), hours_behind: hours, stale_after_hours: threshold, record_count: feed.record_count, is_stale: hours === null || hours > threshold };
  });
  const row = stats[0];
  const adoption = process.env.STATUS_SHOW_ADOPTION?.toLowerCase() === "true";
  return publicResponse({ data: {
    state: views.length === 0 ? "unknown" : views.some((feed) => feed.is_stale) ? "degraded" : "operational",
    checked_at: new Date(), feeds: views, scans_24h: number(row.scans), advisories: number(row.advisories),
    accounts: adoption ? number(row.accounts) : null, projects: adoption ? number(row.projects) : null,
  } }, 60);
}
