import "server-only";

import { db } from "@/server/db/client";
import { number } from "@/server/http/responses";

const signalLabels: Record<string, string> = {
  typosquat: "Name resembles a popular package",
  unmaintained: "No releases for a long time",
  single_maintainer: "One maintainer",
  provenance_missing: "No build provenance",
  provenance_verified: "Build provenance verified",
};

const validViews = ["open", "filtered", "dismissed", "resolved"] as const;
type View = (typeof validViews)[number];

type Target = Record<string, unknown> & {
  id: number; name: string; ecosystem: string; manifest_kind: string | null;
  manifest_content: string | null; dependency_count: number; is_active: boolean;
  last_scanned_at: Date | null; next_scan_at: Date | null; last_scan_error: string | null;
  unreached_by_depth: number; reachability_analyzed_at: Date | null;
  reachability_source_count: number; reachability_analysis_complete: boolean;
  reachability_analysis_notes: string[] | null; direct_threshold: string | null;
  transitive_threshold: string | null; epss_threshold: number | null; profile_id: number | null;
  policy_file: string | null; policy_file_updated_at: Date | null; policy_file_error: string | null;
  webhook_kind: string | null; discord_webhook_url: string | null;
};

type Match = {
  id: number; vulnerability_id: string; package_name: string; package_version: string;
  severity: string; is_kev: boolean; automated_reachability: string;
  reachability_evidence: Array<Record<string, unknown>> | null; reachability: string;
  status: string; first_seen_at: Date;
};

type CountRow = {
  open: string | number; filtered: string | number; dismissed: string | number;
  resolved: string | number; critical: string | number; high: string | number;
};

type Dependency = {
  name: string; version: string | null; depth: number | null; reachability: string;
  automated_reachability: string; reachability_evidence: Array<Record<string, unknown>> | null;
};

type Run = {
  started_at: Date | null; finished_at: Date | null; status: string; dependencies_scanned: number;
  actionable_count: number; suppressed_count: number; new_actionable_count: number;
  resolved_count: number; error: string | null;
};

type Signal = { package_name: string; package_version: string | null; kind: string; level: string; detail: string };
type Rule = { id: number; identifier: string; kind: string; reason: string; created_by_email: string; created_at: Date | null; overridden_at: Date | null };
type Profile = { id: number; slug: string; name: string; description: string; is_default: boolean };
type Key = { id: number; prefix: string; name: string; scope: string; created_at: Date | null; last_used_at: Date | null; call_count: number; revoked_at: Date | null };

function ignoredIds(document: string | null): string[] {
  if (!document) return [];
  const lines = document.split(/\r?\n/);
  const values = new Set<string>();
  let inIgnored = false;
  for (const line of lines) {
    if (/^\s*(ignore|ignored_ids|advisories)\s*:/.test(line)) { inIgnored = true; continue; }
    if (inIgnored && /^\S/.test(line) && !/^\s*-/.test(line)) inIgnored = false;
    const match = inIgnored ? line.match(/^\s*-\s*["']?([A-Za-z0-9._-]+)["']?\s*$/) : null;
    if (match) values.add(match[1].toUpperCase());
  }
  return [...values].sort();
}

function webhook(url: string | null, kind: string | null) {
  if (!url) return { configured: false, kind: null, host: null };
  let host: string | null = null;
  try { host = new URL(url).hostname; } catch { /* stored legacy value */ }
  return { configured: true, kind, host };
}

export async function projectFor(userId: number, targetId: number, requestedView: string) {
  const sql = db();
  const targets = await sql<Target[]>`SELECT * FROM tracked_targets WHERE id = ${targetId} AND user_id = ${userId} LIMIT 1`;
  const target = targets[0];
  if (!target) return null;
  const view: View = validViews.includes(requestedView as View) ? requestedView as View : "open";
  const where = view === "open"
    ? sql`m.verdict = 'actionable' AND m.status = 'open'`
    : view === "filtered"
      ? sql`m.verdict = 'suppressed' AND m.status = 'filtered'`
      : view === "dismissed" ? sql`m.status = 'dismissed'` : sql`m.status = 'resolved'`;

  const [matches, dependencies, runs, countRows, signals, rules, profiles, keys] = await Promise.all([
    sql<Match[]>`
      SELECT m.id, m.vulnerability_id, m.package_name, m.package_version, m.severity,
             m.is_kev, m.automated_reachability, m.reachability_evidence,
             m.reachability, m.status, m.first_seen_at
      FROM cve_matches m WHERE m.target_id = ${targetId} AND ${where}
      ORDER BY m.is_kev DESC,
        CASE m.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
        m.first_seen_at DESC LIMIT 200
    `,
    sql<Dependency[]>`
      SELECT name, version, depth, reachability, automated_reachability, reachability_evidence
      FROM dependencies WHERE target_id = ${targetId} ORDER BY name LIMIT 500
    `,
    sql<Run[]>`
      SELECT started_at, finished_at, status, dependencies_scanned, actionable_count,
             suppressed_count, new_actionable_count, resolved_count, error
      FROM scan_runs WHERE target_id = ${targetId} ORDER BY started_at DESC LIMIT 10
    `,
    sql<CountRow[]>`
      SELECT
        count(id) FILTER (WHERE verdict = 'actionable' AND status = 'open') AS open,
        count(id) FILTER (WHERE verdict = 'suppressed' AND status = 'filtered') AS filtered,
        count(id) FILTER (WHERE status = 'dismissed') AS dismissed,
        count(id) FILTER (WHERE status = 'resolved') AS resolved,
        count(id) FILTER (WHERE verdict = 'actionable' AND status = 'open' AND severity = 'critical') AS critical,
        count(id) FILTER (WHERE verdict = 'actionable' AND status = 'open' AND severity = 'high') AS high
      FROM cve_matches WHERE target_id = ${targetId}
    `,
    sql<Signal[]>`
      SELECT package_name, package_version, kind, level, detail
      FROM supply_chain_findings WHERE target_id = ${targetId} AND status = 'open'
      ORDER BY first_seen_at DESC
    `,
    sql<Rule[]>`
      SELECT id, identifier, kind, reason, created_by_email, created_at, overridden_at
      FROM ignore_rules WHERE target_id = ${targetId} ORDER BY created_at DESC
    `,
    sql<Profile[]>`
      SELECT id, slug, name, description, is_default FROM rule_profiles
      WHERE user_id = ${userId} ORDER BY is_default DESC, name
    `,
    sql<Key[]>`
      SELECT id, prefix, name, scope, created_at, last_used_at, call_count, revoked_at
      FROM api_keys WHERE user_id = ${userId} AND target_id = ${targetId} ORDER BY created_at DESC
    `,
  ]);
  const counts = countRows[0] ?? { open: 0, filtered: 0, dismissed: 0, resolved: 0, critical: 0, high: 0 };
  const tabCounts = {
    open: number(counts.open), filtered: number(counts.filtered),
    dismissed: number(counts.dismissed), resolved: number(counts.resolved),
  };
  const chosen = profiles.find((profile) => profile.id === target.profile_id);
  const defaultProfile = profiles.find((profile) => profile.is_default);
  const applies = chosen ?? defaultProfile;

  return {
    data: {
      id: target.id, name: target.name, ecosystem: target.ecosystem,
      manifest_kind: target.manifest_kind, has_manifest: target.manifest_content !== null,
      dependency_count: target.dependency_count, is_active: target.is_active,
      last_scanned_at: target.last_scanned_at, next_scan_at: target.next_scan_at,
      last_scan_error: target.last_scan_error, unreached_by_depth: target.unreached_by_depth || 0,
      reachability_analyzed_at: target.reachability_analyzed_at,
      reachability_source_count: target.reachability_source_count || 0,
      reachability_analysis_complete: target.reachability_analysis_complete,
      reachability_analysis_notes: target.reachability_analysis_notes ?? [],
      counts: { critical: number(counts.critical), high: number(counts.high) },
      tab_counts: tabCounts,
    },
    findings: matches.map((match) => ({
      id: match.id, project: { id: target.id, name: target.name },
      identifier: match.vulnerability_id, package_name: match.package_name,
      installed_version: match.package_version, severity: match.severity,
      is_exploited: match.is_kev, reachability: match.automated_reachability,
      reachability_evidence: match.reachability_evidence ?? [],
      dependency_relationship: match.reachability, status: match.status,
      detected_at: match.first_seen_at,
    })),
    dependencies: dependencies.map((dependency) => ({
      name: dependency.name, version: dependency.version ?? "", depth: dependency.depth ?? 0,
      is_direct: (dependency.depth ?? 0) === 0,
      dependency_relationship: dependency.reachability,
      reachability: dependency.automated_reachability,
      reachability_evidence: dependency.reachability_evidence ?? [],
    })),
    recent_runs: runs.map((run) => ({
      started_at: run.started_at, status: run.status,
      dependencies_scanned: run.dependencies_scanned, actionable_count: run.actionable_count,
      suppressed_count: run.suppressed_count, new_actionable_count: run.new_actionable_count,
      resolved_count: run.resolved_count,
      duration_seconds: run.finished_at && run.started_at
        ? (run.finished_at.getTime() - run.started_at.getTime()) / 1000 : null,
      error: run.error,
    })),
    supply_chain: signals.map((signal) => ({ ...signal, label: signalLabels[signal.kind] ?? signal.kind })),
    rules,
    thresholds: { direct: target.direct_threshold, transitive: target.transitive_threshold, epss: target.epss_threshold },
    profiles: {
      chosen: chosen?.slug ?? null, applies: applies?.slug ?? null, applies_name: applies?.name ?? null,
      following_default: !chosen && Boolean(defaultProfile),
      available: profiles.map(({ slug, name, description, is_default }) => ({ slug, name, description, is_default })),
    },
    policy_file: {
      present: Boolean(target.policy_file), updated_at: target.policy_file_updated_at,
      error: target.policy_file_error, ignored_ids: ignoredIds(target.policy_file),
    },
    api_keys: keys.map((key) => ({ ...key, is_active: key.revoked_at === null })),
    webhook: webhook(target.discord_webhook_url, target.webhook_kind),
    can_use_rules: true,
    can_use_webhooks: true,
  };
}
