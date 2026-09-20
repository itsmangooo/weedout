import "server-only";

import { scan } from "@/server/engine/client";
import type { Dependency, Finding } from "@/server/engine/types";
import { db } from "@/server/db/client";

type Manifest = { id: number; path: string; kind: string; ecosystem: string; content: string };
type Target = {
  id: number; user_id: number; direct_threshold: string | null; transitive_threshold: string | null;
  dev_threshold: string | null; epss_threshold: number | null;
};
type Ignore = { kind: string; identifier: string; reason: string };
type StoredMatch = { id: number; package_name: string; package_version: string; vulnerability_id: string; verdict: string; status: string };

function relationship(dependency: Dependency) {
  return dependency.scope === "dev_only" ? "dev" : "runtime";
}

function actionableReason(finding: Finding) {
  const rule = finding.rule_decisions.find((decision) => decision.outcome === "actionable" || decision.outcome === "blocking")?.rule;
  if (rule === "malicious_package") return "malicious_package";
  if (rule === "known_exploited") return "exploited_in_wild";
  if (rule === "epss_threshold") return "likely_to_be_exploited";
  if (finding.severity === "critical") return "critical_in_production";
  return "high_severity_direct";
}

function suppressionReason(finding: Finding) {
  const rule = finding.rule_decisions.find((decision) => decision.outcome === "filtered")?.rule;
  if (rule === "ignore") return "ignored_by_rule";
  if (rule === "development_scope") return "dev_only_dependency";
  return "below_severity_threshold";
}

async function reconcile(target: Target, manifest: Manifest, findings: Finding[]) {
  const sql = db();
  const stored = await sql<StoredMatch[]>`
    SELECT id, package_name, package_version, vulnerability_id, verdict, status
    FROM cve_matches WHERE manifest_id = ${manifest.id}
  `;
  const byIdentity = new Map(stored.map((row) => [`${row.package_name}\0${row.package_version}\0${row.vulnerability_id}`, row]));
  const seen = new Set<string>();
  let created = 0;
  let resolved = 0;
  for (const finding of findings) {
    const dependency = finding.dependency;
    const key = `${dependency.name}\0${dependency.version}\0${finding.advisory.id}`;
    seen.add(key);
    const previous = byIdentity.get(key);
    const actionable = finding.verdict === "actionable" || finding.verdict === "blocking";
    const status = actionable ? "open" : "filtered";
    const actionReason = actionable ? actionableReason(finding) : null;
    const filterReason = actionable ? null : suppressionReason(finding);
    if (!previous) {
      await sql`
        INSERT INTO cve_matches (
          target_id, manifest_id, vulnerability_id, ecosystem, package_name, package_version,
          version_spec, version_exact, reachability, automated_reachability, reachability_evidence,
          epss_score, epss_percentile, depth, via, verdict, severity, is_kev, fixed_version,
          actionable_reason, suppression_reason, status, first_seen_at, last_seen_at
        ) VALUES (
          ${target.id}, ${manifest.id}, ${finding.advisory.id}, ${dependency.ecosystem},
          ${dependency.name}, ${dependency.version}, ${(dependency.version_spec ?? "").slice(0, 200)},
          ${dependency.version_exact}, ${relationship(dependency)}, ${dependency.automated_reachability},
          ${sql.json(finding.evidence ?? dependency.reachability_evidence ?? [])},
          ${finding.advisory.epss_score ?? null}, ${finding.advisory.epss_percentile ?? null},
          ${dependency.depth}, ${sql.json(dependency.via ?? [])}, ${actionable ? "actionable" : "suppressed"},
          ${finding.severity}, ${finding.known_exploited}, ${finding.fixed_version ?? null},
          ${actionReason}, ${filterReason}, ${status}, now(), now()
        )
      `;
      if (actionable) created += 1;
      continue;
    }
    const resurfaced = (previous.verdict === "suppressed" || previous.status === "resolved") && actionable;
    await sql`
      UPDATE cve_matches SET
        version_spec = ${(dependency.version_spec ?? "").slice(0, 200)}, version_exact = ${dependency.version_exact},
        reachability = ${relationship(dependency)}, automated_reachability = ${dependency.automated_reachability},
        reachability_evidence = ${sql.json(finding.evidence ?? dependency.reachability_evidence ?? [])},
        epss_score = ${finding.advisory.epss_score ?? null}, epss_percentile = ${finding.advisory.epss_percentile ?? null},
        depth = ${dependency.depth}, via = ${sql.json(dependency.via ?? [])},
        verdict = ${actionable ? "actionable" : "suppressed"}, severity = ${finding.severity},
        is_kev = ${finding.known_exploited}, fixed_version = ${finding.fixed_version ?? null},
        actionable_reason = ${actionReason}, suppression_reason = ${filterReason}, last_seen_at = now(),
        status = CASE WHEN status = 'dismissed' THEN status ELSE ${status}::alert_status END,
        resolved_at = NULL,
        notified_at = CASE WHEN ${resurfaced} THEN NULL ELSE notified_at END
      WHERE id = ${previous.id}
    `;
    if (resurfaced) created += 1;
  }
  for (const row of stored) {
    const key = `${row.package_name}\0${row.package_version}\0${row.vulnerability_id}`;
    if (!seen.has(key) && row.status !== "resolved") {
      await sql`UPDATE cve_matches SET status = 'resolved', resolved_at = now() WHERE id = ${row.id}`;
      resolved += 1;
    }
  }
  return { created, resolved };
}

async function syncDependencies(targetId: number, manifestId: number, dependencies: Dependency[]) {
  const sql = db();
  await sql`DELETE FROM dependencies WHERE manifest_id = ${manifestId}`;
  for (const dependency of dependencies) {
    await sql`
      INSERT INTO dependencies (
        target_id, manifest_id, ecosystem, name, version, version_spec, reachability,
        automated_reachability, reachability_evidence, version_exact, depth, via
      ) VALUES (
        ${targetId}, ${manifestId}, ${dependency.ecosystem}, ${dependency.name}, ${dependency.version},
        ${(dependency.version_spec ?? "").slice(0, 200)}, ${relationship(dependency)},
        ${dependency.automated_reachability}, ${sql.json(dependency.reachability_evidence ?? [])},
        ${dependency.version_exact}, ${dependency.depth}, ${sql.json(dependency.via ?? [])}
      )
    `;
  }
}

export async function scanProject(targetId: number, userId: number) {
  const sql = db();
  const targets = await sql<Target[]>`
    SELECT id, user_id, direct_threshold, transitive_threshold, dev_threshold, epss_threshold
    FROM tracked_targets WHERE id = ${targetId} AND user_id = ${userId} LIMIT 1
  `;
  const target = targets[0];
  if (!target) return null;
  const manifests = await sql<Manifest[]>`
    SELECT id, path, kind, ecosystem, content FROM project_manifests
    WHERE target_id = ${targetId} AND is_active ORDER BY id
  `;
  if (!manifests.length) throw new Error("NO_MANIFEST");
  const ignores = await sql<Ignore[]>`SELECT kind, identifier, reason FROM ignore_rules WHERE target_id = ${targetId} AND overridden_at IS NULL`;
  const runRows = await sql<Array<{ id: number }>>`
    INSERT INTO scan_runs (target_id, status) VALUES (${targetId}, 'running') RETURNING id
  `;
  const runId = runRows[0].id;
  let actionable = 0, filtered = 0, created = 0, resolved = 0, dependencies = 0, unreached = 0;
  try {
    for (const manifest of manifests) {
      const result = await scan({
        manifests: [{ path: manifest.path, kind: manifest.kind, ecosystem: manifest.ecosystem as never, content: manifest.content }],
        rules: {
          direct_threshold: target.direct_threshold ?? undefined,
          transitive_threshold: target.transitive_threshold ?? undefined,
          dev_threshold: target.dev_threshold ?? undefined,
          epss_alert_above: target.epss_threshold ?? undefined,
          ignored: ignores.map((rule) => rule.kind === "package"
            ? { package: rule.identifier, reason: rule.reason }
            : { advisory_id: rule.identifier, reason: rule.reason }),
        },
      } as never);
      await syncDependencies(targetId, manifest.id, result.graph.dependencies);
      const reconciled = await reconcile(target, manifest, result.findings);
      actionable += result.stats.actionable + result.stats.blocking;
      filtered += result.stats.filtered;
      created += reconciled.created;
      resolved += reconciled.resolved;
      dependencies += result.stats.dependencies;
      unreached += result.stats.unreached_by_depth;
      await sql`
        UPDATE project_manifests SET dependency_count = ${result.stats.dependencies}, parse_warnings = ${sql.json(result.warnings ?? [])},
          last_parsed_at = now(), last_parse_error = NULL WHERE id = ${manifest.id}
      `;
    }
    await sql`
      UPDATE tracked_targets SET dependency_count = ${dependencies}, last_scanned_at = now(),
        next_scan_at = now() + interval '4 hours', last_scan_error = NULL,
        unreached_by_depth = ${unreached}, updated_at = now() WHERE id = ${targetId}
    `;
    await sql`
      UPDATE scan_runs SET status = 'success', finished_at = now(), dependencies_scanned = ${dependencies},
        actionable_count = ${actionable}, suppressed_count = ${filtered}, new_actionable_count = ${created},
        resolved_count = ${resolved} WHERE id = ${runId}
    `;
    return { actionable, suppressed: filtered, new: created, resolved, unreached_by_depth: unreached };
  } catch (error) {
    const message = String(error).slice(0, 4000);
    await sql`UPDATE tracked_targets SET last_scan_error = ${message}, next_scan_at = now() + interval '4 hours' WHERE id = ${targetId}`;
    await sql`UPDATE scan_runs SET status = 'failed', finished_at = now(), error = ${message} WHERE id = ${runId}`;
    throw error;
  }
}
