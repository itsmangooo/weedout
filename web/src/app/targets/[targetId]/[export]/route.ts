import { NextRequest, NextResponse } from "next/server";
import { resolveSession, sessionCookie } from "@/server/auth/session";
import { db } from "@/server/db/client";

const fields = ["package", "version", "severity", "exploited_in_wild", "advisory", "cve", "summary", "verdict", "status", "reason", "fixed_version", "ships_to_production", "first_seen", "project", "ecosystem"] as const;
const reasonLabels: Record<string, string> = {
  malicious_package: "Malicious package — remove it",
  likely_to_be_exploited: "Scored likely to be exploited (EPSS)",
  exploited_in_wild: "Actively exploited (CISA KEV)",
  critical_in_production: "Critical severity, ships to production",
  high_severity_direct: "High severity, direct dependency",
  withdrawn: "Advisory withdrawn by its publisher",
  dev_only_dependency: "Dev-only dependency — never ships to production",
  transitive_not_direct: "Transitive dependency, not exploited in the wild",
  below_severity_threshold: "Below severity threshold and not exploited",
  ignored_by_rule: "Ignored by a rule on this project",
};
type ExportRow = Record<(typeof fields)[number], string>;
type FindingRow = {
  package_name: string; package_version: string; severity: string; is_kev: boolean; vulnerability_id: string;
  cve_ids: string[]; summary: string; verdict: string; status: string; actionable_reason: string | null;
  suppression_reason: string | null; fixed_version: string | null; reachability: string; first_seen_at: Date | null;
};
function csvCell(value: string) { return /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value; }

export async function GET(request: NextRequest, { params }: { params: Promise<{ targetId: string; export: string }> }) {
  const { targetId: rawTargetId, export: exportName } = await params;
  const match = /^export\.(csv|json)$/.exec(exportName);
  if (!match) return new NextResponse("Not found", { status: 404 });
  const token = await sessionCookie();
  const user = token ? await resolveSession(token) : null;
  if (!user) return NextResponse.redirect(new URL(`/login?next=${encodeURIComponent(request.nextUrl.pathname + request.nextUrl.search)}`, request.url));
  const targetId = Number(rawTargetId);
  if (!Number.isInteger(targetId)) return new NextResponse("Not found", { status: 404 });
  const targets = await db()<Array<{ id: number; name: string; ecosystem: string }>>`SELECT id,name,ecosystem FROM tracked_targets WHERE id=${targetId} AND user_id=${user.id} LIMIT 1`;
  const target = targets[0];
  if (!target) return NextResponse.json({ detail: "That project doesn't exist." }, { status: 404 });
  const requested = request.nextUrl.searchParams.get("show") ?? "open";
  const selected = ["open", "filtered", "dismissed", "resolved", "all"].includes(requested) ? requested : "open";
  const findings = await db()<FindingRow[]>`
    SELECT m.package_name,m.package_version,m.severity,m.is_kev,m.vulnerability_id,v.cve_ids,v.summary,
      m.verdict,m.status,m.actionable_reason,m.suppression_reason,m.fixed_version,m.reachability,m.first_seen_at
    FROM cve_matches m JOIN vulnerabilities v ON v.id=m.vulnerability_id
    WHERE m.target_id=${targetId} AND (
      ${selected}='all' OR (${selected}='open' AND m.verdict='actionable' AND m.status='open') OR
      (${selected}='filtered' AND m.verdict='suppressed' AND m.status='filtered') OR
      (${selected}='dismissed' AND m.status='dismissed') OR (${selected}='resolved' AND m.status='resolved'))
    ORDER BY m.is_kev DESC,CASE m.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,m.package_name`;
  const rows: ExportRow[] = findings.map((finding) => ({
    package: finding.package_name,
    version: finding.package_version,
    severity: finding.severity,
    exploited_in_wild: finding.is_kev ? "yes" : "no",
    advisory: finding.vulnerability_id,
    cve: finding.cve_ids?.[0] ?? finding.vulnerability_id,
    summary: finding.summary ?? "",
    verdict: finding.verdict,
    status: finding.status,
    reason: reasonLabels[finding.actionable_reason ?? finding.suppression_reason ?? ""] ?? "",
    fixed_version: finding.fixed_version ?? "",
    ships_to_production: finding.reachability === "dev_only" ? "no" : "yes",
    first_seen: finding.first_seen_at?.toISOString() ?? "",
    project: target.name,
    ecosystem: target.ecosystem,
  }));
  const date = new Date().toISOString().slice(0, 10).replaceAll("-", "");
  const slug = target.name.replace(/[^A-Za-z0-9_-]/g, "-").replace(/^-+|-+$/g, "") || "project";
  const format = match[1];
  const filename = `weedout-${slug}-${selected}-${date}.${format}`;
  const headers = { "Content-Disposition": `attachment; filename="${filename}"`, "Cache-Control": "no-store" };
  if (format === "json") return new NextResponse(JSON.stringify({ project: target.name, ecosystem: target.ecosystem, view: selected, exported_at: new Date().toISOString(), count: rows.length, findings: rows }, null, 2), { headers: { ...headers, "Content-Type": "application/json; charset=utf-8" } });
  const body = `${fields.join(",")}\n${rows.map((row) => fields.map((field) => csvCell(row[field])).join(",")).join("\n")}${rows.length ? "\n" : ""}`;
  return new NextResponse(body, { headers: { ...headers, "Content-Type": "text/csv; charset=utf-8" } });
}
