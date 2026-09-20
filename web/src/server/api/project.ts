import "server-only";

import { createHash } from "node:crypto";
import { NextRequest,NextResponse } from "next/server";
import { bearer,projectKeyIdentity,type ProjectKeyIdentity } from "@/server/auth/bearer";
import { db } from "@/server/db/client";
import { manifestKind,ecosystemFor } from "@/server/projects/manifest";
import { parsePolicy } from "@/server/projects/policy";
import { scanProject } from "@/server/projects/scan";

export const freePlan={tier:"free",name:"Free",scan_depth:null,custom_rules:true,scan_interval_hours:4,max_projects:null};
export function apiError(status:number,error:string,message:string,extra:Record<string,unknown>={}){const headers:Record<string,string>={"Cache-Control":"no-store"};if(status===401)headers["WWW-Authenticate"]="Bearer";return NextResponse.json({detail:{error,message,...extra}},{status,headers});}
export function apiResponse(body:unknown,status=200){return NextResponse.json(body,{status,headers:{"Cache-Control":"no-store"}});}
export async function authenticateProjectKey(request:NextRequest,need:"scan"|"read"|"manage"){const key=await projectKeyIdentity(bearer(request));if(!key)return {response:apiError(401,"unauthenticated","That project key is not valid.")};const allowed=need==="manage"?key.scope==="manage":need==="read"?["read","manage"].includes(key.scope):["scan","manage"].includes(key.scope);if(!allowed)return {response:apiError(403,"insufficient_scope",`This endpoint requires a ${need} key.`)};return {key};}
const reasonLabels:Record<string,string>={malicious_package:"Malicious package — remove it",likely_to_be_exploited:"Scored likely to be exploited (EPSS)",exploited_in_wild:"Actively exploited (CISA KEV)",critical_in_production:"Critical severity, ships to production",high_severity_direct:"High severity, direct dependency",withdrawn:"Advisory withdrawn by its publisher",dev_only_dependency:"Dev-only dependency — never ships to production",transitive_not_direct:"Transitive dependency, not exploited in the wild",below_severity_threshold:"Below severity threshold and not exploited",ignored_by_rule:"Ignored by a rule on this project"};
export async function projectStatus(key:ProjectKeyIdentity){const rows=await db()<Array<{open:string|number;filtered:string|number;dismissed:string|number;resolved:string|number;critical:string|number;high:string|number;medium:string|number;low:string|number;unknown:string|number;malicious:string|number;exploited:string|number}>>`SELECT count(*) FILTER(WHERE verdict='actionable' AND status='open') AS open,count(*) FILTER(WHERE verdict='suppressed' AND status='filtered') AS filtered,count(*) FILTER(WHERE status='dismissed') AS dismissed,count(*) FILTER(WHERE status='resolved') AS resolved,count(*) FILTER(WHERE verdict='actionable' AND status='open' AND severity='critical') AS critical,count(*) FILTER(WHERE verdict='actionable' AND status='open' AND severity='high') AS high,count(*) FILTER(WHERE verdict='actionable' AND status='open' AND severity='medium') AS medium,count(*) FILTER(WHERE verdict='actionable' AND status='open' AND severity='low') AS low,count(*) FILTER(WHERE verdict='actionable' AND status='open' AND severity='unknown') AS unknown,count(*) FILTER(WHERE verdict='actionable' AND status='open' AND actionable_reason='malicious_package') AS malicious,count(*) FILTER(WHERE verdict='actionable' AND status='open' AND is_kev=true) AS exploited FROM cve_matches WHERE target_id=${key.target_id}`;const row=rows[0];return {project:key.target_name,plan:freePlan,ecosystem:key.ecosystem,dependencies:key.dependency_count,last_scanned_at:key.last_scanned_at,next_scan_at:key.next_scan_at,last_error:key.last_scan_error,counts:{critical:Number(row.critical),high:Number(row.high),medium:Number(row.medium),low:Number(row.low),unknown:Number(row.unknown),malicious:Number(row.malicious),exploited:Number(row.exploited)},open:Number(row.open),filtered:Number(row.filtered),dismissed:Number(row.dismissed),resolved:Number(row.resolved),unreached_by_depth:key.unreached_by_depth,dashboard_url:`${(process.env.BASE_URL??"http://localhost:3000").replace(/\/$/,"")}/targets/${key.target_id}`};}
export async function findings(key:ProjectKeyIdentity,showValue:string|null,limitValue:string|null){const show=["open","filtered","dismissed","resolved"].includes(showValue??"")?showValue??"open":"open",limit=Math.max(1,Math.min(Number(limitValue)||50,200));const rows=await db()<Array<{id:number;package_name:string;package_version:string;vulnerability_id:string;cve_ids:string[];severity:string;is_kev:boolean;actionable_reason:string|null;suppression_reason:string|null;epss_score:number|null;fixed_version:string|null;summary:string;via:string[];depth:number;reachability:string;automated_reachability:string;reachability_evidence:Array<Record<string,unknown>>;status:string;first_seen_at:Date}>>`SELECT m.id,m.package_name,m.package_version,m.vulnerability_id,v.cve_ids,m.severity,m.is_kev,m.actionable_reason,m.suppression_reason,m.epss_score,m.fixed_version,v.summary,m.via,m.depth,m.reachability,m.automated_reachability,m.reachability_evidence,m.status,m.first_seen_at FROM cve_matches m JOIN vulnerabilities v ON v.id=m.vulnerability_id WHERE m.target_id=${key.target_id} AND ((${show}='open' AND m.verdict='actionable' AND m.status='open') OR (${show}='filtered' AND m.verdict='suppressed' AND m.status='filtered') OR (${show}='dismissed' AND m.status='dismissed') OR (${show}='resolved' AND m.status='resolved')) ORDER BY m.is_kev DESC,CASE m.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,m.package_name LIMIT ${limit}`;return {show,plan:freePlan,count:rows.length,findings:rows.map(row=>({id:row.id,package:row.package_name,version:row.package_version,cve:row.cve_ids?.[0]??row.vulnerability_id,advisory:row.vulnerability_id,severity:row.severity,exploited:row.is_kev,malicious:row.actionable_reason==="malicious_package",epss:row.epss_score,fixed_in:row.fixed_version,summary:row.summary,via:row.via??[],depth:row.depth,dependency_relationship:row.reachability,reachability:row.automated_reachability,reachability_evidence:row.reachability_evidence??[],status:row.status,reason:reasonLabels[row.actionable_reason??row.suppression_reason??""]??"",first_seen_at:row.first_seen_at}))};}
export async function history(key:ProjectKeyIdentity,limitValue:string|null){const limit=Math.max(1,Math.min(Number(limitValue)||20,100));const rows=await db()<Array<{started_at:Date;finished_at:Date|null;status:string;dependencies_scanned:number;actionable_count:number;suppressed_count:number;new_actionable_count:number;resolved_count:number;error:string|null}>>`SELECT started_at,finished_at,status,dependencies_scanned,actionable_count,suppressed_count,new_actionable_count,resolved_count,error FROM scan_runs WHERE target_id=${key.target_id} ORDER BY started_at DESC LIMIT ${limit}`;return {runs:rows.map(row=>({started_at:row.started_at,status:row.status,dependencies_scanned:row.dependencies_scanned,actionable:row.actionable_count,suppressed:row.suppressed_count,new:row.new_actionable_count,resolved:row.resolved_count,duration_seconds:row.finished_at?(row.finished_at.getTime()-row.started_at.getTime())/1000:null,error:row.error}))};}
const signalLabels:Record<string,string>={unmaintained:"Unmaintained package",low_maintainer_count:"Few maintainers",missing_repository:"No source repository",install_scripts:"Runs install scripts",provenance_missing:"No provenance",suspicious_name:"Possible typosquat"};
export async function supplyChain(key:ProjectKeyIdentity){const rows=await db()<Array<{package_name:string;package_version:string;kind:string;level:string;detail:string}>>`SELECT package_name,package_version,kind,level,detail FROM supply_chain_findings WHERE target_id=${key.target_id} AND status='open' ORDER BY first_seen_at DESC`;return {signals:rows.map(row=>({package:row.package_name,version:row.package_version,kind:row.kind,label:signalLabels[row.kind]??row.kind,level:row.level,detail:row.detail}))};}
export async function rules(key:ProjectKeyIdentity){const parsed=parsePolicy(key.policy_file);const ignores=await db()<Array<{identifier:string;kind:string;reason:string;created_by_email:string|null;created_at:Date;overridden_at:Date|null}>>`SELECT identifier,kind,reason,created_by_email,created_at,overridden_at FROM ignore_rules WHERE target_id=${key.target_id} ORDER BY created_at DESC`;return {thresholds:{direct:key.direct_threshold,transitive:key.transitive_threshold,epss:key.epss_threshold},ignores:ignores.map(row=>({identifier:row.identifier,kind:row.kind,reason:row.reason,created_by:row.created_by_email,created_at:row.created_at,overridden_at:row.overridden_at})),policy_file:{present:Boolean(key.policy_file),updated_at:key.policy_file_updated_at,error:key.policy_file_error??parsed.error,ignores:parsed.ignored.filter(i=>i.advisory_id).map(i=>i.advisory_id),ignored_packages:parsed.ignored.filter(i=>i.package).map(i=>i.package)},plan:freePlan};}
export async function profiles(key:ProjectKeyIdentity){const rows=await db()<Array<{id:number;name:string;slug:string;description:string;is_default:boolean;document:string}>>`SELECT id,name,slug,description,is_default,document FROM rule_profiles WHERE user_id=${key.user_id} ORDER BY is_default DESC,name`;return {profiles:rows.map(row=>({name:row.name,slug:row.slug,description:row.description,is_default:row.is_default,in_use_here:row.id===key.profile_id,document:row.document})),applies_here:rows.find(row=>row.id===key.profile_id||(!key.profile_id&&row.is_default))?.slug??null};}
export async function addRule(key:ProjectKeyIdentity,body:Record<string,unknown>){const kind=body.kind==="package"?"package":"advisory",identifier=typeof body.identifier==="string"?body.identifier.trim():"",reason=typeof body.reason==="string"?body.reason.trim():"";if(!identifier||identifier.length>300||!reason||reason.length>500)throw new ApiProjectError(400,"invalid_rule","An ignore rule needs an identifier and a reason.");const existing=await db()<Array<{id:number}>>`SELECT id FROM ignore_rules WHERE target_id=${key.target_id} AND kind=${kind} AND lower(identifier)=lower(${identifier})`;if(existing.length)throw new ApiProjectError(409,"already_ignored",`${identifier} is already ignored on this project.`);await db()`INSERT INTO ignore_rules (target_id,identifier,kind,reason,created_by_email) VALUES (${key.target_id},${identifier},${kind},${reason},${`api key ${key.prefix}`})`;return {identifier,kind,reason};}
export async function removeRule(key:ProjectKeyIdentity,identifier:string){const rows=await db()<Array<{identifier:string;kind:string}>>`DELETE FROM ignore_rules WHERE id=(SELECT id FROM ignore_rules WHERE target_id=${key.target_id} AND lower(identifier)=lower(${identifier.trim()}) LIMIT 1) RETURNING identifier,kind`;if(!rows[0])throw new ApiProjectError(404,"no_such_rule",`${identifier.trim()} is not ignored here.`);return {...rows[0],removed:true};}
export class ApiProjectError extends Error{constructor(public status:number,public code:string,message:string){super(message);}}
const sourceSuffixes = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);

function safeSourcePath(rawPath: string) {
  const raw = rawPath.replaceAll("\\", "/").trim();
  if (!raw || raw.length > 400 || /[\u0000-\u001f]/.test(raw) || /^[A-Za-z]:/.test(raw) || raw.startsWith("/")) return null;
  const parts = raw.split("/").filter((part) => part && part !== ".");
  if (!parts.length || parts.includes("..")) return null;
  const path = parts.join("/");
  const suffix = path.includes(".") ? `.${path.split(".").at(-1)?.toLowerCase()}` : "";
  return sourceSuffixes.has(suffix) ? path : null;
}

function decodeUtf8(buffer: ArrayBuffer) {
  return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
}

async function sourceBundle(form: FormData) {
  const uploads = form.getAll("sources").filter((value): value is File => value instanceof File);
  if (uploads.length > 512) throw new ApiProjectError(413, "too_many_source_files", "Source analysis accepts at most 512 files per scan.");

  const rawContext = form.get("source_context");
  let context: Record<string, unknown> = {};
  if (typeof rawContext === "string" && rawContext) {
    if (rawContext.length > 100_000) throw new ApiProjectError(413, "source_context_too_large", "The source inventory metadata is too large.");
    try {
      const parsed: unknown = JSON.parse(rawContext);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
      context = parsed as Record<string, unknown>;
    } catch {
      throw new ApiProjectError(400, "invalid_source_context", "The source inventory metadata must be a valid JSON object.");
    }
  }

  const rawPaths = context.files ?? uploads.map((upload) => upload.name);
  if (!Array.isArray(rawPaths) || rawPaths.length !== uploads.length || rawPaths.some((path) => typeof path !== "string")) {
    throw new ApiProjectError(400, "invalid_source_context", "The source inventory must name every attached source file exactly once.");
  }
  if (context.notes !== undefined && !Array.isArray(context.notes)) {
    throw new ApiProjectError(400, "invalid_source_context", "Source analysis notes must be a list.");
  }

  let complete = context.complete === true;
  const notes = Array.isArray(context.notes)
    ? context.notes.map(String).filter((note) => note.trim()).slice(0, 20).map((note) => note.slice(0, 300))
    : [];
  if (!(typeof rawContext === "string" && rawContext)) {
    complete = false;
    notes.push("No complete source inventory was supplied; unobserved dependencies remain unknown.");
  }

  const sources: Array<{ path: string; content: string }> = [];
  const seen = new Set<string>();
  let total = 0;
  for (let index = 0; index < uploads.length; index += 1) {
    const path = safeSourcePath(String(rawPaths[index]));
    if (!path) throw new ApiProjectError(400, "invalid_source_path", `Unsupported or unsafe source path: ${String(rawPaths[index]).slice(0, 120)}.`);
    if (seen.has(path)) throw new ApiProjectError(400, "invalid_source_context", `The source inventory names ${path} more than once.`);
    seen.add(path);
    const upload = uploads[index];
    if (upload.size > 512 * 1024) throw new ApiProjectError(413, "source_file_too_large", `${path} is larger than 512 KiB.`);
    total += upload.size;
    if (total > 4 * 1024 * 1024) throw new ApiProjectError(413, "source_bundle_too_large", "Source analysis accepts at most 4 MiB.");
    try {
      sources.push({ path, content: decodeUtf8(await upload.arrayBuffer()) });
    } catch {
      complete = false;
      notes.push(`${path} was not UTF-8 and could not be analysed.`);
    }
  }
  return { sources, context: { complete, notes: [...new Set(notes)] } };
}

export async function runApiScan(key: ProjectKeyIdentity, request: NextRequest) {
  const form = await request.formData();
  const manifest = form.get("manifest");
  if (!(manifest instanceof File) || !manifest.name) throw new ApiProjectError(400, "missing_file", "Attach the lockfile as a multipart field named 'manifest'.");
  const maxBytes = Number(process.env.API_SCAN_MAX_BYTES ?? 5 * 1024 * 1024);
  if (manifest.size > maxBytes) throw new ApiProjectError(413, "file_too_large", `That file is larger than ${Math.floor(maxBytes / 1024 / 1024)} MB.`);
  let content: string;
  try { content = decodeUtf8(await manifest.arrayBuffer()); }
  catch { throw new ApiProjectError(400, "not_utf8", "That file isn't valid UTF-8 text — is it a binary file?"); }
  if (!content.trim()) throw new ApiProjectError(400, "empty_file", "That file is empty.");
  const kind = manifestKind(manifest.name);
  if (!kind) throw new ApiProjectError(422, "unsupported_manifest", "Could not recognise that dependency manifest.");
  const ecosystem = ecosystemFor(kind);
  if (ecosystem !== key.ecosystem) throw new ApiProjectError(422, "unsupported_manifest", `This project tracks ${key.ecosystem} dependencies, but that file is ${ecosystem}.`);
  const recent = await db()<Array<{ count: string | number }>>`SELECT count(*) AS count FROM scan_runs WHERE target_id=${key.target_id} AND started_at>=now()-interval '1 hour'`;
  const limit = Number(process.env.API_SCAN_RATE_LIMIT_PER_HOUR ?? 60);
  if (limit > 0 && Number(recent[0]?.count ?? 0) >= limit) throw new ApiProjectError(429, "rate_limited", `This project has run ${recent[0].count} scans in the last hour (limit ${limit}). Try again shortly.`);

  const policy = form.get("policy");
  if (policy instanceof File && policy.name) {
    if (policy.size > 256 * 1024) throw new ApiProjectError(413, "policy_too_large", "That .weedout.yml is too large to read.");
    const document = await policy.text(), parsed = parsePolicy(document);
    await db()`UPDATE tracked_targets SET policy_file=${document},policy_file_updated_at=now(),policy_file_error=${parsed.error ?? null} WHERE id=${key.target_id}`;
  }

  const digest = createHash("sha256").update(content).digest("hex");
  const existing = await db()<Array<{ id: number; content_hash: string }>>`SELECT id,content_hash FROM project_manifests WHERE target_id=${key.target_id} AND is_active ORDER BY id LIMIT 1`;
  const changed = existing[0]?.content_hash !== digest;
  if (existing.length) await db()`UPDATE project_manifests SET path=${manifest.name.slice(0, 400)},kind=${kind},ecosystem=${ecosystem},content=${content},content_hash=${digest},updated_at=now() WHERE id=${existing[0].id}`;
  else await db()`INSERT INTO project_manifests (target_id,path,kind,ecosystem,content,content_hash,dependency_count,is_active) VALUES (${key.target_id},${manifest.name.slice(0, 400)},${kind},${ecosystem},${content},${digest},0,true)`;
  await db()`UPDATE tracked_targets SET manifest_kind=${kind},manifest_content=${content},content_hash=${digest},updated_at=now() WHERE id=${key.target_id}`;

  const bundle = await sourceBundle(form);
  const profile = form.get("profile");
  let outcome;
  try {
    outcome = await scanProject(key.target_id, key.user_id, {
      sources: bundle.sources,
      sourceContext: bundle.context,
      requestedProfile: typeof profile === "string" ? profile || null : null,
      deliveredInApp: true,
    });
  } catch (error) {
    const message = String(error);
    if (message.includes("NO_SUCH_PROFILE:")) throw new ApiProjectError(400, "no_such_profile", `No rule profile named ${message.split(":").at(-1)}.`);
    throw new ApiProjectError(503, "scan_failed", message.replace(/^Error:\s*/, ""));
  }
  if (!outcome) throw new ApiProjectError(404, "no_such_project", "No such project.");
  const refreshed = await projectKeyIdentity(bearer(request), false);
  if (!refreshed) throw new ApiProjectError(401, "unauthenticated", "That project key is not valid.");
  const status = await projectStatus(refreshed);
  const blocking = await findings(refreshed, "open", "20");
  return {
    project: key.target_name,
    plan: freePlan,
    manifest_changed: changed,
    dependencies_scanned: refreshed.dependency_count,
    actionable: outcome.actionable,
    suppressed: outcome.suppressed,
    new: outcome.new,
    resolved: outcome.resolved,
    counts: status.counts,
    reachability: outcome.reachability,
    findings: blocking.findings.filter((finding) => finding.severity === "critical" || finding.severity === "high" || finding.exploited || finding.malicious),
    warnings: outcome.warnings,
    dashboard_url: status.dashboard_url,
  };
}
