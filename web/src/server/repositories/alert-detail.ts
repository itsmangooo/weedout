import "server-only";

import { db } from "@/server/db/client";

type Finding = {
  id:number; target_id:number; project_name:string; vulnerability_id:string; cve_ids:string[]; summary:string;
  ecosystem:string; package_name:string; package_version:string; version_spec:string; version_exact:boolean;
  fixed_version:string|null; severity:string; is_kev:boolean; epss_score:number|null; automated_reachability:string;
  reachability_evidence:Array<Record<string,unknown>>; reachability:string; verdict:string; status:string; depth:number;
  via:string[]; first_seen_at:Date; dismissed_at:Date|null; dismiss_note:string|null;
  actionable_reason:string|null; suppression_reason:string|null;
};

const severityPhrase:Record<string,string>={critical:"critical",high:"high-severity",medium:"moderate",low:"low-severity",unknown:"unrated"};

function sentence(value:string){const clean=value.trim().replace(/\s+/g," ").replace(/\.+$/,"" );return clean?`${clean}.`:"";}
function why(f:Finding, ransomware=false){
  if(f.verdict==="suppressed"){
    if(f.suppression_reason==="withdrawn")return "The publisher has withdrawn this advisory, usually because it was filed in error or superseded. No action is needed.";
    if(f.suppression_reason==="dev_only_dependency")return `${f.package_name} is a development-only dependency. It is recorded here rather than treated as production work.`;
    if(f.suppression_reason==="transitive_not_direct")return `${f.package_name} is pulled in indirectly and there is no evidence of exploitation in the wild. It is recorded here without interrupting the team.`;
    if(f.suppression_reason==="below_severity_threshold")return `This is rated ${severityPhrase[f.severity]??"unrated"} and is not on CISA's actively-exploited list. It remains visible without clearing the alert threshold.`;
    if(f.suppression_reason==="ignored_by_rule")return "A rule on this project filtered this matching advisory.";
    return "This match did not clear the alerting threshold.";
  }
  if(f.actionable_reason==="malicious_package")return `${f.package_name} is itself malicious. Remove it and treat credentials available to developer and CI machines as exposed.`;
  if(f.actionable_reason==="exploited_in_wild")return `CISA lists this vulnerability as actively exploited in the wild.${ransomware?" It has been used in known ransomware campaigns.":""}`;
  if(f.actionable_reason==="critical_in_production")return `This is rated critical and affects ${f.reachability==="runtime_direct"?"a direct production dependency":"a transitive production dependency"}.`;
  if(f.actionable_reason==="high_severity_direct")return `This is rated high severity in ${f.package_name}, a direct production dependency that can be upgraded by this project.`;
  if(f.actionable_reason==="likely_to_be_exploited")return "Its EPSS score cleared this project's exploitation-probability threshold.";
  return "This match cleared the alerting threshold.";
}
function fix(f:Finding){
  if(f.actionable_reason==="malicious_package")return `Remove ${f.package_name} from your dependencies and reinstall from a clean lockfile. Rotate credentials the install could have read.`;
  if(f.fixed_version){const tail=f.reachability==="runtime_transitive"?" Because it is transitive, you may need to upgrade the direct dependency that pulls it in or use an override/resolution.":"";return `Upgrade ${f.package_name} from ${f.package_version} to ${f.fixed_version} or later. That release contains the fix.${tail}`;}
  return `No fixed version has been published for ${f.package_name} yet. Check the advisory references for a workaround or avoid the affected functionality.`;
}
function command(f:Finding){if(!f.fixed_version)return null;if(f.ecosystem==="npm")return `npm install ${f.package_name}@${f.fixed_version}`;if(f.ecosystem==="PyPI")return `pip install --upgrade '${f.package_name}>=${f.fixed_version}'`;if(f.ecosystem==="Go")return `go get ${f.package_name}@v${f.fixed_version.replace(/^v/,"")}`;return null;}

export async function alertDetail(userId:number, matchId:number){
  const rows=await db()<Finding[]>`
    SELECT m.id,m.target_id,t.name AS project_name,m.vulnerability_id,v.cve_ids,v.summary,
      m.ecosystem,m.package_name,m.package_version,m.version_spec,m.version_exact,m.fixed_version,
      m.severity,m.is_kev,m.epss_score,m.automated_reachability,m.reachability_evidence,m.reachability,
      m.verdict,m.status,m.depth,m.via,m.first_seen_at,m.dismissed_at,m.dismiss_note,
      m.actionable_reason,m.suppression_reason
    FROM cve_matches m JOIN tracked_targets t ON t.id=m.target_id
    JOIN vulnerabilities v ON v.id=m.vulnerability_id
    WHERE m.id=${matchId} AND t.user_id=${userId} LIMIT 1`;
  const f=rows[0];if(!f)return null;
  const kev=f.is_kev?await db()<Array<{cve_id:string;vulnerability_name:string;required_action:string;date_added:Date|null;due_date:Date|null;known_ransomware_use:boolean}>>`
    SELECT cve_id,vulnerability_name,required_action,date_added,due_date,known_ransomware_use
    FROM kev_entries WHERE cve_id = ANY(${f.cve_ids}) LIMIT 1`:[];
  const deliveries=await db()<Array<{channel:string;status:string;created_at:Date;error:string|null}>>`
    SELECT channel,status,created_at,error FROM alerts WHERE match_id=${f.id} ORDER BY created_at DESC LIMIT 10`;
  const confidence=f.version_exact?null:`Your manifest requests '${f.version_spec}', which does not pin an exact version. Weedout assumed ${f.package_version}. Upload a lockfile for an exact answer.`;
  return {
    data:{id:f.id,identifier:f.vulnerability_id,cve_ids:f.cve_ids??[],summary:f.summary??"",package_name:f.package_name,
      installed_version:f.package_version,version_spec:f.version_spec,fixed_version:f.fixed_version,severity:f.severity,
      is_exploited:f.is_kev,epss_score:f.epss_score,reachability:f.automated_reachability,
      reachability_evidence:f.reachability_evidence??[],dependency_relationship:f.reachability,verdict:f.verdict,
      status:f.status,depth:f.depth,via:f.via??[],first_seen_at:f.first_seen_at,dismissed_at:f.dismissed_at,
      dismiss_note:f.dismiss_note,project:{id:f.target_id,name:f.project_name}},
    explanation:{risk:sentence(f.summary)||`A ${severityPhrase[f.severity]??"unrated"} vulnerability was published for ${f.package_name} ${f.package_version}.`,why:why(f,kev[0]?.known_ransomware_use),fix:fix(f),command:command(f),confidence},
    kev:kev[0]??null,deliveries,thresholds:{direct:"high",transitive:"critical"},
  };
}

export async function setAlertStatus(userId:number,matchId:number,status:unknown,note:unknown){
  if(status!=="open"&&status!=="dismissed")return {error:"Only open and dismissed are manual finding states."} as const;
  if(typeof note!=="string"||note.length>500)return {error:"The dismissal note must be 500 characters or fewer."} as const;
  const rows=status==="dismissed"
    ? await db()<Array<{id:number;status:string;dismissed_at:Date|null;dismiss_note:string|null}>>`
      UPDATE cve_matches m SET status='dismissed',dismissed_at=now(),dismiss_note=${note.trim()||null},updated_at=now()
      FROM tracked_targets t WHERE m.id=${matchId} AND t.id=m.target_id AND t.user_id=${userId}
      RETURNING m.id,m.status,m.dismissed_at,m.dismiss_note`
    : await db()<Array<{id:number;status:string;dismissed_at:Date|null;dismiss_note:string|null}>>`
      UPDATE cve_matches m SET status='open',dismissed_at=NULL,dismiss_note=NULL,updated_at=now()
      FROM tracked_targets t WHERE m.id=${matchId} AND t.id=m.target_id AND t.user_id=${userId}
      RETURNING m.id,m.status,m.dismissed_at,m.dismiss_note`;
  return rows[0]??null;
}
