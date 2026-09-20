import "server-only";
import { createHash } from "node:crypto";
import { db } from "@/server/db/client";
export function bearer(request: Request) { const [scheme, token] = (request.headers.get("authorization") ?? "").split(/\s+/, 2); return scheme?.toLowerCase() === "bearer" ? token : undefined; }
export function opaqueHash(token: string) { return createHash("sha256").update(token).digest("hex"); }
export async function cliIdentity(token?: string) {
  if (!token?.startsWith("woa_")) return null;
  const rows = await db()<Array<{ id: number; user_id: number; device_label: string; expires_at: Date; email: string }>>`
    SELECT c.id, c.user_id, c.device_label, c.expires_at, u.email FROM cli_tokens c JOIN users u ON u.id = c.user_id
    WHERE c.token_hash = ${opaqueHash(token)} AND c.revoked_at IS NULL AND c.expires_at > now() AND u.is_active AND NOT u.is_suspended LIMIT 1`;
  return rows[0] ?? null;
}

export type ProjectKeyIdentity={id:number;user_id:number;target_id:number;prefix:string;scope:string;target_name:string;ecosystem:string;dependency_count:number;last_scanned_at:Date|null;next_scan_at:Date|null;last_scan_error:string|null;unreached_by_depth:number;policy_file:string|null;policy_file_updated_at:Date|null;policy_file_error:string|null;direct_threshold:string|null;transitive_threshold:string|null;epss_threshold:number|null;profile_id:number|null};
export async function projectKeyIdentity(token?:string,recordUse=true){if(!token?.startsWith("wo_")||token.startsWith("woa_"))return null;const rows=await db()<ProjectKeyIdentity[]>`SELECT k.id,k.user_id,k.target_id,k.prefix,k.scope,t.name AS target_name,t.ecosystem,t.dependency_count,t.last_scanned_at,t.next_scan_at,t.last_scan_error,t.unreached_by_depth,t.policy_file,t.policy_file_updated_at,t.policy_file_error,t.direct_threshold,t.transitive_threshold,t.epss_threshold,t.profile_id FROM api_keys k JOIN tracked_targets t ON t.id=k.target_id JOIN users u ON u.id=k.user_id WHERE k.token_hash=${opaqueHash(token)} AND k.revoked_at IS NULL AND u.is_active=true AND u.is_suspended=false LIMIT 1`;const row=rows[0];if(!row)return null;if(recordUse)await db()`UPDATE api_keys SET call_count=call_count+1,last_used_at=CASE WHEN last_used_at IS NULL OR last_used_at<now()-interval '1 minute' THEN now() ELSE last_used_at END WHERE id=${row.id}`;return row;}
