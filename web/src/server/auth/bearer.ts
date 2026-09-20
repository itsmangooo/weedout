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
