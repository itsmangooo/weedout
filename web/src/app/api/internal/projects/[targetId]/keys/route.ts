import { NextRequest } from "next/server";
import { newApiKey } from "@/server/auth/api-key";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
import { ownsProject } from "@/server/projects/access";

export async function POST(request: NextRequest, { params }: { params: Promise<{ targetId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const targetId = Number((await params).targetId);
  if (!await ownsProject(auth.user.id, targetId)) return errorResponse(404, "NOT_FOUND", "That project doesn't exist.", request);
  const counts = await db()<Array<{ count: string | number }>>`SELECT count(*) AS count FROM api_keys WHERE target_id = ${targetId} AND revoked_at IS NULL`;
  if (Number(counts[0].count) >= 5) return errorResponse(400, "KEY_REFUSED", "This project already has 5 active keys. Revoke one before creating another.", request);
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  const scope = ["scan", "read", "manage"].includes(String(body.scope)) ? String(body.scope) : "scan";
  const name = typeof body.name === "string" ? body.name.trim().slice(0, 120) : "";
  const issued = newApiKey();
  const rows = await db()<Array<{ id: number; prefix: string; scope: string }>>`
    INSERT INTO api_keys (user_id, target_id, token_hash, prefix, name, scope)
    VALUES (${auth.user.id}, ${targetId}, ${issued.hash}, ${issued.prefix}, ${name}, ${scope})
    RETURNING id, prefix, scope
  `;
  return privateResponse({ data: { ...rows[0], token: issued.token } }, request);
}
