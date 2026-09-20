import { NextRequest } from "next/server";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
import { ownsProject } from "@/server/projects/access";

export async function POST(request: NextRequest, { params }: { params: Promise<{ targetId: string; keyId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const values = await params; const targetId = Number(values.targetId); const keyId = Number(values.keyId);
  if (!await ownsProject(auth.user.id, targetId)) return errorResponse(404, "NOT_FOUND", "That project doesn't exist.", request);
  const rows = await db()<Array<{ id: number }>>`UPDATE api_keys SET revoked_at = coalesce(revoked_at, now()) WHERE id = ${keyId} AND target_id = ${targetId} AND user_id = ${auth.user.id} RETURNING id`;
  if (!rows.length) return errorResponse(404, "NOT_FOUND", "That key doesn't exist.", request);
  return privateResponse({ data: { revoked: true } }, request);
}
