import { NextRequest } from "next/server";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";

export async function POST(request: NextRequest, { params }: { params: Promise<{ targetId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const targetId = Number((await params).targetId);
  const body = await request.json().catch(() => ({})) as { name?: unknown };
  const name = typeof body.name === "string" ? body.name.trim().slice(0, 200) : "";
  if (!name) return errorResponse(400, "INVALID_REQUEST", "Give the project a name.", request);
  const rows = await db()<Array<{ id: number; name: string }>>`UPDATE tracked_targets SET name = ${name}, updated_at = now() WHERE id = ${targetId} AND user_id = ${auth.user.id} RETURNING id, name`;
  if (!rows.length) return errorResponse(404, "NOT_FOUND", "That project doesn't exist.", request);
  return privateResponse({ data: rows[0] }, request);
}
