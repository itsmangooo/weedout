import { NextRequest } from "next/server";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
export async function POST(request: NextRequest, { params }: { params: Promise<{ profileId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const profileId = Number((await params).profileId);
  const owned = await db()<Array<{ id: number }>>`SELECT id FROM rule_profiles WHERE id = ${profileId} AND user_id = ${auth.user.id}`;
  if (!owned.length) return errorResponse(404, "NOT_FOUND", "That profile doesn't exist.", request);
  await db().begin(async (sql) => {
    await sql.unsafe("UPDATE rule_profiles SET is_default = false WHERE user_id = $1", [auth.user.id]);
    await sql.unsafe("UPDATE rule_profiles SET is_default = true WHERE id = $1", [profileId]);
  });
  const rows = await db()<Array<Record<string, unknown>>>`SELECT id, name, slug, description, document, is_default, updated_at FROM rule_profiles WHERE id = ${profileId}`;
  return privateResponse({ data: { ...rows[0], used_by: 0 } }, request);
}
