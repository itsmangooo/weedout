import { NextRequest } from "next/server";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
export async function POST(request: NextRequest, { params }: { params: Promise<{ profileId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const profileId = Number((await params).profileId);
  const rows = await db()<Array<{ id: number }>>`DELETE FROM rule_profiles WHERE id = ${profileId} AND user_id = ${auth.user.id} RETURNING id`;
  if (!rows.length) return errorResponse(404, "NOT_FOUND", "That profile doesn't exist.", request);
  return privateResponse({ data: { deleted: true } }, request);
}
