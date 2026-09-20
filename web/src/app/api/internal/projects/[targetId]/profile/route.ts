import { NextRequest } from "next/server";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
import { ownsProject } from "@/server/projects/access";

export async function POST(request: NextRequest, { params }: { params: Promise<{ targetId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const targetId = Number((await params).targetId);
  if (!await ownsProject(auth.user.id, targetId)) return errorResponse(404, "NOT_FOUND", "That project doesn't exist.", request);
  const body = await request.json().catch(() => ({})) as { profile?: unknown };
  if (typeof body.profile !== "string" || !body.profile.trim()) {
    await db()`UPDATE tracked_targets SET profile_id = NULL, updated_at = now() WHERE id = ${targetId}`;
    return privateResponse({ data: { profile: null } }, request);
  }
  const slug = body.profile.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const profiles = await db()<Array<{ id: number; slug: string }>>`SELECT id, slug FROM rule_profiles WHERE user_id = ${auth.user.id} AND slug = ${slug}`;
  if (!profiles.length) return errorResponse(404, "NOT_FOUND", `There is no rule profile called '${body.profile.trim()}' on this account.`, request);
  await db()`UPDATE tracked_targets SET profile_id = ${profiles[0].id}, updated_at = now() WHERE id = ${targetId}`;
  return privateResponse({ data: { profile: profiles[0].slug } }, request);
}
