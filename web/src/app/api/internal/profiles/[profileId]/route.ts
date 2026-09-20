import { NextRequest } from "next/server";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";

function slugify(value: string) { return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""); }
export async function POST(request: NextRequest, { params }: { params: Promise<{ profileId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const profileId = Number((await params).profileId);
  const current = await db()<Array<{ id: number; name: string; slug: string; description: string; document: string }>>`SELECT id, name, slug, description, document FROM rule_profiles WHERE id = ${profileId} AND user_id = ${auth.user.id}`;
  if (!current.length) return errorResponse(404, "NOT_FOUND", "That profile doesn't exist.", request);
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  const name = typeof body.name === "string" ? body.name.trim().slice(0, 80) : current[0].name;
  const slug = slugify(name);
  const description = typeof body.description === "string" ? body.description.trim().slice(0, 300) : current[0].description;
  const document = typeof body.document === "string" ? body.document : current[0].document;
  if (!slug || document.length > 64 * 1024 || /^\s*profile\s*:/m.test(document)) return errorResponse(400, "INVALID_PROFILE", "That profile is not valid.", request);
  const rows = await db()<Array<Record<string, unknown>>>`UPDATE rule_profiles SET name = ${name}, slug = ${slug}, description = ${description}, document = ${document}, updated_at = now() WHERE id = ${profileId} RETURNING id, name, slug, description, document, is_default, updated_at`;
  return privateResponse({ data: { ...rows[0], used_by: 0 } }, request);
}
