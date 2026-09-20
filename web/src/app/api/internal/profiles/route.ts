import { NextRequest } from "next/server";

import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
import { profilesFor } from "@/server/repositories/profiles";

export async function GET(request: NextRequest) {
  const auth = await authenticated(request);
  if ("response" in auth) return auth.response;
  return privateResponse(await profilesFor(auth.user.id), request);
}

function slugify(value: string) { return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""); }

export async function POST(request: NextRequest) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  const name = typeof body.name === "string" ? body.name.trim().slice(0, 80) : "";
  const slug = slugify(name);
  const description = typeof body.description === "string" ? body.description.trim().slice(0, 300) : "";
  const document = typeof body.document === "string" ? body.document : "";
  if (!slug) return errorResponse(400, "INVALID_PROFILE", "Give the profile a name -- something like Production.", request);
  if (document.length > 64 * 1024) return errorResponse(400, "INVALID_PROFILE", "That profile is too large.", request);
  if (/^\s*profile\s*:/m.test(document)) return errorResponse(400, "INVALID_PROFILE", "A profile cannot name another profile.", request);
  const counts = await db()<Array<{ count: string | number }>>`SELECT count(*) AS count FROM rule_profiles WHERE user_id = ${auth.user.id}`;
  if (Number(counts[0].count) >= 20) return errorResponse(400, "INVALID_PROFILE", "That is 20 profiles, which is the limit.", request);
  try {
    const rows = await db()<Array<{ id: number; name: string; slug: string; description: string; document: string; is_default: boolean; updated_at: Date }>>`
      INSERT INTO rule_profiles (user_id, name, slug, description, document, is_default)
      VALUES (${auth.user.id}, ${name}, ${slug}, ${description}, ${document}, ${Number(counts[0].count) === 0})
      RETURNING id, name, slug, description, document, is_default, updated_at
    `;
    return privateResponse({ data: { ...rows[0], used_by: 0 } }, request);
  } catch (error) {
    if (String(error).includes("unique") || String(error).includes("duplicate")) return errorResponse(400, "INVALID_PROFILE", `You already have a profile called ${name}.`, request);
    throw error;
  }
}
