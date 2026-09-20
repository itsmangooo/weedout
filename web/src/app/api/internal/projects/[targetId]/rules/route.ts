import { NextRequest } from "next/server";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
import { ownsProject } from "@/server/projects/access";

export async function POST(request: NextRequest, { params }: { params: Promise<{ targetId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const targetId = Number((await params).targetId);
  if (!await ownsProject(auth.user.id, targetId)) return errorResponse(404, "NOT_FOUND", "That project doesn't exist.", request);
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  const kind = body.kind === "package" ? "package" : "advisory";
  const raw = typeof body.identifier === "string" ? body.identifier.trim() : "";
  const identifier = kind === "package" ? raw.toLowerCase() : raw.toUpperCase();
  const reason = typeof body.reason === "string" ? body.reason.trim() : "";
  if (!identifier || reason.length < 10) return errorResponse(400, "INVALID_REQUEST", "Name what to ignore and give a reason in a sentence.", request);
  try {
    const rows = await db()<Array<{ id: number; identifier: string; kind: string; reason: string }>>`
      INSERT INTO ignore_rules (target_id, identifier, kind, reason, created_by_email)
      VALUES (${targetId}, ${identifier}, ${kind}, ${reason}, ${auth.user.email})
      RETURNING id, identifier, kind, reason
    `;
    return privateResponse({ data: rows[0] }, request);
  } catch (error) {
    if (String(error).includes("unique") || String(error).includes("duplicate")) return errorResponse(409, "ALREADY_IGNORED", `${identifier} is already ignored on this project.`, request);
    throw error;
  }
}
