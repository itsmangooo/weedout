import { NextRequest } from "next/server";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
import { ownsProject } from "@/server/projects/access";

const severities = new Set(["low", "medium", "high", "critical"]);
export async function POST(request: NextRequest, { params }: { params: Promise<{ targetId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const targetId = Number((await params).targetId);
  if (!await ownsProject(auth.user.id, targetId)) return errorResponse(404, "NOT_FOUND", "That project doesn't exist.", request);
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  const direct = typeof body.direct === "string" && body.direct ? body.direct : null;
  const transitive = typeof body.transitive === "string" && body.transitive ? body.transitive : null;
  if ((direct && !severities.has(direct)) || (transitive && !severities.has(transitive))) return errorResponse(400, "INVALID_REQUEST", "Unknown severity.", request);
  const epss = body.epss === null || body.epss === "" || body.epss === undefined ? null : Number(body.epss);
  if (epss !== null && (!Number.isFinite(epss) || epss < 0 || epss > 100)) return errorResponse(400, "INVALID_REQUEST", "Exploit likelihood is a percentage between 0 and 100.", request);
  await db()`UPDATE tracked_targets SET direct_threshold = ${direct}, transitive_threshold = ${transitive}, epss_threshold = ${epss}, updated_at = now() WHERE id = ${targetId}`;
  return privateResponse({ data: { direct, transitive, epss } }, request);
}
