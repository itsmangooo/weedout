import { NextRequest } from "next/server";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
import { scanProject } from "@/server/projects/scan";

export async function POST(request: NextRequest, { params }: { params: Promise<{ targetId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const targetId = Number((await params).targetId);
  try {
    const result = await scanProject(targetId, auth.user.id);
    if (!result) return errorResponse(404, "NOT_FOUND", "That project doesn't exist.", request);
    return privateResponse({ data: result }, request);
  } catch (error) {
    if (String(error).includes("NO_MANIFEST")) return errorResponse(400, "NO_MANIFEST", "There is nothing to scan yet. Attach a manifest first.", request);
    return errorResponse(503, "SCAN_FAILED", "The scan could not run just now. Try again shortly.", request);
  }
}
