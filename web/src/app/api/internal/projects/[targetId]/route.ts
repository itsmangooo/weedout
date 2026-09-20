import { NextRequest } from "next/server";

import { authenticated, errorResponse, privateResponse } from "@/server/http/responses";
import { projectFor } from "@/server/repositories/project";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ targetId: string }> },
) {
  const auth = await authenticated(request);
  if ("response" in auth) return auth.response;
  const { targetId: raw } = await context.params;
  const targetId = Number(raw);
  if (!Number.isInteger(targetId) || targetId < 1) {
    return errorResponse(404, "NOT_FOUND", "That project doesn't exist.", request);
  }
  const result = await projectFor(auth.user.id, targetId, request.nextUrl.searchParams.get("show") ?? "open");
  if (!result) return errorResponse(404, "NOT_FOUND", "That project doesn't exist.", request);
  return privateResponse(result, request);
}
