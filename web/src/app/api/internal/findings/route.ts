import { NextRequest } from "next/server";

import { authenticated, errorResponse, privateResponse } from "@/server/http/responses";
import {
  DEFAULT_FINDING_LIMIT,
  findingViews,
  findingsFor,
  type FindingView,
} from "@/server/repositories/findings";

export async function GET(request: NextRequest) {
  const auth = await authenticated(request);
  if ("response" in auth) return auth.response;

  const show = request.nextUrl.searchParams.get("show") ?? "open";
  if (!findingViews.includes(show as FindingView)) {
    return errorResponse(422, "INVALID_REQUEST", "Unknown finding view.", request);
  }
  const rawLimit = request.nextUrl.searchParams.get("limit");
  const limit = rawLimit === null ? DEFAULT_FINDING_LIMIT : Number(rawLimit);
  if (!Number.isInteger(limit) || limit < 1) {
    return errorResponse(422, "INVALID_REQUEST", "Limit must be a positive integer.", request);
  }
  return privateResponse(await findingsFor(auth.user.id, show as FindingView, limit), request);
}
