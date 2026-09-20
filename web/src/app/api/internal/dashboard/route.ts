import { NextRequest } from "next/server";

import { authenticated, privateResponse } from "@/server/http/responses";
import { dashboardFor } from "@/server/repositories/dashboard";

export async function GET(request: NextRequest) {
  const auth = await authenticated(request);
  if ("response" in auth) return auth.response;
  return privateResponse(await dashboardFor(auth.user.id), request);
}
