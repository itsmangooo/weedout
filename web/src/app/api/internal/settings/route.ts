import { NextRequest } from "next/server";

import { authenticated, privateResponse } from "@/server/http/responses";
import { settingsFor } from "@/server/repositories/settings";

export async function GET(request: NextRequest) {
  const auth = await authenticated(request);
  if ("response" in auth) return auth.response;
  return privateResponse(await settingsFor(auth.user, auth.token), request);
}
