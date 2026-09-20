import { NextRequest } from "next/server";

import { anonymousAuthState } from "@/contracts/auth";
import { revokeSession } from "@/server/auth/lifecycle";
import { SESSION_COOKIE } from "@/server/auth/session";
import { csrfFailure, privateResponse, validCsrf } from "@/server/http/responses";

export async function POST(request: NextRequest) {
  if (!validCsrf(request)) return csrfFailure(request);
  await revokeSession(request.cookies.get(SESSION_COOKIE)?.value);
  const response = privateResponse({ data: anonymousAuthState() }, request);
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
