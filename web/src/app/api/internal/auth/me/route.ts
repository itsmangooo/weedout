import { NextRequest, NextResponse } from "next/server";

import { anonymousAuthState, authenticatedState } from "@/contracts/auth";
import {
  csrfToken,
  CSRF_COOKIE,
  CSRF_MAX_AGE,
  resolveSession,
  secureCookies,
  SESSION_COOKIE,
} from "@/server/auth/session";

function prepare(response: NextResponse, request: NextRequest) {
  response.headers.set("Cache-Control", "private, no-store");
  response.headers.set("Vary", "Cookie");
  response.cookies.set(CSRF_COOKIE, csrfToken(request.cookies.get(CSRF_COOKIE)?.value), {
    httpOnly: false,
    maxAge: CSRF_MAX_AGE,
    path: "/",
    sameSite: "lax",
    secure: secureCookies(),
  });
  return response;
}

export async function GET(request: NextRequest) {
  const token = request.cookies.get(SESSION_COOKIE)?.value;
  if (!token) {
    return prepare(NextResponse.json({ data: anonymousAuthState() }), request);
  }

  const user = await resolveSession(token);
  if (!user) {
    const response = NextResponse.json(
      { error: { code: "SESSION_EXPIRED", message: "Your session has expired. Sign in again." } },
      { status: 401 },
    );
    response.cookies.set(SESSION_COOKIE, "", {
      httpOnly: true,
      maxAge: 0,
      path: "/",
      sameSite: (process.env.SESSION_COOKIE_SAMESITE as "lax" | "strict" | "none" | undefined) ?? "lax",
      secure: secureCookies(),
    });
    return prepare(response, request);
  }

  return prepare(NextResponse.json({
    data: authenticatedState({ id: user.id, email: user.email, is_admin: user.isAdmin }),
  }), request);
}
