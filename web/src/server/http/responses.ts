import "server-only";

import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "node:crypto";

import {
  csrfToken,
  CSRF_COOKIE,
  CSRF_MAX_AGE,
  resolveSession,
  secureCookies,
  SESSION_COOKIE,
  type SessionUser,
} from "@/server/auth/session";

export function privateResponse(body: unknown, request?: NextRequest, init?: ResponseInit) {
  const response = NextResponse.json(body, init);
  response.headers.set("Cache-Control", "private, no-store");
  response.headers.set("Vary", "Cookie");
  if (request) {
    response.cookies.set(CSRF_COOKIE, csrfToken(request.cookies.get(CSRF_COOKIE)?.value), {
      httpOnly: false,
      maxAge: CSRF_MAX_AGE,
      path: "/",
      sameSite: "lax",
      secure: secureCookies(),
    });
  }
  return response;
}

export function publicResponse(body: unknown, maxAge: number, init?: ResponseInit) {
  const response = NextResponse.json(body, init);
  response.headers.set("Cache-Control", `public, max-age=${maxAge}`);
  return response;
}

export function errorResponse(
  status: number,
  code: string,
  message: string,
  request?: NextRequest,
) {
  return privateResponse({ error: { code, message } }, request, { status });
}

export async function authenticated(
  request: NextRequest,
): Promise<{ user: SessionUser; token: string } | { response: NextResponse }> {
  const token = request.cookies.get(SESSION_COOKIE)?.value;
  if (!token) {
    return { response: errorResponse(401, "AUTH_REQUIRED", "Sign in to continue.", request) };
  }
  const user = await resolveSession(token);
  if (!user) {
    const response = errorResponse(
      401,
      "SESSION_EXPIRED",
      "Your session has expired. Sign in again.",
      request,
    );
    response.cookies.set(SESSION_COOKIE, "", {
      httpOnly: true,
      maxAge: 0,
      path: "/",
      sameSite: (process.env.SESSION_COOKIE_SAMESITE as "lax" | "strict" | "none" | undefined) ?? "lax",
      secure: secureCookies(),
    });
    return { response };
  }
  return { user, token };
}

export function number(value: string | number | bigint | null | undefined): number {
  return value == null ? 0 : Number(value);
}

export function validCsrf(request: NextRequest): boolean {
  const cookie = request.cookies.get(CSRF_COOKIE)?.value;
  const header = request.headers.get("x-csrf-token");
  if (!cookie || !header) return false;
  const left = Buffer.from(cookie);
  const right = Buffer.from(header);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function csrfFailure(request: NextRequest) {
  return errorResponse(403, "CSRF_FAILED", "Invalid CSRF token. Please reload the page.", request);
}
