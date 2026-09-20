import { NextRequest } from "next/server";

import { authenticatedState } from "@/contracts/auth";
import { createSession, MFA_COOKIE, setSessionCookie, signMfaChallenge } from "@/server/auth/lifecycle";
import { verifyPassword } from "@/server/auth/password";
import { db } from "@/server/db/client";
import { clientIp, safeNext } from "@/server/http/client";
import { csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";

type User = { id: number; email: string; password_hash: string | null; is_admin: boolean; is_active: boolean; is_suspended: boolean; totp_confirmed_at: Date | null };

export async function POST(request: NextRequest) {
  if (!validCsrf(request)) return csrfFailure(request);
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const next = safeNext(body.next);
  if (!email || !password) return errorResponse(400, "INVALID_REQUEST", "Enter your email and password.", request);

  const rows = await db()<User[]>`
    SELECT id, email, password_hash, is_admin, is_active, is_suspended, totp_confirmed_at
    FROM users WHERE email = ${email} LIMIT 1
  `;
  const user = rows[0];
  const accepted = user ? await verifyPassword(user.password_hash, password) : false;
  if (!accepted || !user?.is_active || user.is_suspended) {
    return errorResponse(401, "INVALID_CREDENTIALS", "Incorrect email or password.", request);
  }
  if (process.env.ADMIN_EMAIL?.trim().toLowerCase() === user.email && !user.is_admin) {
    await db()`UPDATE users SET is_admin = true WHERE id = ${user.id}`;
    user.is_admin = true;
  }
  await db()`UPDATE users SET last_login_at = now() WHERE id = ${user.id}`;
  if (user.totp_confirmed_at) {
    const response = privateResponse({ data: { authenticated: false, two_factor_required: true, next } }, request);
    response.cookies.set(MFA_COOKIE, signMfaChallenge(user.id), {
      httpOnly: true, maxAge: 300, path: "/", sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    });
    return response;
  }
  const token = await createSession(user.id, request.headers.get("user-agent"), clientIp(request));
  const response = privateResponse({
    data: authenticatedState({ id: user.id, email: user.email, is_admin: user.is_admin }), next,
  }, request);
  setSessionCookie(response, token);
  return response;
}
