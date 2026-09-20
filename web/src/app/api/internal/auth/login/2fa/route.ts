import { NextRequest } from "next/server";

import { authenticatedState } from "@/contracts/auth";
import { createSession, MFA_COOKIE, readMfaChallenge, setSessionCookie } from "@/server/auth/lifecycle";
import { backupCodeHash, normalizeBackupCode, verifyTotp } from "@/server/auth/totp";
import { db } from "@/server/db/client";
import { clientIp, safeNext } from "@/server/http/client";
import { csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";

type User = { id: number; email: string; is_admin: boolean; totp_secret: string | null; totp_confirmed_at: Date | null; totp_last_counter: string | number | null; is_active: boolean; is_suspended: boolean };

export async function POST(request: NextRequest) {
  if (!validCsrf(request)) return csrfFailure(request);
  const userId = readMfaChallenge(request.cookies.get(MFA_COOKIE)?.value);
  if (!userId) return errorResponse(401, "CHALLENGE_EXPIRED", "That took too long. Sign in again.", request);
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  const code = typeof body.code === "string" ? body.code : "";
  const rows = await db()<User[]>`SELECT id, email, is_admin, totp_secret, totp_confirmed_at, totp_last_counter, is_active, is_suspended FROM users WHERE id = ${userId} LIMIT 1`;
  const user = rows[0];
  if (!user?.totp_secret || !user.totp_confirmed_at || !user.is_active || user.is_suspended) {
    return errorResponse(401, "CHALLENGE_EXPIRED", "That took too long. Sign in again.", request);
  }
  const counter = verifyTotp(user.totp_secret, code);
  let accepted = counter !== null && (user.totp_last_counter === null || counter > Number(user.totp_last_counter));
  if (accepted) {
    await db()`UPDATE users SET totp_last_counter = ${counter} WHERE id = ${user.id}`;
  } else {
    const normalized = normalizeBackupCode(code);
    if (normalized) {
      const consumed = await db()<Array<{ id: number }>>`
        UPDATE backup_codes SET used_at = now()
        WHERE id = (SELECT id FROM backup_codes WHERE user_id = ${user.id} AND code_hash = ${backupCodeHash(normalized)} AND used_at IS NULL LIMIT 1 FOR UPDATE)
        RETURNING id
      `;
      accepted = consumed.length > 0;
    }
  }
  if (!accepted) return errorResponse(401, "INVALID_CODE", "That code was not accepted. Check your authenticator and try again.", request);
  const token = await createSession(user.id, request.headers.get("user-agent"), clientIp(request));
  const response = privateResponse({
    data: authenticatedState({ id: user.id, email: user.email, is_admin: user.is_admin }),
    next: safeNext(body.next),
  }, request);
  setSessionCookie(response, token);
  response.cookies.delete(MFA_COOKIE);
  return response;
}
