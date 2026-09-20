import "server-only";

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { db } from "@/server/db/client";
import { hashOpaqueToken, SESSION_COOKIE, secureCookies } from "./session";
import type { NextResponse } from "next/server";

export const SESSION_TTL_HOURS = Number(process.env.SESSION_TTL_HOURS ?? 24 * 14);
export const MFA_COOKIE = "weedout_mfa";

export async function createSession(
  userId: number,
  userAgent?: string | null,
  ipAddress?: string | null,
) {
  const token = randomBytes(32).toString("base64url");
  await db()`
    INSERT INTO sessions (user_id, token_hash, expires_at, user_agent, ip_address)
    VALUES (${userId}, ${hashOpaqueToken(token)}, now() + (${SESSION_TTL_HOURS} * interval '1 hour'),
            ${(userAgent ?? "").slice(0, 512) || null}, ${(ipAddress ?? "").slice(0, 64) || null})
  `;
  return token;
}

export function setSessionCookie(response: NextResponse, token: string) {
  response.cookies.set(SESSION_COOKIE, token, {
    httpOnly: true,
    maxAge: SESSION_TTL_HOURS * 3600,
    path: "/",
    sameSite: (process.env.SESSION_COOKIE_SAMESITE as "lax" | "strict" | "none" | undefined) ?? "lax",
    secure: secureCookies(),
  });
}

export async function revokeSession(token?: string) {
  if (!token) return;
  await db()`UPDATE sessions SET revoked_at = now() WHERE token_hash = ${hashOpaqueToken(token)} AND revoked_at IS NULL`;
}

function secret() {
  const value = process.env.SECRET_KEY;
  if (!value) throw new Error("SECRET_KEY is required for authentication");
  return value;
}

export function signMfaChallenge(userId: number) {
  const expires = Math.floor(Date.now() / 1000) + 300;
  const payload = `${userId}.${expires}`;
  const signature = createHmac("sha256", secret()).update(payload).digest("hex");
  return `${payload}.${signature}`;
}

export function readMfaChallenge(raw?: string): number | null {
  if (!raw) return null;
  const parts = raw.split(".");
  if (parts.length !== 3) return null;
  const userId = Number(parts[0]);
  const expires = Number(parts[1]);
  if (!Number.isInteger(userId) || !Number.isInteger(expires) || expires < Date.now() / 1000) return null;
  const expected = signMfaChallengeAt(userId, expires);
  const left = Buffer.from(expected);
  const right = Buffer.from(raw);
  return left.length === right.length && timingSafeEqual(left, right) ? userId : null;
}

function signMfaChallengeAt(userId: number, expires: number) {
  const payload = `${userId}.${expires}`;
  return `${payload}.${createHmac("sha256", secret()).update(payload).digest("hex")}`;
}
