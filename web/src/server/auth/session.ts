import "server-only";

import { createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";

import { db } from "@/server/db/client";

export const SESSION_COOKIE = process.env.SESSION_COOKIE_NAME ?? "weedout_session";
export const CSRF_COOKIE = "weedout_csrf";
export const CSRF_MAX_AGE = 60 * 60 * 12;

export interface SessionUser {
  id: number;
  email: string;
  isAdmin: boolean;
}

export function hashOpaqueToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export async function sessionCookie(): Promise<string | undefined> {
  return (await cookies()).get(SESSION_COOKIE)?.value;
}

export async function resolveSession(token: string): Promise<SessionUser | null> {
  const sql = db();
  const rows = await sql<{
    session_id: number;
    last_seen_at: Date;
    id: number;
    email: string;
    is_admin: boolean;
  }[]>`
    SELECT s.id AS session_id, s.last_seen_at, u.id, u.email, u.is_admin
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ${hashOpaqueToken(token)}
      AND s.revoked_at IS NULL
      AND s.expires_at > now()
      AND u.is_active = true
      AND u.is_suspended = false
    LIMIT 1
  `;
  const row = rows[0];
  if (!row) return null;

  if (Date.now() - row.last_seen_at.getTime() > 5 * 60 * 1000) {
    await sql`
      UPDATE sessions SET last_seen_at = now()
      WHERE id = ${row.session_id}
        AND last_seen_at < now() - interval '5 minutes'
    `;
  }
  return { id: row.id, email: row.email, isAdmin: row.is_admin };
}

export function csrfToken(existing?: string): string {
  return existing || randomBytes(32).toString("base64url");
}

export function secureCookies(): boolean {
  const configured = process.env.SESSION_COOKIE_SECURE;
  if (configured !== undefined) return configured.toLowerCase() === "true";
  return process.env.NODE_ENV === "production";
}
