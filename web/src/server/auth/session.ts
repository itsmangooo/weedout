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
  tier: string;
  emailAlertsEnabled: boolean;
  twoFactorEnabled: boolean;
  accountKind: string;
  organisationName: string | null;
  organisationWebsite: string | null;
  showcaseOptIn: boolean;
  showcaseListed: boolean;
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
    tier: string;
    email_alerts_enabled: boolean;
    totp_confirmed_at: Date | null;
    account_kind: string;
    organisation_name: string | null;
    organisation_website: string | null;
    showcase_opt_in: boolean;
    showcase_approved_at: Date | null;
  }[]>`
    SELECT s.id AS session_id, s.last_seen_at, u.id, u.email, u.is_admin,
           u.tier, u.email_alerts_enabled, u.totp_confirmed_at, u.account_kind,
           u.organisation_name, u.organisation_website, u.showcase_opt_in,
           u.showcase_approved_at
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
  return {
    id: row.id,
    email: row.email,
    isAdmin: row.is_admin,
    tier: row.tier,
    emailAlertsEnabled: row.email_alerts_enabled,
    twoFactorEnabled: row.totp_confirmed_at !== null,
    accountKind: row.account_kind,
    organisationName: row.organisation_name,
    organisationWebsite: row.organisation_website,
    showcaseOptIn: row.showcase_opt_in,
    showcaseListed: row.showcase_opt_in && row.showcase_approved_at !== null,
  };
}

export function csrfToken(existing?: string): string {
  return existing || randomBytes(32).toString("base64url");
}

export function secureCookies(): boolean {
  const configured = process.env.SESSION_COOKIE_SECURE;
  if (configured !== undefined) return configured.toLowerCase() === "true";
  return process.env.NODE_ENV === "production";
}
