import "server-only";

import { hashOpaqueToken, type SessionUser } from "@/server/auth/session";
import { db } from "@/server/db/client";
import { number } from "@/server/http/responses";

type CountRow = { unused: string | number; total: string | number };
type ProjectRow = { id: number; name: string };
type KeyRow = {
  id: number; prefix: string; name: string; scope: string; target_id: number | null;
  target_name: string | null; created_at: Date; last_used_at: Date | null;
  call_count: number; revoked_at: Date | null;
};
type SessionRow = {
  id: number; token_hash: string; user_agent: string | null; ip_address: string | null;
  created_at: Date; last_seen_at: Date;
};

export async function settingsFor(user: SessionUser, currentToken: string) {
  const sql = db();
  const [codeRows, projects, keys, sessions] = await Promise.all([
    sql<CountRow[]>`
      SELECT count(*) FILTER (WHERE used_at IS NULL) AS unused, count(*) AS total
      FROM backup_codes WHERE user_id = ${user.id}
    `,
    sql<ProjectRow[]>`SELECT id, name FROM tracked_targets WHERE user_id = ${user.id} ORDER BY created_at DESC`,
    sql<KeyRow[]>`
      SELECT k.id, k.prefix, k.name, k.scope, k.target_id, t.name AS target_name,
             k.created_at, k.last_used_at, k.call_count, k.revoked_at
      FROM api_keys k LEFT JOIN tracked_targets t ON t.id = k.target_id
      WHERE k.user_id = ${user.id} ORDER BY k.created_at DESC
    `,
    sql<SessionRow[]>`
      SELECT id, token_hash, user_agent, ip_address, created_at, last_seen_at
      FROM sessions
      WHERE user_id = ${user.id} AND revoked_at IS NULL AND expires_at > now()
      ORDER BY last_seen_at DESC
    `,
  ]);
  const codes = codeRows[0] ?? { unused: 0, total: 0 };
  const currentHash = hashOpaqueToken(currentToken);
  return {
    data: {
      email: user.email,
      tier: "free",
      is_admin: user.isAdmin,
      email_alerts: user.emailAlertsEnabled,
      two_factor_enabled: user.twoFactorEnabled,
      backup_codes_unused: number(codes.unused),
      backup_codes_total: number(codes.total),
      account_kind: user.accountKind,
      organisation_name: user.organisationName,
      organisation_website: user.organisationWebsite,
      showcase_opt_in: user.showcaseOptIn,
      showcase_listed: user.showcaseListed,
    },
    projects,
    api_keys: keys.map((key) => ({
      id: key.id, prefix: key.prefix, name: key.name, scope: key.scope,
      project: key.target_id === null ? null : { id: key.target_id, name: key.target_name },
      created_at: key.created_at, last_used_at: key.last_used_at, call_count: key.call_count,
      is_active: key.revoked_at === null, revoked_at: key.revoked_at,
    })),
    sessions: sessions.map(({ token_hash, ...session }) => ({
      ...session,
      is_current: token_hash === currentHash,
    })),
  };
}
