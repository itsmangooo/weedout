import "server-only";

import QRCode from "qrcode";

import { newApiKey } from "@/server/auth/api-key";
import { createSession } from "@/server/auth/lifecycle";
import { hashPassword, passwordProblem, verifyPassword } from "@/server/auth/password";
import { hashOpaqueToken, type SessionUser } from "@/server/auth/session";
import {
  backupCodeHash,
  generateBackupCodes,
  generateTotpSecret,
  provisioningUri,
  verifyTotp,
} from "@/server/auth/totp";
import { db } from "@/server/db/client";

export class AccountActionError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}

export async function setOrganisation(user: SessionUser, nameValue: unknown, websiteValue: unknown) {
  const name = typeof nameValue === "string" ? nameValue.trim() : "";
  const website = typeof websiteValue === "string" ? websiteValue.trim() : "";
  if (name.length > 200) throw new AccountActionError(400, "INVALID_REQUEST", "That name is too long.");
  if (website.length > 300) throw new AccountActionError(400, "INVALID_REQUEST", "That website is too long.");
  if (website && !/^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(website)) {
    throw new AccountActionError(400, "INVALID_REQUEST", "That does not look like a website. Include https://.");
  }
  const rows = name
    ? await db()<Array<{ account_kind: string; organisation_name: string | null; showcase_listed: boolean }>>`
        UPDATE users SET account_kind = 'organization', organisation_name = ${name},
          organisation_website = ${website || null}, showcase_approved_at = NULL, updated_at = now()
        WHERE id = ${user.id}
        RETURNING account_kind, organisation_name,
          (showcase_opt_in AND showcase_approved_at IS NOT NULL) AS showcase_listed`
    : await db()<Array<{ account_kind: string; organisation_name: string | null; showcase_listed: boolean }>>`
        UPDATE users SET account_kind = 'personal', organisation_name = NULL,
          organisation_website = NULL, showcase_opt_in = false, showcase_approved_at = NULL,
          updated_at = now() WHERE id = ${user.id}
        RETURNING account_kind, organisation_name, false AS showcase_listed`;
  return rows[0];
}

export async function setShowcase(user: SessionUser, listed: unknown) {
  if (typeof listed !== "boolean") throw new AccountActionError(400, "INVALID_REQUEST", "Choose whether the company may be listed.");
  const current = await db()<Array<{ account_kind: string; organisation_name: string | null }>>`
    SELECT account_kind, organisation_name FROM users WHERE id = ${user.id}`;
  if (listed && (current[0]?.account_kind !== "organization" || !current[0]?.organisation_name)) {
    throw new AccountActionError(400, "INVALID_REQUEST", "Only an organisation account can be listed. Add your company name first.");
  }
  const rows = await db()<Array<{ showcase_opt_in: boolean; showcase_listed: boolean }>>`
    UPDATE users SET showcase_opt_in = ${listed}, updated_at = now() WHERE id = ${user.id}
    RETURNING showcase_opt_in, (showcase_opt_in AND showcase_approved_at IS NOT NULL) AS showcase_listed`;
  return rows[0];
}

export async function setEmailAlerts(userId: number, enabled: unknown) {
  if (typeof enabled !== "boolean") throw new AccountActionError(400, "INVALID_REQUEST", "Choose whether email alerts are enabled.");
  const rows = await db()<Array<{ email_alerts: boolean }>>`
    UPDATE users SET email_alerts_enabled = ${enabled}, updated_at = now() WHERE id = ${userId}
    RETURNING email_alerts_enabled AS email_alerts`;
  return rows[0];
}

export async function changePassword(
  userId: number,
  currentPassword: unknown,
  newPassword: unknown,
  userAgent: string | null,
  ipAddress: string | null,
) {
  if (typeof currentPassword !== "string" || !currentPassword || typeof newPassword !== "string") {
    throw new AccountActionError(400, "INVALID_REQUEST", "Enter your current password and a new password.");
  }
  const rows = await db()<Array<{ password_hash: string | null }>>`SELECT password_hash FROM users WHERE id = ${userId}`;
  if (!await verifyPassword(rows[0]?.password_hash ?? null, currentPassword)) {
    throw new AccountActionError(400, "REJECTED", "Your current password is incorrect.");
  }
  const problem = passwordProblem(newPassword);
  if (problem) throw new AccountActionError(400, "REJECTED", problem);
  const passwordHash = await hashPassword(newPassword);
  await db().begin(async (sql) => {
    await sql.unsafe("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2", [passwordHash, userId]);
    await sql.unsafe("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", [userId]);
  });
  return createSession(userId, userAgent, ipAddress);
}

export async function revokeSessionById(userId: number, sessionId: number) {
  const rows = await db()<Array<{ id: number }>>`
    UPDATE sessions SET revoked_at = coalesce(revoked_at, now())
    WHERE id = ${sessionId} AND user_id = ${userId} RETURNING id`;
  if (!rows.length) throw new AccountActionError(404, "NOT_FOUND", "That session doesn't exist.");
}

export async function revokeOtherSessions(userId: number, token: string) {
  const rows = await db()<Array<{ id: number }>>`
    UPDATE sessions SET revoked_at = now() WHERE user_id = ${userId} AND revoked_at IS NULL
      AND token_hash <> ${hashOpaqueToken(token)} RETURNING id`;
  return rows.length;
}

export async function startTwoFactor(user: SessionUser) {
  if (user.twoFactorEnabled) throw new AccountActionError(400, "REJECTED", "Two-factor authentication is already on for this account.");
  const secret = generateTotpSecret();
  await db()`UPDATE users SET totp_secret = ${secret}, totp_confirmed_at = NULL, totp_last_counter = NULL WHERE id = ${user.id}`;
  const uri = provisioningUri(secret, user.email);
  const qrSvg = await QRCode.toString(uri, { type: "svg", errorCorrectionLevel: "M", margin: 2, color: { dark: "#000000", light: "#00000000" } });
  return { secret, uri, qr_svg: qrSvg.replace(/^<\?xml[^>]*>\s*/i, "") };
}

async function replaceBackupCodes(userId: number) {
  const codes = generateBackupCodes();
  await db().begin(async (sql) => {
    await sql.unsafe("DELETE FROM backup_codes WHERE user_id = $1", [userId]);
    for (const code of codes) {
      await sql.unsafe("INSERT INTO backup_codes (user_id, code_hash) VALUES ($1, $2)", [userId, backupCodeHash(code)]);
    }
  });
  return codes;
}

export async function confirmTwoFactor(user: SessionUser, submitted: unknown) {
  if (user.twoFactorEnabled) throw new AccountActionError(400, "INVALID_CODE", "Two-factor authentication is already on for this account.");
  const rows = await db()<Array<{ totp_secret: string | null }>>`SELECT totp_secret FROM users WHERE id = ${user.id}`;
  const secret = rows[0]?.totp_secret;
  if (!secret) throw new AccountActionError(400, "INVALID_CODE", "Start the setup again — there's no pending secret to confirm.");
  const counter = verifyTotp(secret, typeof submitted === "string" ? submitted : "");
  if (counter === null) throw new AccountActionError(400, "INVALID_CODE", "That code isn't right. Check the app and try the current code.");
  await db()`UPDATE users SET totp_confirmed_at = now(), totp_last_counter = ${counter} WHERE id = ${user.id}`;
  return replaceBackupCodes(user.id);
}

export async function regenerateCodes(user: SessionUser) {
  if (!user.twoFactorEnabled) throw new AccountActionError(400, "NOT_ENABLED", "Two-factor is not switched on for this account.");
  return replaceBackupCodes(user.id);
}

export async function disableTwoFactor(userId: number, password: unknown) {
  const rows = await db()<Array<{ password_hash: string | null }>>`SELECT password_hash FROM users WHERE id = ${userId}`;
  if (typeof password !== "string" || !await verifyPassword(rows[0]?.password_hash ?? null, password)) {
    throw new AccountActionError(400, "REJECTED", "That password isn't right. Two-factor is still on.");
  }
  await db().begin(async (sql) => {
    await sql.unsafe("UPDATE users SET totp_secret = NULL, totp_confirmed_at = NULL, totp_last_counter = NULL WHERE id = $1", [userId]);
    await sql.unsafe("DELETE FROM backup_codes WHERE user_id = $1", [userId]);
  });
}

export async function createAccountKey(userId: number, targetIdValue: unknown, nameValue: unknown, scopeValue: unknown) {
  const targetId = Number(targetIdValue);
  if (!Number.isInteger(targetId) || targetId < 1) throw new AccountActionError(400, "INVALID_REQUEST", "Choose a project for this key.");
  const targets = await db()<Array<{ id: number }>>`SELECT id FROM tracked_targets WHERE id = ${targetId} AND user_id = ${userId}`;
  if (!targets.length) throw new AccountActionError(404, "NOT_FOUND", "That project could not be found.");
  const scope = typeof scopeValue === "string" && ["scan", "read", "manage"].includes(scopeValue) ? scopeValue : "scan";
  const name = typeof nameValue === "string" ? nameValue.trim() : "";
  if (name.length > 120) throw new AccountActionError(400, "INVALID_REQUEST", "That key name is too long.");
  const active = await db()<Array<{ count: string | number }>>`SELECT count(*) AS count FROM api_keys WHERE target_id = ${targetId} AND revoked_at IS NULL`;
  if (Number(active[0]?.count ?? 0) >= 5) throw new AccountActionError(400, "KEY_REFUSED", "This project already has 5 active keys. Revoke one before creating another.");
  const issued = newApiKey();
  const rows = await db()<Array<{ id: number; prefix: string; scope: string }>>`
    INSERT INTO api_keys (user_id, target_id, token_hash, prefix, name, scope)
    VALUES (${userId}, ${targetId}, ${issued.hash}, ${issued.prefix}, ${name}, ${scope})
    RETURNING id, prefix, scope`;
  return { ...rows[0], token: issued.token };
}

export async function revokeAccountKey(userId: number, keyId: number) {
  const rows = await db()<Array<{ id: number }>>`
    UPDATE api_keys SET revoked_at = coalesce(revoked_at, now()) WHERE id = ${keyId} AND user_id = ${userId} RETURNING id`;
  if (!rows.length) throw new AccountActionError(404, "NOT_FOUND", "That key doesn't exist.");
}
