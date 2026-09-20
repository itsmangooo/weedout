import { api, ApiError } from "./client";

/**
 * The account page: preferences, password, sessions, two-factor and keys.
 *
 * Three of these return a secret exactly once — the TOTP secret, a set of
 * backup codes, and a new key's plaintext. The caller has to show each of them
 * immediately and must not stash it anywhere that outlives the screen, because
 * the server keeps only a hash and will never hand it over again.
 */

export const SETTINGS_PATH = "/api/internal/settings";

function unexpected(payload) {
  return new ApiError("The settings service returned an unexpected response.", {
    status: 502,
    code: "INVALID_SETTINGS_RESPONSE",
    details: payload,
  });
}

export async function getSettings({ signal } = {}) {
  const payload = await api(SETTINGS_PATH, { signal });
  if (
    typeof payload?.data?.email !== "string" ||
    !Array.isArray(payload.sessions) ||
    !Array.isArray(payload.api_keys)
  ) {
    throw unexpected(payload);
  }
  return payload;
}

export async function setEmailAlerts(enabled) {
  const payload = await api(`${SETTINGS_PATH}/alerts`, {
    method: "POST",
    body: { email_alerts: enabled },
  });
  return payload?.data;
}

/**
 * Say this account is a company, or that it is not.
 *
 * An empty name means personal. One endpoint rather than two, because "am I a
 * company" is one fact and a second way to express it is a second thing to
 * keep in step.
 */
export async function setOrganisation({ name, website = "" }) {
  const payload = await api(`${SETTINGS_PATH}/organisation`, {
    method: "POST",
    body: { name, website },
  });
  return payload?.data;
}

/**
 * Ask to be named on the landing page, or stop being named.
 *
 * Asking is not being listed: somebody checks that the name is theirs to give
 * first. Turning it off is immediate and needs nobody's approval.
 */
export async function setShowcase(listed) {
  const payload = await api(`${SETTINGS_PATH}/showcase`, {
    method: "POST",
    body: { listed },
  });
  return payload?.data;
}

export async function changePassword({ currentPassword, newPassword }) {
  const payload = await api(`${SETTINGS_PATH}/password`, {
    method: "POST",
    body: { current_password: currentPassword, new_password: newPassword },
  });
  return payload?.data;
}

export async function revokeSession(sessionId) {
  await api(`${SETTINGS_PATH}/sessions/${encodeURIComponent(sessionId)}/revoke`, {
    method: "POST",
    body: {},
  });
}

export async function revokeOtherSessions() {
  const payload = await api(`${SETTINGS_PATH}/sessions/revoke-others`, {
    method: "POST",
    body: {},
  });
  return payload?.data;
}

/** Begin setup. The secret and QR are in this response and nowhere else. */
export async function startTwoFactor() {
  const payload = await api(`${SETTINGS_PATH}/2fa/start`, { method: "POST", body: {} });
  if (typeof payload?.data?.secret !== "string") {
    throw unexpected(payload);
  }
  return payload.data;
}

/** Confirm it. The backup codes are in this response and nowhere else. */
export async function confirmTwoFactor(code) {
  const payload = await api(`${SETTINGS_PATH}/2fa/confirm`, {
    method: "POST",
    body: { code },
  });
  return payload?.data;
}

export async function regenerateBackupCodes() {
  const payload = await api(`${SETTINGS_PATH}/2fa/codes`, { method: "POST", body: {} });
  return payload?.data;
}

export async function disableTwoFactor(password) {
  const payload = await api(`${SETTINGS_PATH}/2fa/disable`, {
    method: "POST",
    body: { password },
  });
  return payload?.data;
}

export async function createAccountKey({ targetId, name, scope }) {
  const payload = await api(`${SETTINGS_PATH}/api-keys`, {
    method: "POST",
    body: { target_id: targetId, name, scope },
  });
  if (typeof payload?.data?.token !== "string") {
    throw unexpected(payload);
  }
  return payload.data;
}

export async function revokeAccountKey(keyId) {
  await api(`${SETTINGS_PATH}/api-keys/${encodeURIComponent(keyId)}/revoke`, {
    method: "POST",
    body: {},
  });
}
