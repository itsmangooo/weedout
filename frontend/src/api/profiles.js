import { api, ApiError } from "./client";

/**
 * Rule profiles: an account's scan rules, reusable across projects.
 *
 * A profile is a `.weedout.yml` document stored under a name. One syntax, one
 * parser — a working file can be lifted into a profile by copying it, and the
 * documentation for one is the documentation for both.
 */

export const PROFILES_PATH = "/api/internal/profiles";

function unexpected(payload) {
  return new ApiError("The profiles service returned an unexpected response.", {
    status: 502,
    code: "INVALID_PROFILES_RESPONSE",
    details: payload,
  });
}

function isProfile(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    Number.isInteger(value.id) &&
    typeof value.name === "string" &&
    typeof value.slug === "string" &&
    typeof value.description === "string" &&
    typeof value.document === "string" &&
    typeof value.is_default === "boolean" &&
    Number.isInteger(value.used_by)
  );
}

export async function getProfiles({ signal } = {}) {
  const payload = await api(PROFILES_PATH, { signal });
  if (!Array.isArray(payload?.data) || !payload.data.every(isProfile)) {
    throw unexpected(payload);
  }
  return payload;
}

export async function createProfile({ name, description = "", document = "" }) {
  const payload = await api(PROFILES_PATH, {
    method: "POST",
    body: { name, description, document },
  });
  return payload?.data;
}

export async function saveProfile(id, { name, description = "", document = "" }) {
  const payload = await api(`${PROFILES_PATH}/${encodeURIComponent(id)}`, {
    method: "POST",
    body: { name, description, document },
  });
  return payload?.data;
}

/** Apply this profile to every project that has not chosen its own. */
export async function makeProfileDefault(id) {
  const payload = await api(`${PROFILES_PATH}/${encodeURIComponent(id)}/default`, {
    method: "POST",
    body: {},
  });
  return payload?.data;
}

export async function deleteProfile(id) {
  await api(`${PROFILES_PATH}/${encodeURIComponent(id)}/delete`, {
    method: "POST",
    body: {},
  });
}
