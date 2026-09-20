import { api, ApiError } from "./client";

export const CURRENT_USER_PATH = "/api/internal/auth/me";

function isCurrentUser(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    Number.isInteger(value.id) &&
    typeof value.email === "string" &&
    typeof value.is_admin === "boolean" &&
    typeof value.tier === "string" &&
    value.account_state === "active"
  );
}

function isCurrentAuthState(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  if (value.authenticated === false) {
    return value.session_state === "anonymous" && value.user === null;
  }

  return (
    value.authenticated === true &&
    value.session_state === "authenticated" &&
    isCurrentUser(value.user)
  );
}

export async function getCurrentUser({ signal } = {}) {
  const payload = await api(CURRENT_USER_PATH, { signal });
  if (!isCurrentAuthState(payload?.data)) {
    throw new ApiError("The authentication service returned an unexpected response.", {
      status: 502,
      code: "INVALID_AUTH_RESPONSE",
      details: payload,
    });
  }

  return payload.data;
}
