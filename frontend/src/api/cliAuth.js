import { api, ApiError } from "./client";

/**
 * Approving a machine that ran `weedout auth`.
 *
 * The browser half of the flow, and the half that carries the authorisation:
 * the terminal proves it started the request, this proves who is granting it.
 * Everything here goes through the session-authenticated, CSRF-protected
 * internal API for that reason.
 */

export const CLI_AUTH_PATH = "/api/internal/cli-auth";
export const CLI_TOKENS_PATH = "/api/internal/cli-tokens";

export async function getCliAuthRequest(code, { signal } = {}) {
  const payload = await api(`${CLI_AUTH_PATH}/${encodeURIComponent(code)}`, { signal });
  if (typeof payload?.data?.code !== "string") {
    throw new ApiError("That code could not be read.", {
      status: 502,
      code: "INVALID_CLI_AUTH_RESPONSE",
      details: payload,
    });
  }
  return payload;
}

export async function approveCliAuth(code) {
  const payload = await api(`${CLI_AUTH_PATH}/approve`, {
    method: "POST",
    body: { code },
  });
  return payload?.data;
}

export async function denyCliAuth(code) {
  const payload = await api(`${CLI_AUTH_PATH}/deny`, {
    method: "POST",
    body: { code },
  });
  return payload?.data;
}

/** Which machines hold a credential for this account. */
export async function getSignedInMachines({ signal } = {}) {
  const payload = await api(CLI_TOKENS_PATH, { signal });
  if (!Array.isArray(payload?.data)) {
    throw new ApiError("The machine list could not be read.", {
      status: 502,
      code: "INVALID_CLI_TOKENS_RESPONSE",
      details: payload,
    });
  }
  return payload;
}

export async function revokeMachine(id) {
  await api(`${CLI_TOKENS_PATH}/${encodeURIComponent(id)}/revoke`, {
    method: "POST",
    body: {},
  });
}
