import { api, ApiError } from "./client";

/**
 * Signing in, signing up, signing out and recovery.
 *
 * Separate from `auth.js`, which only reads who you are. These change state,
 * so every one of them is a POST and every one carries the CSRF header the
 * client attaches from the double-submit cookie.
 *
 * Each response is validated before it is trusted, the same way the read
 * endpoints are. A malformed reply becoming a signed-in state would be a much
 * worse bug than a visible error, so an unexpected shape is an error.
 */

export const LOGIN_PATH = "/api/internal/auth/login";
export const SECOND_FACTOR_PATH = "/api/internal/auth/login/2fa";
export const LOGOUT_PATH = "/api/internal/auth/logout";
export const SIGNUP_PATH = "/api/internal/auth/signup";
export const FORGOT_PASSWORD_PATH = "/api/internal/auth/forgot-password";
export const RESET_PASSWORD_PATH = "/api/internal/auth/reset-password";

/** Where to go after signing in, when the server did not say. */
export const DEFAULT_LANDING = "/dashboard";

function isUser(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    Number.isInteger(value.id) &&
    typeof value.email === "string" &&
    typeof value.is_admin === "boolean" &&
    typeof value.tier === "string"
  );
}

function unexpected(payload) {
  return new ApiError("The sign-in service returned an unexpected response.", {
    status: 502,
    code: "INVALID_AUTH_RESPONSE",
    details: payload,
  });
}

/**
 * Only ever a same-origin path.
 *
 * `next` reaches the client from a query string, so it is attacker-controlled.
 * Without this, a link to `/login?next=https://evil.example` would turn our own
 * sign-in form into an open redirect that lands people on someone else's page
 * wearing our address in the referrer.
 */
export function safeNext(value) {
  if (typeof value !== "string" || !value.startsWith("/")) {
    return DEFAULT_LANDING;
  }
  // A protocol-relative URL also starts with a slash and is not same-origin.
  if (value.startsWith("//")) {
    return DEFAULT_LANDING;
  }
  return value;
}

/**
 * Exchange credentials for a session.
 *
 * Returns either `{ status: "authenticated", user, next }` or
 * `{ status: "two_factor_required", next }`. The second is not an error: the
 * password was right and there is another step, and treating it as a failure
 * would show "sign-in failed" to somebody who did nothing wrong.
 */
export async function signIn({ email, password, next }) {
  const payload = await api(LOGIN_PATH, {
    method: "POST",
    body: { email, password, next: safeNext(next) },
  });

  const data = payload?.data;
  if (data?.two_factor_required === true) {
    return { status: "two_factor_required", next: safeNext(data.next ?? next) };
  }

  if (data?.authenticated === true && isUser(data.user)) {
    return {
      status: "authenticated",
      user: data.user,
      next: safeNext(payload.next ?? next),
    };
  }

  throw unexpected(payload);
}

/** Complete a sign-in that is waiting on a code. */
export async function submitSecondFactor({ code, next }) {
  const payload = await api(SECOND_FACTOR_PATH, {
    method: "POST",
    body: { code, next: safeNext(next) },
  });

  const data = payload?.data;
  if (data?.authenticated === true && isUser(data.user)) {
    return { user: data.user, next: safeNext(payload.next ?? next) };
  }

  throw unexpected(payload);
}

/** Create an account and sign in. */
export async function signUp({ email, password, website = "" }) {
  const payload = await api(SIGNUP_PATH, {
    method: "POST",
    body: { email, password, website },
  });

  const data = payload?.data;
  if (data?.authenticated === true && isUser(data.user)) {
    return { user: data.user, next: safeNext(payload.next) };
  }

  // A filled honeypot gets an anonymous 200, which is deliberate on the
  // server. A real person cannot reach it, so there is nothing to explain.
  if (data?.authenticated === false) {
    return { user: null, next: DEFAULT_LANDING };
  }

  throw unexpected(payload);
}

/**
 * End the session.
 *
 * Never throws for an already-signed-out caller: the server answers 200 for
 * that case on purpose, so a client whose cookie already expired can still
 * reach a clean signed-out state instead of an error it has to special-case.
 */
export async function signOut() {
  await api(LOGOUT_PATH, { method: "POST", body: {} });
}

/**
 * Ask for a reset link.
 *
 * Resolves the same way whether or not the address is registered, because the
 * server answers the same way. The UI must not add a distinction the API
 * deliberately refuses to make.
 */
export async function requestPasswordReset({ email }) {
  const payload = await api(FORGOT_PASSWORD_PATH, {
    method: "POST",
    body: { email },
  });

  return {
    message:
      payload?.data?.message ??
      "If that address has an account, a reset link is on its way.",
  };
}

/** Set a new password using an emailed token. */
export async function resetPassword({ token, password, passwordConfirm }) {
  const payload = await api(RESET_PASSWORD_PATH, {
    method: "POST",
    body: { token, password, password_confirm: passwordConfirm },
  });

  return {
    message: payload?.data?.message ?? "Password changed. Sign in with it.",
  };
}
