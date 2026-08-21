const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);
const CSRF_COOKIE_NAME = "weedout_csrf";

export class ApiError extends Error {
  constructor(message, { status, code, details } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  return Array.isArray(value) || Object.getPrototypeOf(value) === Object.prototype;
}

function readCookie(name) {
  if (typeof document === "undefined") {
    return null;
  }

  const prefix = `${encodeURIComponent(name)}=`;
  const entry = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix));

  return entry ? decodeURIComponent(entry.slice(prefix.length)) : null;
}

async function responseBody(response) {
  if (response.status === 204) {
    return null;
  }

  const text = await response.text();
  if (!text) {
    return null;
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("json")) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  return text;
}

function errorDetails(payload, status) {
  if (payload && typeof payload === "object") {
    if (payload.error && typeof payload.error === "object") {
      return {
        code: payload.error.code,
        message: payload.error.message || `Request failed with status ${status}`,
      };
    }

    if (typeof payload.error === "string" && typeof payload.message === "string") {
      return { code: payload.error, message: payload.message };
    }

    if (typeof payload.error === "string") {
      return { message: payload.error };
    }

    if (typeof payload.message === "string") {
      return { message: payload.message };
    }
  }

  if (typeof payload === "string" && payload.trim()) {
    return { message: payload.trim() };
  }

  return { message: `Request failed with status ${status}` };
}

export async function api(path, options = {}) {
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new TypeError("API paths must be same-origin paths beginning with '/'.");
  }

  const { body, headers: suppliedHeaders, ...fetchOptions } = options;
  const method = String(fetchOptions.method || "GET").toUpperCase();
  const headers = new Headers(suppliedHeaders);
  headers.set("Accept", "application/json");

  let requestBody = body;
  if (isPlainObject(body)) {
    requestBody = JSON.stringify(body);
    if (!headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
  }

  if (!SAFE_METHODS.has(method) && !headers.has("X-CSRF-Token")) {
    const csrfToken = readCookie(CSRF_COOKIE_NAME);
    if (csrfToken) {
      headers.set("X-CSRF-Token", csrfToken);
    }
  }

  const response = await fetch(path, {
    ...fetchOptions,
    method,
    body: requestBody,
    credentials: "include",
    headers,
  });
  const payload = await responseBody(response);

  if (!response.ok) {
    const details = errorDetails(payload, response.status);
    throw new ApiError(details.message, {
      status: response.status,
      code: details.code,
      details: payload,
    });
  }

  return payload;
}
