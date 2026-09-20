import { api, ApiError } from "./client";

/**
 * The terms of service and the privacy policy.
 *
 * Public, and served from the repository rather than the database — so the
 * version history is `git log`, which is the only useful answer to "what did
 * this say when I signed up?".
 */

export const LEGAL_PATH = "/api/internal/legal";

export async function getLegalPage(slug, { signal } = {}) {
  const payload = await api(`${LEGAL_PATH}/${encodeURIComponent(slug)}`, { signal });
  if (typeof payload?.data?.body_html !== "string" || !payload.data.title) {
    throw new ApiError("That page could not be read.", {
      status: 502,
      code: "INVALID_LEGAL_RESPONSE",
      details: payload,
    });
  }
  return payload;
}
