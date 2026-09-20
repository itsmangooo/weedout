import { api } from "./client";

export const LANDING_PATH = "/api/internal/landing";

/**
 * Live, anonymised figures for the landing page.
 *
 * Public, and the only unauthenticated call the client makes. Every field is
 * already public information — advisory ids from OSV, package names from
 * public registries, and headline numbers rounded so they cannot be used to
 * count customers.
 *
 * A failure resolves to empty rather than throwing. This section is an extra
 * on a marketing page; it should never be the reason the page does not render.
 */
export async function getLandingData({ signal } = {}) {
  try {
    const payload = await api(LANDING_PATH, { signal });
    const data = payload?.data;
    if (!data || typeof data !== "object") {
      return null;
    }
    return data;
  } catch {
    return null;
  }
}
