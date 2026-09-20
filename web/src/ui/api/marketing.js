import { api } from "./client";

/**
 * The public pages: pricing, the CLI page, docs and contact.
 *
 * All unauthenticated except contact, which reads the session only to fill in
 * the sender's address — a typed one could be anybody's, and a reply going to
 * the wrong person is worse than no reply.
 */

export async function getPricing({ signal } = {}) {
  const payload = await api("/api/internal/pricing", { signal });
  return payload?.data;
}

export async function getCliFacts({ signal } = {}) {
  const payload = await api("/api/internal/cli", { signal });
  return payload?.data;
}

export async function getDocsIndex({ signal } = {}) {
  const payload = await api("/api/internal/docs", { signal });
  return payload?.data;
}

export async function getDocsPage(slug, { signal } = {}) {
  return api(`/api/internal/docs/${encodeURIComponent(slug)}`, { signal });
}

export async function sendContactMessage({ message, category, email }) {
  const payload = await api("/api/internal/contact", {
    method: "POST",
    body: { message, category, email },
  });
  return payload?.data;
}
