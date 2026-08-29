import { api } from "./client";

/**
 * The admin panel's data layer.
 *
 * Every path here is under `/api/internal/admin`, which the server puts behind
 * an is-admin check. Nothing in this file is a permission boundary — the
 * `AdminRoute` guard and this module control what is *shown*, and a customer
 * who calls these paths directly is refused by Python, not by the absence of a
 * link. That is the arrangement the whole panel depends on, so it is worth
 * saying once here rather than in ten call sites.
 */

const ADMIN = "/api/internal/admin";

function unwrap(payload) {
  return payload?.data;
}

// --- Overview ---------------------------------------------------------------

export async function getOverview({ days = 30, signal } = {}) {
  return unwrap(await api(`${ADMIN}/overview?days=${encodeURIComponent(days)}`, { signal }));
}

// --- Users ------------------------------------------------------------------

export async function getUsers({ page = 1, search = "", status = "", signal } = {}) {
  const query = new URLSearchParams();
  query.set("page", String(page));
  if (search) query.set("search", search);
  if (status) query.set("status", status);

  return await api(`${ADMIN}/users?${query}`, { signal });
}

export async function getUser(id, { signal } = {}) {
  return unwrap(await api(`${ADMIN}/users/${encodeURIComponent(id)}`, { signal }));
}

export async function suspendUser(id, { reason = "" } = {}) {
  return unwrap(
    await api(`${ADMIN}/users/${encodeURIComponent(id)}/suspend`, {
      method: "POST",
      body: { reason },
    }),
  );
}

export async function unsuspendUser(id) {
  return unwrap(
    await api(`${ADMIN}/users/${encodeURIComponent(id)}/unsuspend`, { method: "POST", body: {} }),
  );
}

/**
 * Delete an account, permanently.
 *
 * `confirmEmail` is not optional and is not defaulted to the account's own
 * address: the point of the check is that a person typed it, and filling it in
 * from what we already know would turn the guard into a formality.
 */
export async function deleteUser(id, { confirmEmail }) {
  return unwrap(
    await api(`${ADMIN}/users/${encodeURIComponent(id)}/delete`, {
      method: "POST",
      body: { confirm_email: confirmEmail },
    }),
  );
}

// --- Billing ----------------------------------------------------------------

export async function getAdminBilling({ signal } = {}) {
  return unwrap(await api(`${ADMIN}/billing`, { signal }));
}

// --- Docs -------------------------------------------------------------------

export async function getDocPages({ signal } = {}) {
  return unwrap(await api(`${ADMIN}/docs`, { signal }))?.pages ?? [];
}

export async function getDocPage(id, { signal } = {}) {
  return unwrap(await api(`${ADMIN}/docs/${encodeURIComponent(id)}`, { signal }))?.page;
}

export async function createDocPage(fields) {
  return unwrap(await api(`${ADMIN}/docs`, { method: "POST", body: fields }))?.page;
}

export async function updateDocPage(id, fields) {
  return unwrap(
    await api(`${ADMIN}/docs/${encodeURIComponent(id)}`, { method: "POST", body: fields }),
  )?.page;
}

export async function deleteDocPage(id) {
  return unwrap(
    await api(`${ADMIN}/docs/${encodeURIComponent(id)}/delete`, { method: "POST", body: {} }),
  );
}

// --- Inbox ------------------------------------------------------------------

export async function getInbox({ show = "new", signal } = {}) {
  return unwrap(await api(`${ADMIN}/inbox?show=${encodeURIComponent(show)}`, { signal }));
}

export async function getInboxMessage(id, { signal } = {}) {
  return unwrap(await api(`${ADMIN}/inbox/${encodeURIComponent(id)}`, { signal }));
}

export async function setMessageStatus(id, { status, note = "" }) {
  return unwrap(
    await api(`${ADMIN}/inbox/${encodeURIComponent(id)}/status`, {
      method: "POST",
      body: { status, note },
    }),
  );
}

// --- Email ------------------------------------------------------------------

export async function getComposer({ signal } = {}) {
  return unwrap(await api(`${ADMIN}/email`, { signal }));
}

export async function previewCampaign(draft) {
  return unwrap(await api(`${ADMIN}/email/preview`, { method: "POST", body: draft }));
}

/**
 * Send a campaign.
 *
 * `confirmedCount` is the number the preview showed and a person agreed to.
 * The server refuses the send if the audience no longer matches it, so this
 * must be the count that was actually on screen — not a fresh count, and not
 * the length of a list this module recomputed.
 */
export async function sendCampaign(draft, { confirmedCount }) {
  return unwrap(
    await api(`${ADMIN}/email/send`, {
      method: "POST",
      body: { ...draft, confirmed_count: confirmedCount },
    }),
  );
}

// --- Audit ------------------------------------------------------------------

export async function getAudit({ signal } = {}) {
  return unwrap(await api(`${ADMIN}/audit`, { signal }))?.entries ?? [];
}
