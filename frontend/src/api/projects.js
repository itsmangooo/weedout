import { api, ApiError } from "./client";

/**
 * One project: reading it, and the things the project page can change.
 *
 * The read is a single request. The page shows findings, dependencies, scan
 * history, supply-chain signals, rules and keys together, and fetching them
 * separately would render it in pieces — each arriving at a different moment
 * and shifting the layout under whoever is reading it.
 */

export const PROJECTS_PATH = "/api/internal/projects";

export function projectPath(id) {
  return `${PROJECTS_PATH}/${encodeURIComponent(id)}`;
}

function unexpected(payload) {
  return new ApiError("The project service returned an unexpected response.", {
    status: 502,
    code: "INVALID_PROJECT_RESPONSE",
    details: payload,
  });
}

function isProjectPage(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    value.data !== null &&
    typeof value.data === "object" &&
    Number.isInteger(value.data.id) &&
    typeof value.data.name === "string" &&
    Array.isArray(value.findings) &&
    Array.isArray(value.dependencies) &&
    Array.isArray(value.recent_runs) &&
    Array.isArray(value.rules) &&
    Array.isArray(value.api_keys) &&
    value.webhook !== null &&
    typeof value.webhook === "object"
  );
}

export async function getProject(id, { show = "open", signal } = {}) {
  const payload = await api(`${projectPath(id)}?show=${encodeURIComponent(show)}`, { signal });
  if (!isProjectPage(payload)) {
    throw unexpected(payload);
  }
  return payload;
}

/**
 * Create a project.
 *
 * Multipart rather than JSON, because one of the three ways in is a file
 * upload: base64 in a JSON body would cost a third more bytes for nothing. A
 * FormData body is passed through untouched by the client, which only
 * serialises plain objects.
 */
export async function createProject({ name, ecosystem, file, content, filename }) {
  const form = new FormData();
  form.set("name", name ?? "");
  if (ecosystem) form.set("ecosystem", ecosystem);
  if (file) form.set("manifest", file);
  if (content) form.set("content", content);
  if (filename) form.set("filename", filename);

  const payload = await api(PROJECTS_PATH, { method: "POST", body: form });
  if (!Number.isInteger(payload?.data?.id)) {
    throw unexpected(payload);
  }
  return payload.data;
}

export async function renameProject(id, name) {
  const payload = await api(`${projectPath(id)}/rename`, {
    method: "POST",
    body: { name },
  });
  return payload?.data;
}

export async function attachManifest(id, { file, content, filename }) {
  const form = new FormData();
  if (file) form.set("manifest", file);
  if (content) form.set("content", content);
  if (filename) form.set("filename", filename);

  const payload = await api(`${projectPath(id)}/manifest`, { method: "POST", body: form });
  return payload?.data;
}

export async function rescanProject(id) {
  const payload = await api(`${projectPath(id)}/scan`, { method: "POST", body: {} });
  return payload?.data;
}

export async function deleteProject(id) {
  await api(`${projectPath(id)}/delete`, { method: "POST", body: {} });
}

/**
 * Issue a key.
 *
 * The plaintext comes back in this response and is never obtainable again —
 * only its hash is stored. The caller has to show it once and must not put it
 * anywhere it would persist, which is why nothing here writes it to a URL.
 */
export async function createProjectKey(id, { name, scope }) {
  const payload = await api(`${projectPath(id)}/keys`, {
    method: "POST",
    body: { name, scope },
  });
  if (typeof payload?.data?.token !== "string") {
    throw unexpected(payload);
  }
  return payload.data;
}

export async function revokeProjectKey(id, keyId) {
  await api(`${projectPath(id)}/keys/${encodeURIComponent(keyId)}/revoke`, {
    method: "POST",
    body: {},
  });
}

export async function addIgnoreRule(id, { identifier, reason }) {
  const payload = await api(`${projectPath(id)}/rules`, {
    method: "POST",
    body: { identifier, reason },
  });
  return payload?.data;
}

export async function removeIgnoreRule(id, ruleId) {
  await api(`${projectPath(id)}/rules/${encodeURIComponent(ruleId)}/delete`, {
    method: "POST",
    body: {},
  });
}

export async function setThresholds(id, { direct, transitive, epss }) {
  const payload = await api(`${projectPath(id)}/thresholds`, {
    method: "POST",
    body: { direct: direct ?? "", transitive: transitive ?? "", epss: epss ?? null },
  });
  return payload?.data;
}
