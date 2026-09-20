import { api, ApiError } from "./client";

export const FINDINGS_PATH = "/api/internal/findings";

const FINDING_SHOWS = new Set(["open", "filtered", "dismissed", "resolved"]);
const SEVERITIES = new Set(["unknown", "low", "medium", "high", "critical"]);
const REACHABILITY = new Set([
  "reachable",
  "potentially_reachable",
  "not_observed",
  "unknown",
]);
const STATUSES = new Set(["open", "filtered", "dismissed", "resolved"]);

function isFinding(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    Number.isInteger(value.id) &&
    value.project !== null &&
    typeof value.project === "object" &&
    Number.isInteger(value.project.id) &&
    typeof value.project.name === "string" &&
    typeof value.identifier === "string" &&
    typeof value.package_name === "string" &&
    typeof value.installed_version === "string" &&
    SEVERITIES.has(value.severity) &&
    typeof value.is_exploited === "boolean" &&
    REACHABILITY.has(value.reachability) &&
    (value.fixed_version === null || typeof value.fixed_version === "string" || value.fixed_version === undefined) &&
    STATUSES.has(value.status) &&
    typeof value.detected_at === "string"
  );
}

function isMeta(value, show) {
  return (
    value !== null &&
    typeof value === "object" &&
    value.show === show &&
    FINDING_SHOWS.has(value.show) &&
    Number.isInteger(value.limit) &&
    value.limit > 0 &&
    Number.isInteger(value.count) &&
    value.count >= 0 &&
    (value.history_days === null || Number.isInteger(value.history_days))
  );
}

export async function getFindings({ show = "open", limit = 25, signal } = {}) {
  const search = new URLSearchParams({ show, limit: String(limit) });
  const payload = await api(`${FINDINGS_PATH}?${search}`, { signal });

  if (
    !Array.isArray(payload?.data) ||
    !payload.data.every(isFinding) ||
    !isMeta(payload.meta, show) ||
    payload.meta.count !== payload.data.length
  ) {
    throw new ApiError("The findings service returned an unexpected response.", {
      status: 502,
      code: "INVALID_FINDINGS_RESPONSE",
      details: payload,
    });
  }

  return payload;
}

export const ALERTS_PATH = "/api/internal/alerts";

function alertPath(id) {
  return `${ALERTS_PATH}/${encodeURIComponent(id)}`;
}

/**
 * One finding in full, with its explanation.
 *
 * The explanation is plain text produced by the server from the same functions
 * that write the alert emails, so a finding reads identically wherever it is
 * met. The client renders those strings and does not compose its own.
 */
export async function getAlert(id, { signal } = {}) {
  const payload = await api(alertPath(id), { signal });
  if (!Number.isInteger(payload?.data?.id) || typeof payload?.explanation !== "object") {
    throw new ApiError("The finding service returned an unexpected response.", {
      status: 502,
      code: "INVALID_ALERT_RESPONSE",
      details: payload,
    });
  }
  return payload;
}

/**
 * Dismiss a finding, or reopen one.
 *
 * `resolved` is not offered. It is derived from a scan finding the
 * vulnerability gone, and the server refuses it here — marking a still-present
 * finding as fixed is the one claim this product exists not to make falsely.
 */
export async function setAlertStatus(id, { status, note = "" }) {
  const payload = await api(`${alertPath(id)}/status`, {
    method: "POST",
    body: { status, note },
  });
  return payload?.data;
}
