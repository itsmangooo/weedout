import { api, ApiError } from "./client";

export const FINDINGS_PATH = "/api/internal/findings";

const FINDING_SHOWS = new Set(["open", "filtered", "dismissed", "resolved"]);
const SEVERITIES = new Set(["unknown", "low", "medium", "high", "critical"]);
const REACHABILITY = new Set(["runtime_direct", "runtime_transitive", "dev_only"]);
const STATUSES = new Set(["open", "dismissed", "resolved"]);

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
    value.count >= 0
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
