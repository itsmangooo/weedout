import { api, ApiError } from "./client";

export const DASHBOARD_PATH = "/api/internal/dashboard";

const SUMMARY_FIELDS = [
  "projects",
  "dependencies",
  "open_findings",
  "exploited_findings",
  "critical_findings",
  "filtered_findings",
  "dismissed_findings",
  "resolved_findings",
  "filter_rate_percent",
];

function isCount(value) {
  return Number.isInteger(value) && value >= 0;
}

function isSummary(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    SUMMARY_FIELDS.every((field) => isCount(value[field]))
  );
}

function isProject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    Number.isInteger(value.id) &&
    typeof value.name === "string" &&
    typeof value.ecosystem === "string" &&
    (value.manifest_kind === null || typeof value.manifest_kind === "string") &&
    isCount(value.dependency_count) &&
    typeof value.is_active === "boolean" &&
    typeof value.has_manifest === "boolean" &&
    (value.last_scanned_at === null || typeof value.last_scanned_at === "string") &&
    typeof value.last_scan_failed === "boolean" &&
    value.findings !== null &&
    typeof value.findings === "object" &&
    isCount(value.findings.open) &&
    isCount(value.findings.exploited) &&
    isCount(value.findings.filtered)
  );
}

function isDashboardData(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    isSummary(value.summary) &&
    Array.isArray(value.projects) &&
    value.projects.every(isProject)
  );
}

export async function getDashboard({ signal } = {}) {
  const payload = await api(DASHBOARD_PATH, { signal });
  if (!isDashboardData(payload?.data)) {
    throw new ApiError("The dashboard service returned an unexpected response.", {
      status: 502,
      code: "INVALID_DASHBOARD_RESPONSE",
      details: payload,
    });
  }

  return payload.data;
}
