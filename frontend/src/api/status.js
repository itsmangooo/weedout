import { api, ApiError } from "./client";

/**
 * The public service status.
 *
 * No credential, because the failure it reports — a stale advisory feed —
 * breaks the product's promise without breaking a page, and somebody deciding
 * whether to trust a scan result should not need an account to check.
 */

export const STATUS_PATH = "/api/internal/status";

export async function getStatus({ signal } = {}) {
  const payload = await api(STATUS_PATH, { signal });
  if (
    typeof payload?.data?.state !== "string" ||
    !Array.isArray(payload.data.feeds) ||
    !Number.isInteger(payload.data.scans_24h)
  ) {
    throw new ApiError("The status service returned an unexpected response.", {
      status: 502,
      code: "INVALID_STATUS_RESPONSE",
      details: payload,
    });
  }
  return payload;
}
