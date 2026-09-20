import { describe, expect, it, vi } from "vitest";

import { ApiError } from "./client";
import { getFindings } from "./findings";

function response(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function payload() {
  return {
    data: [
      {
        id: 9,
        project: { id: 3, name: "worker" },
        identifier: "CVE-2026-1000",
        package_name: "qs",
        installed_version: "6.0.0",
        severity: "high",
        is_exploited: false,
        reachability: "reachable",
        status: "open",
        detected_at: "2026-08-20T18:30:00Z",
      },
    ],
    meta: { show: "open", limit: 25, count: 1, history_days: null },
  };
}

describe("findings API", () => {
  it("requests the bounded open finding excerpt with the shared client", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(response(payload()));

    await expect(getFindings()).resolves.toEqual(payload());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/internal/findings?show=open&limit=25",
      expect.objectContaining({ credentials: "include", method: "GET" }),
    );
  });

  it("rejects a response that does not match the explicit finding contract", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      response({
        data: [{ id: 9, owner_id: 44 }],
        meta: { show: "open", limit: 25, count: 1, history_days: null },
      }),
    );

    const error = await getFindings().catch((caught) => caught);

    expect(error).toMatchObject({
      name: "ApiError",
      code: "INVALID_FINDINGS_RESPONSE",
      status: 502,
    });
    expect(error).toBeInstanceOf(ApiError);
  });
});
