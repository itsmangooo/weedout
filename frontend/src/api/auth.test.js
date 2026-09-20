import { describe, expect, it, vi } from "vitest";

import { CURRENT_USER_PATH, getCurrentUser } from "./auth";

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("auth API", () => {
  it("loads the current session through the same-origin internal endpoint", async () => {
    const data = {
      authenticated: true,
      session_state: "authenticated",
      user: {
        id: 7,
        email: "dev@example.com",
        is_admin: false,
        tier: "free",
        account_state: "active",
      },
    };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ data }));

    await expect(getCurrentUser()).resolves.toEqual(data);
    expect(fetchMock).toHaveBeenCalledWith(
      CURRENT_USER_PATH,
      expect.objectContaining({
        credentials: "include",
        method: "GET",
      }),
    );
  });

  it("rejects a response that does not match the deliberate auth schema", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ data: { authenticated: true, user: { password_hash: "nope" } } }),
    );

    await expect(getCurrentUser()).rejects.toMatchObject({
      code: "INVALID_AUTH_RESPONSE",
      status: 502,
    });
  });
});
