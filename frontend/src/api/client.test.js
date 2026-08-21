import { afterEach, describe, expect, it, vi } from "vitest";

import { api, ApiError } from "./client";

afterEach(() => {
  document.cookie = "weedout_csrf=; Max-Age=0; path=/";
});

describe("api", () => {
  it("sends same-origin JSON requests with cookies", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { saved: true } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(api("/api/internal/example", { method: "POST", body: { enabled: true } })).resolves.toEqual({
      data: { saved: true },
    });

    const [path, request] = fetchMock.mock.calls[0];
    expect(path).toBe("/api/internal/example");
    expect(request.credentials).toBe("include");
    expect(request.body).toBe(JSON.stringify({ enabled: true }));
    expect(request.headers.get("Content-Type")).toBe("application/json");
  });

  it("leaves FormData intact and attaches the CSRF header", async () => {
    document.cookie = "weedout_csrf=csrf%20value; path=/";
    const form = new FormData();
    form.set("name", "demo");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));

    await expect(api("/api/internal/projects", { method: "POST", body: form })).resolves.toBeNull();

    const request = fetchMock.mock.calls[0][1];
    expect(request.body).toBe(form);
    expect(request.headers.has("Content-Type")).toBe(false);
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf value");
  });

  it("passes abort signals through to fetch", async () => {
    const controller = new AbortController();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "ok" }), {
        headers: { "Content-Type": "application/json" },
      }),
    );

    await api("/healthz", { signal: controller.signal });

    expect(fetchMock.mock.calls[0][1].signal).toBe(controller.signal);
  });

  it.each([
    [{ error: { code: "PROJECT_LIMIT_REACHED", message: "Project limit reached." } }, "PROJECT_LIMIT_REACHED", "Project limit reached."],
    [{ error: "rate_limited", message: "Try again shortly." }, "rate_limited", "Try again shortly."],
    [{ error: "Not allowed." }, undefined, "Not allowed."],
  ])("normalizes JSON error shape %#", async (payload, code, message) => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(payload), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const error = await api("/api/internal/example").catch((caught) => caught);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 403, code, message });
  });

  it("turns a non-JSON failure into an ApiError", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("Service unavailable", {
        status: 503,
        headers: { "Content-Type": "text/plain" },
      }),
    );

    await expect(api("/healthz")).rejects.toMatchObject({
      name: "ApiError",
      status: 503,
      message: "Service unavailable",
    });
  });

  it("rejects external or ambiguous paths", async () => {
    await expect(api("https://example.com/data")).rejects.toThrow("same-origin");
    await expect(api("api/internal/data")).rejects.toThrow("same-origin");
  });
});
