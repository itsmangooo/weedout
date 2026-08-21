import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MotionConfig } from "motion/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
import { AppErrorBoundary, RouteErrorBoundary } from "../components/feedback/AppErrorBoundary";
import { REDUCED_MOTION_POLICY } from "./providers";
import { createQueryClient, shouldRetryRequest } from "./queryClient";
import { createAppRouter } from "./router";

function response(body, status = 200) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "Content-Type": typeof body === "string" ? "text/plain" : "application/json" },
  });
}

function renderRoute(path = "/") {
  const client = createQueryClient({ queries: { retry: false } });
  const router = createAppRouter({ initialEntries: [path] });
  render(
    <QueryClientProvider client={client}>
      <MotionConfig reducedMotion={REDUCED_MOTION_POLICY}>
        <RouterProvider router={router} />
      </MotionConfig>
    </QueryClientProvider>,
  );
  return { client, router };
}

describe("frontend routes", () => {
  it("renders loading and then the real backend status", async () => {
    let resolveRequest;
    vi.spyOn(globalThis, "fetch").mockReturnValue(
      new Promise((resolve) => {
        resolveRequest = resolve;
      }),
    );

    renderRoute();
    expect(await screen.findByText("Checking connection")).toBeInTheDocument();

    resolveRequest(response({ status: "ok", version: "0.1.0" }));
    expect(await screen.findByText("Backend connected")).toBeInTheDocument();
    expect(screen.getByText("0.1.0")).toBeInTheDocument();
  });

  it("renders a backend error and recovers through retry", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(response("Service unavailable", 503))
      .mockResolvedValueOnce(response({ status: "ok", version: "0.1.0" }));
    const user = userEvent.setup();

    renderRoute();
    expect(await screen.findByText("Backend unavailable")).toBeInTheDocument();
    expect(screen.getByText("Service unavailable")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Backend connected")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("renders the not-found route and navigates home without a reload", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response({ status: "ok", version: "0.1.0" }));
    const user = userEvent.setup();

    renderRoute("/not-migrated");
    expect(screen.getByRole("heading", { name: "This frontend route has not migrated yet." })).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "Return to the foundation" }));
    expect(
      await screen.findByRole("heading", {
        name: "Forty-seven advisories enter. One decision leaves.",
      }),
    ).toBeInTheDocument();
  });

  it("renders the Weedout-specific filtering and workflow composition", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      response({ status: "ok", version: "0.1.0" }),
    );

    renderRoute();

    expect(
      await screen.findByRole("heading", {
        name: "Forty-seven advisories enter. One decision leaves.",
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Watch the page get quieter." })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "The path is the product." })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Ship the fix. Ignore the noise." })).toBeInTheDocument();
    expect(screen.getAllByText("CVE-2026-5001").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Replay filter" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Replay scan" })).toBeInTheDocument();
    expect(
      await screen.findByText("Exploited in the wild", {}, { timeout: 2_000 }),
    ).toBeInTheDocument();
  });

  it("keeps the global error boundary recoverable", async () => {
    let shouldThrow = true;
    function UnstableView() {
      if (shouldThrow) {
        throw new Error("render failed");
      }
      return <p>Recovered view</p>;
    }

    render(
      <AppErrorBoundary>
        <UnstableView />
      </AppErrorBoundary>,
    );
    expect(screen.getByText("This view could not render")).toBeInTheDocument();

    shouldThrow = false;
    fireEvent.click(screen.getByRole("button", { name: "Try rendering again" }));
    expect(screen.getByText("Recovered view")).toBeInTheDocument();
  });

  it("keeps route-level failures isolated and navigable", async () => {
    const user = userEvent.setup();
    const router = createMemoryRouter(
      [
        { path: "/", element: <p>Recovered route</p> },
        {
          path: "/broken",
          loader: () => {
            throw new Response("Unavailable", { status: 503, statusText: "Service Unavailable" });
          },
          errorElement: <RouteErrorBoundary />,
        },
      ],
      { initialEntries: ["/broken"] },
    );

    render(<RouterProvider router={router} />);
    expect(await screen.findByText("503 Service Unavailable")).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "Return to the foundation" }));
    expect(await screen.findByText("Recovered route")).toBeInTheDocument();
  });

  it("uses the user's reduced-motion preference globally", () => {
    expect(REDUCED_MOTION_POLICY).toBe("user");
  });

  it("retries only one transient failure and never retries a 4xx", () => {
    expect(shouldRetryRequest(0, new ApiError("Not found", { status: 404 }))).toBe(false);
    expect(shouldRetryRequest(0, new ApiError("Unavailable", { status: 503 }))).toBe(true);
    expect(shouldRetryRequest(1, new TypeError("Network error"))).toBe(false);
  });

  it("does not keep a failed health query pending", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Network error"));
    renderRoute();

    await waitFor(() => {
      expect(screen.getByText("Backend unavailable")).toBeInTheDocument();
    });
  });
});
