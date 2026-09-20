import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MotionConfig } from "motion/react";
import { RouterProvider } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { REDUCED_MOTION_POLICY } from "./providers";
import { createQueryClient } from "./queryClient";
import { createAppRouter } from "./router";

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function currentUser({ isAdmin = false } = {}) {
  return {
    data: {
      authenticated: true,
      session_state: "authenticated",
      user: {
        id: 42,
        email: isAdmin ? "admin@example.com" : "dev@example.com",
        is_admin: isAdmin,
        tier: isAdmin ? "pro" : "free",
        account_state: "active",
      },
    },
  };
}

/** The auth boundary's own panel, as opposed to the page chrome around it. */
function boundaryPanel() {
  const panel = document.querySelector(".auth-route-state");
  if (!panel) throw new Error("the auth boundary panel did not render");
  return panel;
}

function renderRoute(path) {
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

describe("authenticated routes", () => {
  it("renders a dedicated loading state while the session is checked", () => {
    vi.spyOn(globalThis, "fetch").mockReturnValue(new Promise(() => {}));

    renderRoute("/auth-boundary");

    expect(screen.getByRole("heading", { name: "Checking your session" })).toBeInTheDocument();
  });

  it("renders an unauthenticated state without navigating to the legacy login page", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      response({
        data: {
          authenticated: false,
          session_state: "anonymous",
          user: null,
        },
      }),
    );

    renderRoute("/auth-boundary");

    expect(
      await screen.findByRole("heading", { name: "Sign in to continue" }),
    ).toBeInTheDocument();
    // Scoped to the boundary panel: the page header carries its own "Sign in"
    // for anonymous visitors, and an unscoped query matches both.
    expect(within(boundaryPanel()).getByRole("link", { name: "Sign in" })).toHaveAttribute(
      "href",
      "/login?next=%2Fauth-boundary",
    );
  });

  it("renders the protected route for a valid session", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response(currentUser()));

    renderRoute("/auth-boundary");

    expect(
      await screen.findByRole("heading", { name: "Session boundary confirmed." }),
    ).toBeInTheDocument();
    expect(screen.getByText("dev@example.com")).toBeInTheDocument();
  });

  it("renders a distinct expired-session state for a stale cookie", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      response(
        {
          error: {
            code: "SESSION_EXPIRED",
            message: "Your session has expired. Sign in again.",
          },
        },
        401,
      ),
    );

    renderRoute("/auth-boundary");

    expect(
      await screen.findByRole("heading", { name: "Your session expired" }),
    ).toBeInTheDocument();
    // Scoped to the boundary panel: the page header carries its own "Sign in"
    // for anonymous visitors, and an unscoped query matches both.
    expect(within(boundaryPanel()).getByRole("link", { name: "Sign in" })).toHaveAttribute(
      "href",
      "/login?next=%2Fauth-boundary",
    );
  });

  it("renders a forbidden state when the auth service refuses access", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      response({ error: { code: "FORBIDDEN", message: "Not allowed." } }, 403),
    );

    renderRoute("/auth-boundary");

    expect(
      await screen.findByRole("heading", { name: "Administrator access required" }),
    ).toBeInTheDocument();
  });
});

describe("administrator routes", () => {
  it("refuses an authenticated non-admin without a page reload", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response(currentUser()));

    renderRoute("/auth-boundary/admin");

    expect(
      await screen.findByRole("heading", { name: "Administrator access required" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Admin boundary confirmed.")).not.toBeInTheDocument();
  });

  it("renders the admin route for an administrator session", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(response(currentUser({ isAdmin: true })));

    renderRoute("/auth-boundary/admin");

    expect(
      await screen.findByRole("heading", { name: "Admin boundary confirmed." }),
    ).toBeInTheDocument();
    expect(screen.getByText(/admin@example.com may enter/)).toBeInTheDocument();
  });
});
