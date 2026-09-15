import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MotionConfig } from "motion/react";
import { RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { currentUserQueryKey } from "../features/auth/hooks/useCurrentUser";
import { REDUCED_MOTION_POLICY } from "../app/providers";
import { createQueryClient } from "../app/queryClient";
import { createAppRouter } from "../app/router";

/**
 * The archive tabs stop at the plan's retention window. Without a line saying
 * so, a Free account that resolved something in June opens the Resolved tab in
 * August and sees nothing — which reads as data loss, not as a plan limit.
 */

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function user(tier) {
  return {
    authenticated: true,
    session_state: "authenticated",
    user: {
      id: 42,
      email: "dev@example.com",
      is_admin: false,
      tier,
      account_state: "active",
    },
  };
}

function renderResolvedTab({ historyDays, tier = "free" }) {
  vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
    const url = String(input?.url ?? input);
    if (url.includes("/api/internal/findings")) {
      return Promise.resolve(
        response({
          data: [],
          meta: { show: "resolved", limit: 100, count: 0, history_days: historyDays },
        }),
      );
    }
    return Promise.resolve(response({ data: { projects: [], summary: {} } }));
  });

  const client = createQueryClient({ queries: { retry: false } });
  client.setQueryData(currentUserQueryKey, user(tier));
  const router = createAppRouter({ initialEntries: ["/alerts?show=resolved"] });
  render(
    <QueryClientProvider client={client}>
      <MotionConfig reducedMotion={REDUCED_MOTION_POLICY}>
        <RouterProvider router={router} />
      </MotionConfig>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("the retention window on the findings archive", () => {
  it("tells a Free account how far back the archive reaches", async () => {
    renderResolvedTab({ historyDays: 365 });

    expect(await screen.findByText("Showing the past year.")).toBeVisible();
  });

  it("normalizes a legacy paid account to the same archive window", async () => {
    renderResolvedTab({ historyDays: 365, tier: "pro" });

    expect(await screen.findByText("Showing the past year.")).toBeVisible();
    expect(screen.queryByText(/upgrade|paid plan/i)).toBeNull();
  });

  it("says nothing on the tabs that are not trimmed", async () => {
    renderResolvedTab({ historyDays: null });

    expect(await screen.findByText("Nothing has been resolved yet.")).toBeVisible();
    expect(screen.queryByText(/Showing the past/)).toBeNull();
  });
});
