import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MotionConfig } from "motion/react";
import { RouterProvider } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { currentUserQueryKey } from "../features/auth/hooks/useCurrentUser";
import { REDUCED_MOTION_POLICY } from "./providers";
import { createQueryClient } from "./queryClient";
import { createAppRouter } from "./router";

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function authResponse() {
  return {
    data: {
      authenticated: true,
      session_state: "authenticated",
      user: {
        id: 42,
        email: "dev@example.com",
        is_admin: false,
        tier: "free",
        account_state: "active",
      },
    },
  };
}

function summary(overrides = {}) {
  return {
    projects: 0,
    dependencies: 0,
    open_findings: 0,
    exploited_findings: 0,
    critical_findings: 0,
    filtered_findings: 0,
    dismissed_findings: 0,
    resolved_findings: 0,
    filter_rate_percent: 0,
    ...overrides,
  };
}

function project(overrides = {}) {
  return {
    id: 8,
    name: "checkout-api",
    ecosystem: "npm",
    manifest_kind: "package-lock.json",
    dependency_count: 143,
    is_active: true,
    has_manifest: true,
    last_scanned_at: "2026-08-20T18:30:00Z",
    last_scan_failed: false,
    findings: { open: 3, exploited: 1, filtered: 8 },
    ...overrides,
  };
}

function dashboardResponse({ projects = [], summary: summaryValue = summary() } = {}) {
  return { data: { projects, summary: summaryValue } };
}

function finding(overrides = {}) {
  return {
    id: 91,
    project: { id: 8, name: "checkout-api" },
    identifier: "CVE-2026-5001",
    package_name: "minimist",
    installed_version: "1.2.5",
    severity: "critical",
    is_exploited: true,
    reachability: "potentially_reachable",
    status: "open",
    detected_at: "2026-08-20T18:30:00Z",
    ...overrides,
  };
}

function findingsResponse(findings = []) {
  return {
    data: findings,
    meta: { show: "open", limit: 25, count: findings.length, history_days: null },
  };
}

function renderDashboard({ authenticated = false } = {}) {
  const client = createQueryClient({ queries: { retry: false } });
  if (authenticated) {
    client.setQueryData(currentUserQueryKey, authResponse().data);
  }
  const router = createAppRouter({ initialEntries: ["/dashboard"] });
  render(
    <QueryClientProvider client={client}>
      <MotionConfig reducedMotion={REDUCED_MOTION_POLICY}>
        <RouterProvider router={router} />
      </MotionConfig>
    </QueryClientProvider>,
  );
  return { client, router };
}

describe("React dashboard route", () => {
  it("shows dashboard-specific loading after authentication succeeds", async () => {
    vi.spyOn(globalThis, "fetch").mockReturnValue(new Promise(() => {}));

    renderDashboard({ authenticated: true });

    expect(
      await screen.findByRole("heading", { name: "Loading your dashboard" }),
    ).toBeInTheDocument();
  });

  it("renders real dashboard summary and project state", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((path) => {
      if (path === "/api/internal/auth/me") {
        return Promise.resolve(response(authResponse()));
      }
      if (path === "/api/internal/dashboard") {
        return Promise.resolve(
          response(
            dashboardResponse({
              summary: summary({
                projects: 1,
                dependencies: 143,
                open_findings: 3,
                exploited_findings: 1,
                critical_findings: 2,
                filtered_findings: 8,
                resolved_findings: 4,
                filter_rate_percent: 73,
              }),
              projects: [project()],
            }),
          ),
        );
      }
      return Promise.resolve(response(findingsResponse()));
    });

    renderDashboard();

    expect(
      await screen.findByRole("heading", { name: "Security overview" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Exploited in the wild")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "checkout-api" })).toBeInTheDocument();
    expect(screen.getByText("Exploited finding")).toBeInTheDocument();
    expect(screen.getByText("73%")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/internal/dashboard",
      expect.objectContaining({ credentials: "include", method: "GET" }),
    );
  });

  it("shows an independent loading state while the open findings excerpt loads", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((path) => {
      if (path === "/api/internal/dashboard") {
        return Promise.resolve(
          response(
            dashboardResponse({
              summary: summary({ projects: 1, open_findings: 1 }),
              projects: [project()],
            }),
          ),
        );
      }
      return new Promise(() => {});
    });

    renderDashboard({ authenticated: true });

    expect(await screen.findByText("Loading open findings")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Open findings" })).toBeInTheDocument();
  });

  it("renders the compact open-finding attention excerpt", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((path) => {
      if (path === "/api/internal/dashboard") {
        return Promise.resolve(
          response(
            dashboardResponse({
              summary: summary({ projects: 1, open_findings: 1, exploited_findings: 1 }),
              projects: [project()],
            }),
          ),
        );
      }
      return Promise.resolve(response(findingsResponse([finding()])));
    });

    renderDashboard({ authenticated: true });

    expect(await screen.findByRole("link", { name: "CVE-2026-5001" })).toHaveAttribute(
      "href",
      "/alerts/91",
    );
    expect(screen.getByText("minimist@1.2.5")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "checkout-api" })).toHaveAttribute(
      "href",
      "/targets/8",
    );
    expect(screen.getAllByText("Exploited in the wild")).toHaveLength(2);
    expect(screen.getByText("critical severity")).toBeInTheDocument();
    expect(screen.getByText("Potentially reachable")).toBeInTheDocument();
  });

  it("keeps anonymous visitors at the existing protected-route boundary", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      response({
        data: {
          authenticated: false,
          session_state: "anonymous",
          user: null,
        },
      }),
    );

    renderDashboard();

    expect(
      await screen.findByRole("heading", { name: "Sign in to continue" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute(
      "href",
      "/login?next=%2Fdashboard",
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("renders an honest first-project empty state", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((path) => {
      if (path === "/api/internal/auth/me") {
        return Promise.resolve(response(authResponse()));
      }
      if (path === "/api/internal/dashboard") {
        return Promise.resolve(response(dashboardResponse()));
      }
      return Promise.resolve(response(findingsResponse()));
    });

    renderDashboard();

    expect(
      await screen.findByRole("heading", { name: "Add a project to start watching." }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Add project" })).toHaveLength(2);
    for (const link of screen.getAllByRole("link", { name: "Add project" })) {
      expect(link).toHaveAttribute("href", "/targets/new");
    }
    expect(await screen.findByText("No open findings need attention.")).toBeInTheDocument();
  });

  it("isolates backend failures to a retryable dashboard error state", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((path) => {
      if (path === "/api/internal/auth/me") {
        return Promise.resolve(response(authResponse()));
      }
      return Promise.resolve(
        response(
          { error: { code: "DASHBOARD_UNAVAILABLE", message: "Service unavailable" } },
          503,
        ),
      );
    });

    renderDashboard();

    expect(
      await screen.findByRole("heading", { name: "We couldn't load the dashboard." }),
    ).toBeInTheDocument();
    expect(screen.getByText("Service unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("isolates a findings API failure from the rest of the dashboard", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((path) => {
      if (path === "/api/internal/dashboard") {
        return Promise.resolve(
          response(
            dashboardResponse({
              summary: summary({ projects: 1, open_findings: 2 }),
              projects: [project()],
            }),
          ),
        );
      }
      return Promise.resolve(
        response(
          { error: { code: "FINDINGS_UNAVAILABLE", message: "Finding read unavailable" } },
          503,
        ),
      );
    });

    renderDashboard({ authenticated: true });

    expect(
      await screen.findByRole("heading", { name: "Security overview" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("Open findings unavailable")).toBeInTheDocument();
    expect(screen.getByText("Finding read unavailable")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "checkout-api" })).toBeInTheDocument();
  });
});
