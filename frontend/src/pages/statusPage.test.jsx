import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createQueryClient } from "../app/queryClient";
import { StatusPage } from "./StatusPage";

/**
 * The public status page.
 *
 * Read by somebody deciding whether to trust a scan result, often while
 * suspecting something is wrong. What it must not do is overstate what it
 * knows — it runs inside the service it reports on, so it can say the advisory
 * data is stale and cannot say the site is up.
 */

function status(overrides = {}) {
  return {
    data: {
      state: "operational",
      checked_at: new Date().toISOString(),
      feeds: [
        {
          label: "CISA KEV",
          hours_behind: 2,
          stale_after_hours: 24,
          record_count: 1247,
          is_stale: false,
        },
        {
          label: "OSV advisories — npm",
          hours_behind: 6,
          stale_after_hours: 48,
          record_count: 412_003,
          is_stale: false,
        },
      ],
      scans_24h: 318,
      advisories: 1_284_000,
      accounts: null,
      projects: null,
      ...overrides,
    },
  };
}

function renderStatus(body = status(), init = { status: 200 }) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify(body), {
      ...init,
      headers: { "Content-Type": "application/json" },
    }),
  );
  render(
    <QueryClientProvider client={createQueryClient({ queries: { retry: false } })}>
      <MemoryRouter>
        <StatusPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("the status page", () => {
  it("says everything is current when it is", async () => {
    renderStatus();

    expect(await screen.findByText("Everything is current")).toBeVisible();
  });

  it("names each feed separately rather than as one line", async () => {
    // One green "OSV" row while the Go export has been failing for a week is
    // the same lie in a nicer font.
    renderStatus();

    expect(await screen.findByText("CISA KEV")).toBeVisible();
    expect(screen.getByText("OSV advisories — npm")).toBeVisible();
  });

  it("says which scan results may be affected when a feed is behind", async () => {
    renderStatus(
      status({
        state: "degraded",
        feeds: [
          {
            label: "OSV advisories — Go",
            hours_behind: 300,
            stale_after_hours: 48,
            record_count: 90_000,
            is_stale: true,
          },
        ],
      }),
    );

    expect(await screen.findByText("Some advisory data is behind")).toBeVisible();
    // Not just "degraded". What it means for the reader is that their findings
    // may be missing recent advisories.
    expect(screen.getByText(/may be missing recent advisories/)).toBeVisible();
  });

  it("says a feed has never synced rather than showing a zero", async () => {
    renderStatus(
      status({
        state: "degraded",
        feeds: [
          {
            label: "OSV advisories — Maven",
            hours_behind: null,
            stale_after_hours: 48,
            record_count: 0,
            is_stale: true,
          },
        ],
      }),
    );

    expect(await screen.findByText("never synced")).toBeVisible();
  });

  it("reads hours the way a person would", async () => {
    renderStatus(
      status({
        feeds: [
          {
            label: "CISA KEV",
            hours_behind: 0.3,
            stale_after_hours: 24,
            record_count: 10,
            is_stale: false,
          },
        ],
      }),
    );

    // "0.3 hours ago" is accurate and reads as a machine talking.
    expect(await screen.findByText(/18 minutes ago/)).toBeVisible();
  });

  it("admits what it cannot tell you", async () => {
    // The most important sentence on the page. Without it, a page that loads
    // implies an uptime guarantee it cannot make.
    renderStatus();

    expect(await screen.findByText(/runs inside the service it reports on/)).toBeVisible();
  });

  it("hides adoption numbers rather than showing zeroes", async () => {
    // A zero reads as "nobody uses this", which is a different claim from
    // "we do not publish that".
    renderStatus();

    await screen.findByText("Everything is current");
    expect(screen.queryByText("Accounts")).toBeNull();
    expect(screen.queryByText("Projects watched")).toBeNull();
  });

  it("shows them when the deployment publishes them", async () => {
    renderStatus(status({ accounts: 214, projects: 806 }));

    expect(await screen.findByText("Accounts")).toBeVisible();
    expect(screen.getByText("806")).toBeVisible();
  });

  it("says so, rather than showing nothing, when it cannot load", async () => {
    renderStatus({ code: "OOPS", message: "Service unavailable." }, { status: 503 });

    expect(await screen.findByText(/If it will not load, that is/)).toBeVisible();
  });
});
