import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { currentUserQueryKey } from "../../features/auth/hooks/useCurrentUser";
import { createQueryClient } from "../../app/queryClient";
import { AppShell } from "./AppShell";
import { FoundationLayout } from "./FoundationLayout";

/**
 * Every destination is reachable at every width.
 *
 * The header used to drop all but its last link below 40rem with a
 * `display: none`, which is not a responsive layout — it is /cli and /docs
 * becoming unreachable on a phone. CSS media queries cannot be asserted in
 * jsdom, so what is pinned here is the thing that actually broke: the narrow
 * layout must *contain* the same destinations as the wide one, not fewer.
 */

function authResponse(overrides = {}) {
  return {
    authenticated: true,
    session_state: "authenticated",
    user: {
      id: 1,
      email: "dev@example.com",
      is_admin: false,
      tier: "free",
      account_state: "active",
      ...overrides,
    },
  };
}

function renderShell(ui, { user = authResponse() } = {}) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify({ data: user }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );

  const client = createQueryClient({ queries: { retry: false } });
  client.setQueryData(currentUserQueryKey, user);

  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/dashboard"]}>
        <Routes>
          <Route element={ui} path="*" />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function hrefsIn(scope) {
  return [...scope.querySelectorAll("a[href]")].map((node) => node.getAttribute("href"));
}

describe("the public header", () => {
  it("offers the CLI, docs and pricing at full width", () => {
    renderShell(
      <FoundationLayout>
        <p>content</p>
      </FoundationLayout>,
      { user: { authenticated: false, session_state: "anonymous", user: null } },
    );

    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(hrefsIn(nav)).toEqual(["/cli", "/docs", "/pricing"]);
  });

  it("keeps every one of them in the narrow menu", async () => {
    const user = userEvent.setup();
    renderShell(
      <FoundationLayout>
        <p>content</p>
      </FoundationLayout>,
      { user: { authenticated: false, session_state: "anonymous", user: null } },
    );

    await user.click(screen.getByRole("button", { name: "Open menu" }));

    const menu = screen.getByRole("navigation", { name: "Main, expanded" });
    const wide = screen.getByRole("navigation", { name: "Main" });
    expect(hrefsIn(menu)).toEqual(hrefsIn(wide));
  });

  it("closes the menu with Escape", async () => {
    const user = userEvent.setup();
    renderShell(
      <FoundationLayout>
        <p>content</p>
      </FoundationLayout>,
      { user: { authenticated: false, session_state: "anonymous", user: null } },
    );

    await user.click(screen.getByRole("button", { name: "Open menu" }));
    expect(screen.getByRole("navigation", { name: "Main, expanded" })).toBeInTheDocument();

    await user.keyboard("{Escape}");

    await waitFor(() =>
      expect(screen.queryByRole("navigation", { name: "Main, expanded" })).not.toBeInTheDocument(),
    );
  });

  it("offers a way in to somebody signed out, and the app to somebody signed in", () => {
    const { unmount } = renderShell(
      <FoundationLayout>
        <p>content</p>
      </FoundationLayout>,
      { user: { authenticated: false, session_state: "anonymous", user: null } },
    );

    expect(screen.getByRole("link", { name: "Start free" })).toHaveAttribute("href", "/signup");
    unmount();

    renderShell(
      <FoundationLayout>
        <p>content</p>
      </FoundationLayout>,
    );

    expect(screen.getByRole("link", { name: "Dashboard" })).toHaveAttribute("href", "/dashboard");
    expect(screen.queryByRole("link", { name: "Start free" })).not.toBeInTheDocument();
  });
});

describe("the application sidebar", () => {
  it("reaches the CLI page, which used to exist only on the marketing site", () => {
    renderShell(<AppShell />);

    const nav = screen.getByRole("navigation", { name: "Application" });
    expect(hrefsIn(nav)).toContain("/cli");
  });

  it("offers every section of the product", () => {
    renderShell(<AppShell />);

    const nav = screen.getByRole("navigation", { name: "Application" });
    expect(hrefsIn(nav)).toEqual([
      "/dashboard",
      "/alerts",
      "/targets/new",
      "/billing",
      "/cli",
      "/settings",
    ]);
  });

  it("marks future analysis modules as planned instead of linking to fake screens", () => {
    renderShell(<AppShell />);

    for (const label of ["Source code", "Secrets", "CI & config"]) {
      const module = screen.getByText(label).closest(".app-shell__nav-link");
      expect(module).toHaveAttribute("aria-disabled", "true");
      expect(module).not.toHaveAttribute("href");
    }
  });

  it("shows the admin link only to an administrator", () => {
    const { unmount } = renderShell(<AppShell />);
    expect(screen.queryByRole("link", { name: /Admin/ })).not.toBeInTheDocument();
    unmount();

    renderShell(<AppShell />, { user: authResponse({ is_admin: true }) });
    expect(screen.getByRole("link", { name: /Admin/ })).toHaveAttribute("href", "/admin");
  });

  it("offers a way to sign out", async () => {
    /* There was none for the whole of the React migration: `signOut` existed
       in the API layer and nothing called it. */
    const user = userEvent.setup();
    const fetchMock = vi.spyOn(globalThis, "fetch");

    renderShell(<AppShell />);
    await user.click(screen.getByRole("button", { name: /Sign out/ }));

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([url, options]) =>
            String(url).includes("/api/internal/auth/logout") && options?.method === "POST",
        ),
      ).toBe(true),
    );
  });

  it("puts the whole navigation in one panel the narrow layout can disclose", async () => {
    /* The narrow layout hides `.app-sidebar__panel` and shows it again on the
       disclosure. Anything left outside that panel would be missing from the
       phone layout entirely, which is what happened to the account block. */
    const user = userEvent.setup();
    const { container } = renderShell(<AppShell />);

    await user.click(screen.getByRole("button", { name: "Open navigation" }));

    const panel = container.querySelector(".app-sidebar__panel");
    expect(panel).not.toBeNull();
    expect(within(panel).getByRole("navigation", { name: "Application" })).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: /Sign out/ })).toBeInTheDocument();
    expect(within(panel).getByRole("radiogroup", { name: "Colour theme" })).toBeInTheDocument();
  });
});
