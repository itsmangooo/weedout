import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createQueryClient } from "../../app/queryClient";
import { THEME_STORAGE_KEY } from "../../features/theme/useTheme";
import { DashboardShell } from "./DashboardShell";
import { FoundationLayout } from "./FoundationLayout";

/** Both shells read the current user for their nav, so they need a client. */
function renderShell(ui) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(
      JSON.stringify({ data: { authenticated: false, session_state: "anonymous", user: null } }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  );

  return render(
    <QueryClientProvider client={createQueryClient({ queries: { retry: false } })}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/**
 * One theme for the whole product, chosen by the reader.
 *
 * Each shell used to pin its own palette on a wrapper div â€” `"app"` on the
 * dashboard, `"public"` on the marketing pages. That is why the dashboard
 * rendered as a dark island on a cream page: the attribute was on an inner
 * element, so the body kept the other palette and showed around the edges.
 *
 * The attribute now lives on <html> and nowhere else, which is also what lets
 * `theme-boot.js` set it before the first paint.
 */
describe("layout theming", () => {
  beforeEach(() => {
    window.localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
  });

  afterEach(() => {
    document.documentElement.removeAttribute("data-theme");
  });

  it("pins no palette on the marketing shell", () => {
    const { container } = renderShell(
      <FoundationLayout>
        <p>content</p>
      </FoundationLayout>,
    );

    expect(container.querySelector("[data-theme]")).toBeNull();
  });

  it("pins no palette on the application shell", () => {
    const { container } = renderShell(<DashboardShell />);

    expect(container.querySelector("[data-theme]")).toBeNull();
  });

  it("keeps panel theme controls out of the fixed public shell", () => {
    renderShell(<FoundationLayout><p>content</p></FoundationLayout>);
    expect(screen.queryByRole("radiogroup", { name: "Colour theme" })).not.toBeInTheDocument();
  });

  it("writes the panel reader's choice to the document, not to a wrapper", async () => {
    const user = userEvent.setup();
    const { container } = renderShell(<DashboardShell />);

    await user.click(screen.getAllByRole("radio", { name: "Dark" })[0]);

    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(container.querySelector("[data-theme]")).toBeNull();
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
  });

  it("resolves 'match system' to a concrete palette", async () => {
    /* The stylesheet has no rule for `data-theme="system"`, so the choice has
       to be resolved before it is written â€” otherwise picking it would
       silently mean light whatever the machine says. */
    const user = userEvent.setup();
    renderShell(<DashboardShell />);

    await user.click(screen.getAllByRole("radio", { name: "Dark" })[0]);
    expect(document.documentElement.dataset.theme).toBe("dark");

    await user.click(screen.getAllByRole("radio", { name: "Match system" })[0]);

    // jsdom reports no dark preference, so this resolves to light.
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("system");
  });

  it("starts on light for a reader who has never chosen", () => {
    renderShell(<DashboardShell />);

    expect(screen.getAllByRole("radio", { name: "Light" })[0]).toHaveAttribute(
      "aria-checked",
      "true",
    );
  });

  it("restores a saved choice on the next render", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "dark");

    renderShell(<DashboardShell />);

    expect(screen.getAllByRole("radio", { name: "Dark" })[0]).toHaveAttribute(
      "aria-checked",
      "true",
    );
  });
});
