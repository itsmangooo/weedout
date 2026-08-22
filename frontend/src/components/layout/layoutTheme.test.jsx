import { QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { createQueryClient } from "../../app/queryClient";
import { AppShell } from "./AppShell";
import { FoundationLayout } from "./FoundationLayout";

/** AppShell reads the current user for its nav, so it needs a query client. */
function renderShell(ui) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify({ data: { authenticated: false, session_state: "anonymous", user: null } }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );

  return render(
    <QueryClientProvider client={createQueryClient({ queries: { retry: false } })}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/**
 * Which palette each shell pins.
 *
 * This used to be asserted against server-rendered HTML. The markup moved here
 * with the pages, so the assertion did too — the property is unchanged: a
 * marketing page looks the way it was designed to whatever the visitor has
 * saved, and the application respects their choice.
 */
describe("layout theming", () => {
  it("pins the marketing palette on public pages", () => {
    const { container } = renderShell(
      <FoundationLayout>
        <p>content</p>
      </FoundationLayout>,
    );

    // Somebody with light mode saved still gets the designed look on a page
    // they might screenshot or share.
    expect(container.querySelector("[data-theme='public']")).not.toBeNull();
  });

  it("leaves the palette to the visitor inside the application", () => {
    const { container } = renderShell(<AppShell />);

    expect(container.querySelector("[data-theme='app']")).not.toBeNull();
    expect(container.querySelector("[data-theme='public']")).toBeNull();
  });
});
