import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createQueryClient } from "../../app/queryClient";
import { UsedBy } from "./components/UsedBy";

/**
 * The trust section on the landing page.
 *
 * Every name here is a company that ticked a box and was then checked. The
 * component renders what the server hands it and has no opinion about who
 * qualifies — which is the point: one place decides, and it is the one with
 * the database.
 *
 * What these mostly cover is the absent case. An empty trust section is worse
 * than none, and a padded one is a lie on the page that is meant to be the
 * honest part.
 */

function renderUsedBy(usedBy) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify({ data: { used_by: usedBy } }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
  render(
    <QueryClientProvider client={createQueryClient({ queries: { retry: false } })}>
      <UsedBy />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("who uses this", () => {
  it("names the companies it was given", async () => {
    renderUsedBy([
      { name: "Acme Ltd", website: "https://acme.example" },
      { name: "Globex", website: null },
    ]);

    expect(await screen.findByText("Acme Ltd")).toBeVisible();
    expect(screen.getByText("Globex")).toBeVisible();
  });

  it("renders nothing at all when there is nobody to name", async () => {
    // Not an empty heading with a gap under it. A trust section with no names
    // is worse than no trust section.
    const { container } = render(
      <QueryClientProvider client={createQueryClient({ queries: { retry: false } })}>
        <UsedBy />
      </QueryClientProvider>,
    );
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { used_by: [] } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    expect(container.querySelector(".used-by")).toBeNull();
  });

  it("renders nothing when the landing data fails to load", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));
    const { container } = render(
      <QueryClientProvider client={createQueryClient({ queries: { retry: false } })}>
        <UsedBy />
      </QueryClientProvider>,
    );

    expect(container.querySelector(".used-by")).toBeNull();
  });

  it("links a company that gave a website, and does not invent one", async () => {
    renderUsedBy([
      { name: "Acme Ltd", website: "https://acme.example" },
      { name: "Globex", website: null },
    ]);

    const linked = await screen.findByRole("link", { name: "Acme Ltd" });
    expect(linked).toHaveAttribute("href", "https://acme.example");
    expect(screen.queryByRole("link", { name: "Globex" })).toBeNull();
  });

  it("does not pass link equity or a referrer to a customer's site", async () => {
    // These are business relationships, not endorsements of their SEO, and a
    // referrer would tell their analytics that someone came from a
    // vulnerability scanner's front page.
    renderUsedBy([{ name: "Acme Ltd", website: "https://acme.example" }]);

    const linked = await screen.findByRole("link", { name: "Acme Ltd" });
    expect(linked.getAttribute("rel")).toContain("nofollow");
    expect(linked.getAttribute("rel")).toContain("noopener");
  });
});
