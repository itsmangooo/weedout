import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createQueryClient } from "../app/queryClient";
import { CliPage } from "./CliPage";

/**
 * The /cli page.
 *
 * It is a marketing page, so most of it is prose nobody should pin down in a
 * test. What is worth pinning is the part that goes stale: the commands it
 * claims exist, and the distinction between the two credentials — which is the
 * thing people get wrong, and getting it wrong means putting the powerful one
 * in CI.
 */

function facts() {
  return {
    data: {
      repo: "itsmangooo/weedout-cli",
      release: { available: false, version: "", published_at: "", notes_url: "", assets: [] },
      go_module: {
        available: true,
        module_path: "github.com/itsmangooo/weedout-cli",
        go_version: "1.22",
        dependencies: [],
      },
    },
  };
}

function renderCli() {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify(facts()), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
  render(
    <QueryClientProvider client={createQueryClient({ queries: { retry: false } })}>
      <MemoryRouter>
        <CliPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("the CLI page", () => {
  it("marks the CLI as work in progress", async () => {
    renderCli();

    expect(await screen.findByText(/Command line · Work in progress/)).toBeVisible();
  });

  it("numbers its sections without repeating one", async () => {
    // They drifted the moment two sections were inserted, which is why the
    // numbers are derived from the render order now.
    renderCli();

    await screen.findByRole("heading", { name: /Install it/ });
    const numbered = screen
      .getAllByText(/^\d\d$/)
      .filter((node) => node.classList.contains("eyebrow"))
      .map((node) => node.textContent);

    expect(numbered).toEqual([...new Set(numbered)]);
    expect(numbered).toEqual(["01", "02", "03", "04", "05", "06"]);
  });

  it("shows how a machine is signed in", async () => {
    renderCli();

    const heading = await screen.findByRole("heading", { name: /Nothing to copy and paste/ });
    const section = heading.closest("section");

    // It appears in the transcript, the command list and the prose, which is
    // the point -- scoped to the section rather than asserted as unique.
    expect(within(section).getAllByText(/weedout auth/).length).toBeGreaterThan(0);
    expect(within(section).getByText(/HXKR-2FQP/)).toBeVisible();
  });

  it("says what each credential cannot do, not just what it can", async () => {
    // The half that matters. "Can create projects" is not the reason to keep
    // it off a CI runner; "cannot read a finding" is why the other one is
    // safe there.
    renderCli();

    expect(await screen.findByText(/Cannot read a single finding/)).toBeVisible();
    expect(screen.getByText(/Cannot reach another project/)).toBeVisible();
  });

  it("explains that committed rules travel with the scan", async () => {
    // The least discoverable thing the binary does: a file you commit changes
    // what a scan reports, with nothing to configure.
    renderCli();

    expect(await screen.findByRole("heading", { name: /reviewed like code/ })).toBeVisible();
    expect(screen.getByText(/lockfile.s directory upward/)).toBeVisible();
  });

  it("says what a rule cannot silence", async () => {
    renderCli();

    expect(
      await screen.findByText(/Known exploitation and malware are reported whatever the file says/),
    ).toBeVisible();
  });

  it("lists the reading commands including the newer ones", async () => {
    renderCli();

    await screen.findByRole("heading", { name: /without opening it/ });
    for (const command of ["weedout profiles", "weedout findings --show filtered"]) {
      expect(screen.getByText(command)).toBeVisible();
    }
  });

  it("shows the package-glob form of an ignore rule", async () => {
    renderCli();

    await screen.findByRole("heading", { name: /without opening it/ });
    expect(screen.getByText(/weedout rules ignore --package/)).toBeVisible();
  });

  it("still claims no dependencies when there are none", async () => {
    // The claim is read live from go.mod. If the shape of that response
    // changes, this section is where it shows.
    renderCli();

    const section = (await screen.findByRole("heading", { name: /What it brings with it/ }))
      .closest("section");
    expect(within(section).getByText("None.")).toBeVisible();
  });
});
