import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createQueryClient } from "../../app/queryClient";
import { RuleProfiles } from "./components/RuleProfiles";

/**
 * A profile is a policy document under a name, so what the interface has to get
 * right is not the editing — a textarea edits text — but saying which rules
 * apply and where they came from.
 *
 * Three facts sit in one row and none may read as another: what the profile is
 * called, what a pipeline types, and whether it is the one that applies when
 * nobody chose.
 */

function profile(overrides = {}) {
  return {
    id: 1,
    name: "Production",
    slug: "production",
    description: "Everything customer-facing.",
    document: "severity:\n  direct: high\n",
    is_default: true,
    used_by: 0,
    updated_at: "2026-08-20T10:00:00Z",
    ...overrides,
  };
}

function renderProfiles({ profiles = [], meta = {} } = {}) {
  const client = createQueryClient({ queries: { retry: false } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <RuleProfiles
          meta={{ limit: 20, can_use_profiles: true, ...meta }}
          profiles={profiles}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("rule profiles", () => {
  it("offers the plan rather than a broken control on Free", () => {
    renderProfiles({ meta: { can_use_profiles: false } });

    expect(screen.getByText(/part of the Pro plan/i)).toBeVisible();
    expect(screen.queryByLabelText("New profile")).toBeNull();
  });

  it("says what an account with no profiles is running", () => {
    // "No profiles" alone reads as something being wrong. It is a normal state
    // and the built-in rules still apply.
    renderProfiles();

    expect(screen.getByText(/built-in rules/)).toBeVisible();
  });

  it("shows the slug a pipeline types, not just the name", () => {
    renderProfiles({ profiles: [profile()] });

    expect(screen.getByText("Production")).toBeVisible();
    expect(screen.getByText("production")).toBeVisible();
  });

  it("marks the account default", () => {
    renderProfiles({ profiles: [profile()] });

    expect(screen.getByText("account default")).toBeVisible();
  });

  it("counts chosen projects in the singular and the plural", () => {
    renderProfiles({
      profiles: [
        profile({ id: 1, name: "One", slug: "one", used_by: 1 }),
        profile({ id: 2, name: "Two", slug: "two", used_by: 3, is_default: false }),
      ],
    });

    expect(screen.getByText(/Chosen by 1 project\./)).toBeVisible();
    expect(screen.getByText(/Chosen by 3 projects\./)).toBeVisible();
  });

  it("does not offer to make the default the default", () => {
    renderProfiles({ profiles: [profile()] });

    expect(screen.queryByRole("button", { name: "Make it the default" })).toBeNull();
  });

  it("opens one profile at a time", async () => {
    const user = userEvent.setup();
    renderProfiles({
      profiles: [
        profile({ id: 1, name: "One", slug: "one" }),
        profile({ id: 2, name: "Two", slug: "two", is_default: false }),
      ],
    });

    await user.click(screen.getAllByRole("button", { name: "Edit" })[0]);

    expect(screen.getByLabelText("Rules")).toBeVisible();
    expect(screen.getAllByRole("button", { name: "Edit" })).toHaveLength(1);
  });

  it("sends the edited document", async () => {
    const user = userEvent.setup();
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ data: profile() }));
    renderProfiles({ profiles: [profile()] });

    await user.click(screen.getByRole("button", { name: "Edit" }));
    const rules = screen.getByLabelText("Rules");
    await user.clear(rules);
    await user.type(rules, "severity:{enter}  direct: low");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    const body = JSON.parse(fetchSpy.mock.calls.at(-1)[1].body);
    expect(body.document).toContain("direct: low");
  });

  it("warns that renaming breaks a pipeline", async () => {
    // The slug is what --profile matches, so a rename is not a cosmetic edit.
    const user = userEvent.setup();
    renderProfiles({ profiles: [profile()] });

    await user.click(screen.getByRole("button", { name: "Edit" }));

    expect(screen.getByText(/start failing/)).toBeVisible();
  });

  it("says what deleting one does to the projects using it", async () => {
    const user = userEvent.setup();
    renderProfiles({ profiles: [profile({ used_by: 2 })] });

    await user.click(screen.getByRole("button", { name: "Edit" }));

    expect(screen.getByText(/moves any project using this profile/)).toBeVisible();
  });

  it("shows the server's reason when a document will not parse", async () => {
    const user = userEvent.setup();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          error: "INVALID_PROFILE",
          message: "The policy file is not valid YAML: while parsing a flow node",
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      ),
    );
    renderProfiles({ profiles: [profile()] });

    await user.click(screen.getByRole("button", { name: "Edit" }));
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(await screen.findByText(/not valid YAML/)).toBeVisible();
  });

  it("stops offering a new one at the limit", () => {
    renderProfiles({
      profiles: [profile(), profile({ id: 2, slug: "two", is_default: false })],
      meta: { limit: 2 },
    });

    expect(screen.queryByLabelText("New profile")).toBeNull();
    expect(screen.getByText(/which is the limit/)).toBeVisible();
  });
});
