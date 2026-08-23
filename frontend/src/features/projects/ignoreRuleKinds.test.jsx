import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MotionConfig } from "motion/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { REDUCED_MOTION_POLICY } from "../../app/providers";
import { createQueryClient } from "../../app/queryClient";
import { ProjectSettings } from "./components/ProjectSettings";

/**
 * A rule can name one advisory or a family of packages, and the form has to
 * make the difference legible before somebody writes one. `@acme/*` covers
 * every advisory that will ever be written about that scope, which is a much
 * larger statement than silencing one CVE.
 */

function page(overrides = {}) {
  return {
    data: { id: 7, name: "checkout-api" },
    rules: [],
    thresholds: { direct: "high", transitive: "critical", epss: null },
    profiles: {
      chosen: null,
      applies: null,
      applies_name: null,
      following_default: false,
      available: [],
    },
    policy_file: { present: false, updated_at: null, error: null, ignores: [] },
    api_keys: [],
    webhook: { url: null, kind: null, last_sent_at: null, last_error: null },
    can_use_rules: true,
    can_use_webhooks: true,
    ...overrides,
  };
}

function renderSettings(overrides) {
  const client = createQueryClient({ queries: { retry: false } });
  render(
    <QueryClientProvider client={client}>
      <MotionConfig reducedMotion={REDUCED_MOTION_POLICY}>
        <MemoryRouter>
          <ProjectSettings page={page(overrides)} projectId={7} />
        </MemoryRouter>
      </MotionConfig>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("choosing what an ignore rule names", () => {
  it("starts on the narrower of the two", async () => {
    renderSettings();

    expect(await screen.findByLabelText("Ignore")).toHaveValue("advisory");
    expect(screen.getByLabelText("Advisory")).toBeVisible();
  });

  it("relabels the field and the button for a package rule", async () => {
    const user = userEvent.setup();
    renderSettings();

    await user.selectOptions(await screen.findByLabelText("Ignore"), "package");

    expect(screen.getByLabelText("Package")).toHaveAttribute("placeholder", "@acme/*");
    expect(screen.getByRole("button", { name: "Ignore these packages" })).toBeVisible();
  });

  it("clears a half-typed advisory id when the kind changes", async () => {
    // Otherwise `CVE-2021-23337` stays in the box and is submitted as a
    // package glob, which would silence nothing and look like a bug.
    const user = userEvent.setup();
    renderSettings();

    await user.type(await screen.findByLabelText("Advisory"), "CVE-2021");
    await user.selectOptions(screen.getByLabelText("Ignore"), "package");

    expect(screen.getByLabelText("Package")).toHaveValue("");
  });

  it("sends the chosen kind", async () => {
    const user = userEvent.setup();
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { id: 1, identifier: "@acme/*", kind: "package" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    renderSettings();

    await user.selectOptions(await screen.findByLabelText("Ignore"), "package");
    await user.type(screen.getByLabelText("Package"), "@acme/*");
    await user.type(screen.getByLabelText("Why"), "internal mirror of a public name");
    await user.click(screen.getByRole("button", { name: "Ignore these packages" }));

    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    const body = JSON.parse(fetchSpy.mock.calls.at(-1)[1].body);
    expect(body).toMatchObject({ identifier: "@acme/*", kind: "package" });
  });

  it("marks a package rule in the list, and only a package rule", async () => {
    renderSettings({
      rules: [
        {
          id: 1,
          identifier: "CVE-2021-23337",
          kind: "advisory",
          reason: "not reachable from our code",
          created_by_email: "dev@example.com",
          created_at: "2026-08-01T10:00:00Z",
          overridden_at: null,
        },
        {
          id: 2,
          identifier: "@acme/*",
          kind: "package",
          reason: "internal mirror of a public name",
          created_by_email: "dev@example.com",
          created_at: "2026-08-01T10:00:00Z",
          overridden_at: null,
        },
      ],
    });

    expect(await screen.findByText("@acme/*")).toBeVisible();
    expect(screen.getAllByText("every advisory")).toHaveLength(1);
  });
});
