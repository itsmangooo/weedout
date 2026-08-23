import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createQueryClient } from "../app/queryClient";
import { CliAuthPage } from "./CliAuthPage";

/**
 * Approving a machine that ran `weedout auth`.
 *
 * The page has one job beyond the two buttons: give somebody enough to tell
 * their own terminal from a request they did not make. A page that just says
 * "Approve?" trains people to click yes, and a confirmation nobody reads is
 * worth less than no confirmation, because it looks like a control.
 *
 * So these mostly assert what is *shown*, not what is clicked.
 */

function pending(overrides = {}) {
  return {
    data: {
      code: "HXKR-2FQP",
      device_label: "dev-laptop",
      ip_address: "203.0.113.9",
      requested_at: "2026-08-24T10:00:00Z",
      expires_at: "2026-08-24T10:10:00Z",
      ...overrides,
    },
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderPage({ url = "/cli-auth?code=HXKR-2FQP", fetchImpl } = {}) {
  vi.spyOn(globalThis, "fetch").mockImplementation(
    fetchImpl ?? (() => Promise.resolve(json(pending()))),
  );
  const client = createQueryClient({ queries: { retry: false } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[url]}>
        <Routes>
          <Route element={<CliAuthPage />} path="/cli-auth" />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("approving a machine", () => {
  it("shows the code, because that is what the person is comparing", async () => {
    renderPage();

    expect(await screen.findByText("HXKR-2FQP")).toBeVisible();
  });

  it("shows what the machine said about itself, and where it came from", async () => {
    renderPage();

    expect(await screen.findByText("dev-laptop")).toBeVisible();
    expect(screen.getByText("203.0.113.9")).toBeVisible();
  });

  it("says those two are not proof of anything", async () => {
    // Without this the label reads as verified, which is exactly backwards:
    // it is attacker-controlled text on a page asking for a credential.
    renderPage();

    expect(await screen.findByText(/neither is proof/i)).toBeVisible();
  });

  it("says what approving actually grants", async () => {
    renderPage();

    expect(await screen.findByText(/cannot read your findings/i)).toBeVisible();
  });

  it("offers refusing as prominently as approving", async () => {
    // Somebody who does not recognise the request needs that button to be as
    // easy to find as the other one.
    renderPage();

    expect(await screen.findByRole("button", { name: /Yes, sign it in/ })).toBeVisible();
    expect(screen.getByRole("button", { name: /Not me/ })).toBeVisible();
  });

  it("asks for the code when the URL does not carry one", async () => {
    renderPage({ url: "/cli-auth" });

    expect(await screen.findByLabelText("Code")).toBeVisible();
  });

  it("posts the approval and confirms it", async () => {
    const user = userEvent.setup();
    const calls = [];
    renderPage({
      fetchImpl: (input) => {
        const url = String(input?.url ?? input);
        calls.push(url);
        if (url.includes("/approve")) return Promise.resolve(json({ data: { approved: true } }));
        return Promise.resolve(json(pending()));
      },
    });

    await user.click(await screen.findByRole("button", { name: /Yes, sign it in/ }));

    expect(await screen.findByText(/Your terminal has the credential/)).toBeVisible();
    await waitFor(() => expect(calls.some((url) => url.includes("/approve"))).toBe(true));
  });

  it("says nothing was granted when refused", async () => {
    const user = userEvent.setup();
    renderPage({
      fetchImpl: (input) => {
        const url = String(input?.url ?? input);
        if (url.includes("/deny")) return Promise.resolve(json({ data: { denied: true } }));
        return Promise.resolve(json(pending()));
      },
    });

    await user.click(await screen.findByRole("button", { name: /Not me/ }));

    expect(await screen.findByText(/no credential was created/)).toBeVisible();
  });

  it("explains an expired code rather than showing an empty page", async () => {
    renderPage({
      fetchImpl: () =>
        Promise.resolve(
          json(
            {
              code: "NOT_FOUND",
              message:
                "That code is not waiting for approval. It may have expired — codes last "
                + "ten minutes. Run the command again to get a new one.",
            },
            404,
          ),
        ),
    });

    expect(await screen.findByText(/isn.t waiting/i)).toBeVisible();
    expect(await screen.findByText(/Run the command again/)).toBeVisible();
  });

  it("does not render a machine label as markup", async () => {
    // Attacker-controlled text on the page that grants a credential.
    renderPage({
      fetchImpl: () =>
        Promise.resolve(json(pending({ device_label: "<img src=x onerror=alert(1)>" }))),
    });

    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeVisible();
    expect(document.querySelector("img")).toBeNull();
  });
});
