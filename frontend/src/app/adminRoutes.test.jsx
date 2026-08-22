import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MotionConfig } from "motion/react";
import { RouterProvider } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { currentUserQueryKey } from "../features/auth/hooks/useCurrentUser";
import { REDUCED_MOTION_POLICY } from "./providers";
import { createQueryClient } from "./queryClient";
import { createAppRouter } from "./router";

/**
 * The admin panel's routes.
 *
 * Two things are worth a test here and the rest is display. The first is that
 * a signed-in non-admin is refused by the client guard as well as by the
 * server. The second is the send confirmation: it is the last thing between a
 * textarea and every account on the platform, and its whole value is that the
 * count on screen is the count that gets used.
 */

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function authResponse({ isAdmin = true } = {}) {
  return {
    data: {
      authenticated: true,
      session_state: "authenticated",
      user: {
        id: 1,
        email: "root@example.com",
        is_admin: isAdmin,
        tier: "pro",
        account_state: "active",
      },
    },
  };
}

const COMPOSER = {
  data: {
    variables: { "{{user_email}}": "The recipient's email address." },
    confirm_threshold: 5,
    audiences: [
      { value: "one", label: "One address" },
      { value: "pro", label: "Pro users" },
      { value: "free", label: "Free users" },
      { value: "all", label: "Every user" },
    ],
    sends: [],
  },
};

function renderAdmin(path, { isAdmin = true } = {}) {
  const client = createQueryClient({ queries: { retry: false } });
  client.setQueryData(currentUserQueryKey, authResponse({ isAdmin }).data);

  const router = createAppRouter({ initialEntries: [path] });
  render(
    <QueryClientProvider client={client}>
      <MotionConfig reducedMotion={REDUCED_MOTION_POLICY}>
        <RouterProvider router={router} />
      </MotionConfig>
    </QueryClientProvider>,
  );
  return { client, router };
}

describe("the admin guard", () => {
  it("refuses a signed-in non-admin without calling any admin endpoint", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((path) => {
      if (path === "/api/internal/auth/me") {
        return Promise.resolve(response(authResponse({ isAdmin: false })));
      }
      return Promise.resolve(response({ data: {} }));
    });

    renderAdmin("/admin/users", { isAdmin: false });

    expect(
      await screen.findByRole("heading", { name: "Administrator access required" }),
    ).toBeInTheDocument();

    // The guard is presentation, not enforcement — but it should not go
    // fetching admin data it has already decided not to show.
    const admin = fetchMock.mock.calls.filter(([url]) =>
      String(url).startsWith("/api/internal/admin"),
    );
    expect(admin).toEqual([]);
  });
});

describe("the campaign send confirmation", () => {
  async function openComposer() {
    const user = userEvent.setup();
    renderAdmin("/admin/email");

    expect(await screen.findByRole("heading", { name: "Compose", level: 1 })).toBeInTheDocument();
    return user;
  }

  async function fillDraft(user) {
    await user.type(screen.getByLabelText("Subject"), "Scheduled maintenance");
    await user.type(screen.getByLabelText("Body"), "We are moving the database on Friday.");
    await user.click(screen.getByRole("button", { name: /Preview and count/ }));
  }

  it("sends the count the preview showed, not a fresh one", async () => {
    let sent = null;

    vi.spyOn(globalThis, "fetch").mockImplementation((path, options = {}) => {
      if (path === "/api/internal/admin/email") return Promise.resolve(response(COMPOSER));
      if (path === "/api/internal/admin/email/preview") {
        return Promise.resolve(
          response({
            data: {
              audience: "all",
              audience_label: "Every user",
              count: 47,
              needs_confirmation: true,
              without_projects: 0,
              sample_email: "first@example.com",
              subject: "Scheduled maintenance",
              body: "We are moving the database on Friday.",
            },
          }),
        );
      }
      if (path === "/api/internal/admin/email/send") {
        sent = JSON.parse(options.body);
        return Promise.resolve(
          response({ data: { batch_id: "b1", attempted: 47, sent: 47, failed: 0, errors: [] } }),
        );
      }
      return Promise.resolve(response(authResponse()));
    });

    const user = await openComposer();
    await fillDraft(user);

    // The button states the number it is about to act on.
    const send = await screen.findByRole("button", { name: "Send to 47 people" });
    await user.click(send);

    await waitFor(() => expect(sent).not.toBeNull());
    expect(sent.confirmed_count).toBe(47);
  });

  it("clears the confirmation when the server says the audience moved", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((path) => {
      if (path === "/api/internal/admin/email") return Promise.resolve(response(COMPOSER));
      if (path === "/api/internal/admin/email/preview") {
        return Promise.resolve(
          response({
            data: {
              audience: "all",
              audience_label: "Every user",
              count: 47,
              needs_confirmation: true,
              without_projects: 0,
              sample_email: "first@example.com",
              subject: "Scheduled maintenance",
              body: "We are moving the database on Friday.",
            },
          }),
        );
      }
      if (path === "/api/internal/admin/email/send") {
        return Promise.resolve(
          response(
            {
              error: {
                code: "AUDIENCE_CHANGED",
                message:
                  "The audience changed while you were reading it: you confirmed 47 " +
                  "recipients, and it is now 48. Nothing was sent. Check the count and " +
                  "confirm again.",
              },
            },
            409,
          ),
        );
      }
      return Promise.resolve(response(authResponse()));
    });

    const user = await openComposer();
    await fillDraft(user);
    await user.click(await screen.findByRole("button", { name: "Send to 47 people" }));

    expect(await screen.findByText(/it is now 48/)).toBeInTheDocument();
    expect(screen.getByText("Nothing was sent")).toBeInTheDocument();

    // The button offering 47 is gone: the only way forward is to count again,
    // which is what the message tells them to do.
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Send to 47 people" })).not.toBeInTheDocument(),
    );
    expect(screen.getByRole("button", { name: /Preview and count/ })).toBeInTheDocument();
  });

  it("drops the confirmation as soon as the message is edited", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((path) => {
      if (path === "/api/internal/admin/email") return Promise.resolve(response(COMPOSER));
      if (path === "/api/internal/admin/email/preview") {
        return Promise.resolve(
          response({
            data: {
              audience: "all",
              audience_label: "Every user",
              count: 47,
              needs_confirmation: true,
              without_projects: 0,
              sample_email: "first@example.com",
              subject: "Scheduled maintenance",
              body: "We are moving the database on Friday.",
            },
          }),
        );
      }
      return Promise.resolve(response(authResponse()));
    });

    const user = await openComposer();
    await fillDraft(user);
    expect(await screen.findByRole("button", { name: "Send to 47 people" })).toBeInTheDocument();

    // A confirmation showing a count for text nobody can see any more is not a
    // confirmation.
    await user.type(screen.getByLabelText("Subject"), " (revised)");

    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Send to 47 people" })).not.toBeInTheDocument(),
    );
  });
});
