import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MotionConfig } from "motion/react";
import { RouterProvider } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { REDUCED_MOTION_POLICY } from "../app/providers";
import { createQueryClient } from "../app/queryClient";
import { createAppRouter } from "../app/router";
import { safeNext } from "../api/authActions";

/**
 * The sign-in screens.
 *
 * These are the only screens that take a credential, so the cases worth
 * writing down are the ones where getting it wrong has a cost: sending a
 * password somewhere it should not go, treating a second factor as a failure,
 * or reporting something different for a known and an unknown address.
 */

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const ANONYMOUS = {
  data: { authenticated: false, session_state: "anonymous", user: null },
};

function signedIn(email = "dev@example.com") {
  return {
    data: {
      authenticated: true,
      session_state: "authenticated",
      user: { id: 7, email, is_admin: false, tier: "free", account_state: "active" },
    },
  };
}

function renderRoute(path) {
  const client = createQueryClient({ queries: { retry: false } });
  const router = createAppRouter({ initialEntries: [path] });
  render(
    <QueryClientProvider client={client}>
      <MotionConfig reducedMotion={REDUCED_MOTION_POLICY}>
        <RouterProvider router={router} />
      </MotionConfig>
    </QueryClientProvider>,
  );
  return router;
}

/** Records every request so a test can assert on what was actually sent. */
function mockFetch(handler) {
  const calls = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (url, options = {}) => {
    const path = typeof url === "string" ? url : url.toString();
    calls.push({ path, options });
    return handler(path, options) ?? response(ANONYMOUS);
  });
  return calls;
}

beforeEach(() => {
  document.cookie = "weedout_csrf=test-token";
});

describe("the sign-in page", () => {
  it("shows labelled fields rather than placeholder-only ones", async () => {
    mockFetch(() => response(ANONYMOUS));
    renderRoute("/login");

    expect(await screen.findByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });

  it("posts the credentials and attaches the CSRF header", async () => {
    const calls = mockFetch((path) =>
      path.includes("/auth/login") ? response(signedIn()) : response(ANONYMOUS),
    );
    renderRoute("/login");

    await userEvent.type(await screen.findByLabelText("Email"), "dev@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => {
      expect(calls.some((call) => call.path.includes("/auth/login"))).toBe(true);
    });

    const login = calls.find((call) => call.path.includes("/auth/login"));
    expect(login.options.method).toBe("POST");
    // Without this header the server refuses, which is what stops any page on
    // the internet posting a login on somebody's behalf.
    expect(new Headers(login.options.headers).get("X-CSRF-Token")).toBe("test-token");
    expect(JSON.parse(login.options.body)).toMatchObject({
      email: "dev@example.com",
      password: "correct-horse-battery",
    });
  });

  it("reports a rejected password without clearing the email", async () => {
    mockFetch((path) =>
      path.includes("/auth/login")
        ? response(
            { error: { code: "INVALID_CREDENTIALS", message: "Wrong email or password." } },
            401,
          )
        : response(ANONYMOUS),
    );
    renderRoute("/login");

    await userEvent.type(await screen.findByLabelText("Email"), "dev@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Wrong email or password.");
    // Retyping the address after a typo in the password is pure friction.
    expect(screen.getByLabelText("Email")).toHaveValue("dev@example.com");
  });

  it("treats a second factor as the next step, not a failure", async () => {
    mockFetch((path) =>
      path.includes("/auth/login")
        ? response({ data: { authenticated: false, two_factor_required: true, next: "/dashboard" } })
        : response(ANONYMOUS),
    );
    const router = renderRoute("/login");

    await userEvent.type(await screen.findByLabelText("Email"), "dev@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    // Showing "sign-in failed" to somebody whose password was right would be
    // the worst possible reading of this response.
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/login/2fa");
    });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("never puts the password in the URL", async () => {
    const calls = mockFetch((path) =>
      path.includes("/auth/login") ? response(signedIn()) : response(ANONYMOUS),
    );
    renderRoute("/login");

    await userEvent.type(await screen.findByLabelText("Email"), "dev@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => {
      expect(calls.some((call) => call.path.includes("/auth/login"))).toBe(true);
    });
    // A credential in a query string ends up in server logs, proxy logs and
    // browser history.
    for (const call of calls) {
      expect(call.path).not.toContain("correct-horse-battery");
    }
  });
});

describe("the next destination", () => {
  it("keeps a same-origin path", () => {
    expect(safeNext("/alerts?show=open")).toBe("/alerts?show=open");
  });

  it("refuses an absolute URL", () => {
    // `next` arrives from a query string, so it is attacker-controlled.
    // Without this the sign-in form is an open redirect.
    expect(safeNext("https://evil.example/steal")).toBe("/dashboard");
  });

  it("refuses a protocol-relative URL", () => {
    // Starts with a slash and is still not same-origin — the case a naive
    // startsWith("/") check waves through.
    expect(safeNext("//evil.example/steal")).toBe("/dashboard");
  });

  it("falls back when there is nothing useful", () => {
    expect(safeNext(null)).toBe("/dashboard");
    expect(safeNext("")).toBe("/dashboard");
  });
});

describe("the sign-up page", () => {
  it("states the password requirement before it is enforced", async () => {
    mockFetch(() => response(ANONYMOUS));
    renderRoute("/signup");

    expect(await screen.findByText(/at least 10 characters/i)).toBeInTheDocument();
  });

  it("carries a honeypot that is hidden from people", async () => {
    mockFetch(() => response(ANONYMOUS));
    renderRoute("/signup");

    await screen.findByLabelText("Email");
    const honeypot = document.querySelector("input[name='website']");

    expect(honeypot).not.toBeNull();
    expect(honeypot.tabIndex).toBe(-1);
    expect(honeypot.closest("[aria-hidden='true']")).not.toBeNull();
  });

  it("explains a duplicate address", async () => {
    mockFetch((path) =>
      path.includes("/auth/signup")
        ? response({ error: { code: "EMAIL_IN_USE", message: "That address already has an account." } }, 409)
        : response(ANONYMOUS),
    );
    renderRoute("/signup");

    await userEvent.type(await screen.findByLabelText("Email"), "taken@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct-horse-battery");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("already has an account");
  });
});

describe("password recovery", () => {
  it("says the same thing whatever address was given", async () => {
    mockFetch((path) =>
      path.includes("/forgot-password")
        ? response({ data: { sent: true, message: "If that address has an account, a reset link is on its way." } })
        : response(ANONYMOUS),
    );
    renderRoute("/forgot-password");

    await userEvent.type(await screen.findByLabelText("Email"), "nobody@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Send the link" }));

    // The screen must not add a distinction the API deliberately refuses to
    // make, or it becomes the account-enumeration oracle the API is avoiding.
    expect(await screen.findByText(/if that address has an account/i)).toBeInTheDocument();
  });

  it("refuses to submit a mistyped confirmation", async () => {
    const calls = mockFetch(() => response(ANONYMOUS));
    renderRoute("/reset-password?token=abc123");

    await userEvent.type(await screen.findByLabelText("New password"), "a-brand-new-password");
    await userEvent.type(screen.getByLabelText("Confirm new password"), "a-brand-new-passwrod");

    // This is the one screen where a typo locks somebody out of the account
    // they are recovering, so the button does not even offer to try.
    expect(screen.getByRole("button", { name: "Change password" })).toBeDisabled();
    expect(calls.some((call) => call.path.includes("/reset-password"))).toBe(false);
  });

  it("explains a link with no token instead of showing a dead form", async () => {
    mockFetch(() => response(ANONYMOUS));
    renderRoute("/reset-password");

    expect(await screen.findByText(/link is incomplete/i)).toBeInTheDocument();
    expect(screen.queryByLabelText("New password")).not.toBeInTheDocument();
  });
});
