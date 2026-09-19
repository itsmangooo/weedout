import assert from "node:assert/strict";
import test from "node:test";

import { anonymousAuthState, authenticatedState } from "../src/contracts/auth.ts";

test("anonymous auth state preserves the legacy browser contract", () => {
  assert.deepEqual(anonymousAuthState(), {
    authenticated: false,
    session_state: "anonymous",
    user: null,
  });
});

test("authenticated auth state exposes only safe explicit fields", () => {
  assert.deepEqual(authenticatedState({ id: 7, email: "dev@example.com", is_admin: true }), {
    authenticated: true,
    session_state: "authenticated",
    user: {
      id: 7,
      email: "dev@example.com",
      is_admin: true,
      tier: "free",
      account_state: "active",
    },
  });
});
