import assert from "node:assert/strict";
import test from "node:test";

import config from "../next.config.ts";

test("Next.js no longer delegates unknown routes to the legacy application", () => {
  assert.equal(config.rewrites, undefined);
});
