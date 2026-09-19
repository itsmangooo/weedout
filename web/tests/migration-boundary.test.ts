import assert from "node:assert/strict";
import test from "node:test";

import config from "../next.config.ts";

test("unmigrated routes fall back to the legacy compatibility service", async () => {
  assert.equal(typeof config.rewrites, "function");
  const rewrites = await config.rewrites!();
  assert.ok(!Array.isArray(rewrites));
  assert.ok(rewrites.fallback);
  assert.equal(rewrites.fallback![0].source, "/:path*");
  assert.match(rewrites.fallback![0].destination, /^http:\/\/legacy:8000\//);
});
