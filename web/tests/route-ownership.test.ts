import assert from "node:assert/strict";
import { access } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ownedRoutes = [
  "dashboard", "findings", "projects", "profiles", "settings", "landing", "pricing", "status", "docs",
];

test("core product routes are implemented by Next.js instead of relying on the legacy fallback", async () => {
  for (const route of ownedRoutes) {
    await assert.doesNotReject(access(path.join(process.cwd(), "src", "app", "api", "internal", route, "route.ts")));
  }
});
