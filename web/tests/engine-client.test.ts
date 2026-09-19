import assert from "node:assert/strict";
import test from "node:test";

import type { ScanRequest } from "../src/server/engine/types.ts";

test("engine request contract requires manifests", () => {
  const request = {
    schema_version: "v1",
    manifests: [{ path: "go.mod", content: "module example\n" }],
  } satisfies ScanRequest;
  assert.equal(request.manifests[0].path, "go.mod");
});
