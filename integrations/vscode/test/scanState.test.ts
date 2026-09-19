import assert from "node:assert/strict";
import test from "node:test";

import { ScanState } from "../src/scanState";

test("only the newest automatic scan may publish results", () => {
  const state = new ScanState();
  const first = state.begin("workspace-a");
  const second = state.begin("workspace-a");

  assert.equal(state.isCurrent("workspace-a", first), false);
  assert.equal(state.isCurrent("workspace-a", second), true);
});

test("workspaces and explicit invalidation are independent", () => {
  const state = new ScanState();
  const first = state.begin("workspace-a");
  const other = state.begin("workspace-b");

  state.invalidate("workspace-a");

  assert.equal(state.isCurrent("workspace-a", first), false);
  assert.equal(state.isCurrent("workspace-b", other), true);
});
