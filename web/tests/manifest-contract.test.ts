import assert from "node:assert/strict";
import test from "node:test";

import { ecosystemFor, manifestKind } from "../src/server/projects/manifest.ts";

test("all authoritative engine manifests map to the stored ecosystem contract", () => {
  assert.equal(manifestKind("frontend/package-lock.json"), "package-lock.json");
  assert.equal(manifestKind("requirements-prod.txt"), "requirements.txt");
  assert.equal(manifestKind("Cargo.lock"), "Cargo.lock");
  assert.equal(manifestKind("pom.xml"), "pom.xml");
  assert.equal(ecosystemFor("go.mod"), "Go");
  assert.equal(ecosystemFor("build.sbt.lock"), "Maven");
  assert.equal(manifestKind("README.md"), null);
});
