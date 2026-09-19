import assert from "node:assert/strict";
import test from "node:test";

import { findDependencyOccurrences, inlineHint, isManifest, manifestRank } from "../src/manifest";

test("recognises every backend manifest family", () => {
  for (const name of ["package.json", "package-lock.json", "requirements-dev.txt", "go.mod", "Cargo.lock", "pom.xml", "gradle.lockfile", "dependencies.lock", "build.sbt.lock"]) {
    assert.equal(isManifest(name), true, name);
  }
});

test("prefers resolved lockfiles", () => {
  assert.ok(manifestRank("package-lock.json") < manifestRank("package.json"));
  assert.ok(manifestRank("Cargo.lock") < manifestRank("pom.xml"));
});

test("finds dependency ranges for editor diagnostics", () => {
  const npm = findDependencyOccurrences('{\n  "dependencies": {\n    "lodash": "4.17.20"\n  }\n}', "package.json");
  assert.deepEqual(npm.map((entry) => entry.package), ["lodash"]);
  const requirements = findDependencyOccurrences("Django==4.2.0\nrequests>=2.0", "requirements.txt");
  assert.deepEqual(requirements.map((entry) => entry.package), ["Django", "requests"]);
  const go = findDependencyOccurrences("require (\n  golang.org/x/text v0.3.0\n)", "go.mod");
  assert.deepEqual(go.map((entry) => entry.package), ["golang.org/x/text"]);
  const npmLock = findDependencyOccurrences('"node_modules/lodash": {', "package-lock.json");
  assert.deepEqual(npmLock.map((entry) => entry.package), ["lodash"]);
  const maven = findDependencyOccurrences("<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.0</version></dependency>", "pom.xml");
  assert.deepEqual(maven.map((entry) => entry.package), ["org.slf4j:slf4j-api"]);
});

test("inline hints stay under eight words", () => {
  assert.ok(inlineHint({ cve: "CVE-2025-1", fixed_in: "2.4.1" }).split(/\s+/).length <= 8);
  assert.ok(inlineHint({ cve: "CVE-2025-1" }).split(/\s+/).length <= 8);
});
