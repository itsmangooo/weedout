export const manifestKinds = [
  "package.json", "package-lock.json", "requirements.txt", "go.mod", "Cargo.lock",
  "pom.xml", "gradle.lockfile", "build.sbt.lock",
] as const;

export function manifestKind(path: string): (typeof manifestKinds)[number] | null {
  const base = path.replaceAll("\\", "/").split("/").pop()?.toLowerCase() ?? "";
  if (base.startsWith("requirements") && base.endsWith(".txt")) return "requirements.txt";
  return manifestKinds.find((kind) => kind.toLowerCase() === base) ?? null;
}

export function ecosystemFor(kind: (typeof manifestKinds)[number]) {
  if (kind === "package.json" || kind === "package-lock.json") return "npm";
  if (kind === "requirements.txt") return "PyPI";
  if (kind === "go.mod") return "Go";
  if (kind === "Cargo.lock") return "crates.io";
  return "Maven";
}
