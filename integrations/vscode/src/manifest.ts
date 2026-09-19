import type { DependencyOccurrence } from "./types";

export const MANIFEST_PATTERNS = [
  "**/package-lock.json",
  "**/package.json",
  "**/requirements*.txt",
  "**/go.mod",
  "**/Cargo.lock",
  "**/pom.xml",
  "**/gradle.lockfile",
  "**/*.gradle.lockfile",
  "**/dependencies.lock",
  "**/build.sbt.lock",
];

const RANK = [
  "package-lock.json",
  "Cargo.lock",
  "gradle.lockfile",
  "dependencies.lock",
  "build.sbt.lock",
  "package.json",
  "requirements.txt",
  "go.mod",
  "pom.xml",
];

export function isManifest(path: string): boolean {
  const name = path.replaceAll("\\", "/").split("/").pop() ?? "";
  return name === "package.json" || name === "package-lock.json" ||
    /^requirements.*\.txt$/i.test(name) || name === "go.mod" || name === "Cargo.lock" ||
    name === "pom.xml" || name === "gradle.lockfile" || name.endsWith(".gradle.lockfile") ||
    name === "dependencies.lock" || name === "build.sbt.lock";
}

export function manifestRank(path: string): number {
  const name = path.replaceAll("\\", "/").split("/").pop() ?? "";
  if (/^requirements.*\.txt$/i.test(name)) return RANK.indexOf("requirements.txt");
  if (name.endsWith(".gradle.lockfile")) return RANK.indexOf("gradle.lockfile");
  const rank = RANK.indexOf(name);
  return rank < 0 ? RANK.length : rank;
}

export function dependencyKey(value: string): string {
  return value.trim().toLowerCase().replace(/[._-]+/g, "-");
}

export function findDependencyOccurrences(text: string, filename: string): DependencyOccurrence[] {
  const found: DependencyOccurrence[] = [];
  const structural = new Set(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "packages"]);
  const lines = text.split(/\r?\n/);
  const push = (line: number, packageName: string, start: number, length = packageName.length) => {
    const clean = packageName.trim().replace(/^.*node_modules\//, "");
    if (clean) found.push({ package: clean, start, end: start + length, line });
  };

  if (filename === "pom.xml") {
    const dependencies = /<dependency>[\s\S]*?<groupId>\s*([^<]+)\s*<\/groupId>[\s\S]*?<artifactId>\s*([^<]+)\s*<\/artifactId>[\s\S]*?<\/dependency>/g;
    for (const match of text.matchAll(dependencies)) {
      const absolute = (match.index ?? 0) + match[0].indexOf(match[2]);
      const line = text.slice(0, absolute).split(/\r?\n/).length - 1;
      const lineStart = Math.max(text.lastIndexOf("\n", absolute - 1) + 1, 0);
      push(line, `${match[1].trim()}:${match[2].trim()}`, absolute - lineStart, match[2].trim().length);
    }
    return found;
  }

  if (filename === "package.json" || filename === "package-lock.json") {
    lines.forEach((line, index) => {
      const match = line.match(/^\s*"([@a-zA-Z0-9_.\/-]+)"\s*:\s*(?:"[^"\n]+"|\{)/);
      if (match?.index !== undefined && !structural.has(match[1])) push(index, match[1], line.indexOf(match[1], match.index));
    });
  } else if (/^requirements.*\.txt$/i.test(filename)) {
    lines.forEach((line, index) => {
      const match = line.match(/^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:===|==|~=|>=|<=|>|<|!=)/);
      if (match) push(index, match[1], line.indexOf(match[1]));
    });
  } else if (filename === "go.mod") {
    lines.forEach((line, index) => {
      const match = line.match(/^\s*([^\s/][^\s]*)\s+v?\d/);
      if (match && !["module", "go", "toolchain", "replace", "exclude"].includes(match[1])) {
        push(index, match[1], line.indexOf(match[1]));
      }
    });
  } else if (filename === "Cargo.lock") {
    lines.forEach((line, index) => {
      const match = line.match(/^name\s*=\s*"([^"]+)"/);
      if (match) push(index, match[1], line.indexOf(match[1]));
    });
  } else {
    lines.forEach((line, index) => {
      const match = line.match(/^\s*([^\s:#]+:[^\s:#]+):([^\s=]+)/);
      if (match) push(index, match[1], line.indexOf(match[1]));
    });
  }

  return found;
}

export function inlineHint(finding: FindingLike): string {
  return finding.fixed_in ? `Update to ${finding.fixed_in}` : `Review ${finding.cve}`;
}

interface FindingLike { cve: string; fixed_in?: string | null }
