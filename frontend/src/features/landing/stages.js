/**
 * The four stages the showcase plays through, and the field they act on.
 *
 * The dot counts are the story's counts: 47 advisories, 12 that survive
 * triage, 3 that are reachable, 1 that is exploited. A graphic claiming 47 and
 * drawing thirty would be the same small dishonesty this product exists to
 * complain about, so the field really does hold 47 dots.
 *
 * Positions are fixed rather than generated at runtime. A layout that reshuffles
 * on every render is a layout nobody can point at twice.
 */

export const SHOWCASE_STAGES = [
  {
    id: "watch",
    index: "01",
    label: "Watch the lockfile",
    headline: "Every dependency, not just the ones you wrote down.",
    body:
      "Point Weedout at a lockfile and it resolves the whole tree — direct, transitive, and the ones your tools pulled in without telling you.",
    metric: { value: 528, unit: "dependencies resolved" },
    /** Which survives-tier is still lit. -1 lights every dot. */
    threshold: -1,
    /** Nothing has been matched yet, so the field is dependencies, not alerts. */
    neutral: true,
  },
  {
    id: "match",
    index: "02",
    label: "Match every advisory",
    headline: "47 advisories match. That is the easy part.",
    body:
      "Every package is checked against the advisory mirror. This is the number most tools stop at, and the number that teaches people to ignore the alert.",
    metric: { value: 47, unit: "advisories matched" },
    threshold: -1,
  },
  {
    id: "triage",
    index: "03",
    label: "Drop what cannot run",
    headline: "Most of it never ships.",
    body:
      "Build tools, test fixtures, dev-only packages. If it cannot reach production, it is not an incident — so it stops being an alert.",
    metric: { value: 12, unit: "still worth checking" },
    threshold: 0,
  },
  {
    id: "reach",
    index: "04",
    label: "Trace what is reachable",
    headline: "Three can be reached. One is being exploited.",
    body:
      "What is left carries its dependency path and its evidence, ordered by whether somebody is attacking it today.",
    metric: { value: 3, unit: "actually reachable" },
    threshold: 1,
  },
];

/** How long each stage holds before the next one takes over. */
export const STAGE_DURATION_MS = 3000;

export const ADVISORY_FIELD = [
  { id: "n00", name: "minimist", x: 446.0, y: 158.0, r: 9, survives: 3 },
  { id: "n01", name: "express", x: 523.0, y: 254.0, r: 7.2, survives: 2 },
  { id: "n02", name: "systeminformation", x: 388.0, y: 88.0, r: 7.2, survives: 2 },
  { id: "n03", name: "qs", x: 372.0, y: 237.5, r: 5.6, survives: 1 },
  { id: "n04", name: "axios", x: 368.4, y: 131.5, r: 5.6, survives: 1 },
  { id: "n05", name: "lodash", x: 398.3, y: 283.0, r: 5.6, survives: 1 },
  { id: "n06", name: "webpack", x: 398.7, y: 55.6, r: 5.6, survives: 1 },
  { id: "n07", name: "tar", x: 400.9, y: 211.2, r: 5.6, survives: 1 },
  { id: "n08", name: "semver", x: 404.1, y: 176.5, r: 5.6, survives: 1 },
  { id: "n09", name: "tough-cookie", x: 410.8, y: 116.3, r: 5.6, survives: 1 },
  { id: "n10", name: "word-wrap", x: 336.0, y: 227.6, r: 5.6, survives: 1 },
  { id: "n11", name: "node-forge", x: 435.0, y: 52.1, r: 5.6, survives: 1 },
  { id: "n12", name: "postcss", x: 439.5, y: 293.6, r: 4.2, survives: 0 },
  { id: "n13", name: "jsdom", x: 307.3, y: 279.4, r: 4.2, survives: 0 },
  { id: "n14", name: "sass", x: 454.4, y: 90.9, r: 4.2, survives: 0 },
  { id: "n15", name: "eslint", x: 301.4, y: 216.6, r: 4.2, survives: 0 },
  { id: "n16", name: "rollup", x: 294.3, y: 119.9, r: 4.2, survives: 0 },
  { id: "n17", name: "vite", x: 285.5, y: 298.4, r: 4.2, survives: 0 },
  { id: "n18", name: "chokidar", x: 476.6, y: 257.2, r: 4.2, survives: 0 },
  { id: "n19", name: "glob", x: 485.8, y: 123.8, r: 4.2, survives: 0 },
  { id: "n20", name: "yargs", x: 496.2, y: 175.7, r: 4.2, survives: 0 },
  { id: "n21", name: "chalk", x: 496.4, y: 305.0, r: 4.2, survives: 0 },
  { id: "n22", name: "debug", x: 503.3, y: 39.8, r: 4.2, survives: 0 },
  { id: "n23", name: "ms", x: 249.8, y: 32.1, r: 4.2, survives: 0 },
  { id: "n24", name: "mime", x: 247.0, y: 165.2, r: 4.2, survives: 0 },
  { id: "n25", name: "raw-body", x: 516.0, y: 70.9, r: 4.2, survives: 0 },
  { id: "n26", name: "http-errors", x: 225.8, y: 303.1, r: 4.2, survives: 0 },
  { id: "n27", name: "cookie", x: 538.3, y: 44.5, r: 4.2, survives: 0 },
  { id: "n28", name: "iconv-lite", x: 195.6, y: 246.0, r: 4.2, survives: 0 },
  { id: "n29", name: "ajv", x: 191.9, y: 86.9, r: 4.2, survives: 0 },
  { id: "n30", name: "picomatch", x: 179.6, y: 206.7, r: 4.2, survives: 0 },
  { id: "n31", name: "braces", x: 590.9, y: 54.9, r: 4.2, survives: 0 },
  { id: "n32", name: "micromatch", x: 594.3, y: 157.3, r: 4.2, survives: 0 },
  { id: "n33", name: "readdirp", x: 594.7, y: 114.4, r: 4.2, survives: 0 },
  { id: "n34", name: "anymatch", x: 161.0, y: 297.4, r: 4.2, survives: 0 },
  { id: "n35", name: "esbuild", x: 145.3, y: 154.4, r: 4.2, survives: 0 },
  { id: "n36", name: "terser", x: 143.7, y: 259.8, r: 4.2, survives: 0 },
  { id: "n37", name: "acorn", x: 134.6, y: 317.8, r: 4.2, survives: 0 },
  { id: "n38", name: "source-map", x: 110.3, y: 290.8, r: 4.2, survives: 0 },
  { id: "n39", name: "magic-string", x: 109.6, y: 125.2, r: 4.2, survives: 0 },
  { id: "n40", name: "rimraf", x: 102.0, y: 180.2, r: 4.2, survives: 0 },
  { id: "n41", name: "nanoid", x: 89.7, y: 206.4, r: 4.2, survives: 0 },
  { id: "n42", name: "punycode", x: 84.5, y: 49.1, r: 4.2, survives: 0 },
  { id: "n43", name: "tslib", x: 76.3, y: 319.1, r: 4.2, survives: 0 },
  { id: "n44", name: "undici", x: 70.6, y: 124.3, r: 4.2, survives: 0 },
  { id: "n45", name: "form-data", x: 52.2, y: 212.5, r: 4.2, survives: 0 },
  { id: "n46", name: "follow-redirects", x: 51.1, y: 104.0, r: 4.2, survives: 0 },
];
