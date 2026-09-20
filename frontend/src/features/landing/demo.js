// Landing-only fixtures. Never merged into API responses or authenticated UI.
// Counts, source files, paths and severities illustrate a scenario, not live results.
export const DEMO_FINDINGS = [
  {
    id: "CVE-2021-3749",
    packageName: "axios",
    version: "0.21.1",
    fixed: "0.21.2",
    severity: "High",
    path: ["demo-app", "axios"],
    reachability: "Reachable",
    source: "src/api.js:1 imports axios",
    evidence:
      "A static import of this direct package was observed in production source. This does not prove that the vulnerable function executes.",
    action: "Update axios to 0.21.2 or later, then rescan.",
  },
  {
    id: "CVE-2021-44906",
    packageName: "minimist",
    version: "1.2.5",
    fixed: "1.2.6",
    severity: "Critical",
    path: ["demo-app", "argument-helper", "minimist"],
    reachability: "Potentially reachable",
    source: "src/cli.js:2 imports argument-helper",
    evidence:
      "The imported direct dependency leads to minimist in this example lockfile. A transitive path is potential reachability, not proof of vulnerable-function execution.",
    action:
      "Update the parent dependency to resolve minimist 1.2.6 or later, then rescan.",
  },
  {
    id: "CVE-2021-23337",
    packageName: "lodash",
    version: "4.17.15",
    fixed: "4.17.21",
    severity: "High",
    path: ["demo-app", "lodash"],
    reachability: "Unknown",
    source: "Source inventory incomplete",
    evidence:
      "The manifest identifies a direct production dependency. Incomplete source analysis cannot establish whether it is imported. Unknown does not mean safe.",
    action: "Review usage and update lodash to 4.17.21 or later, then rescan.",
  },
];
