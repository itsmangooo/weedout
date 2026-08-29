# Automated reachability in Weedout

Weedout performs conservative static reachability analysis for Node.js and
JavaScript/TypeScript projects scanned by the CLI. It observes package imports;
it does not claim to prove that a vulnerable function executes.

## States

| State | Meaning |
|---|---|
| `reachable` | Production source contains a static import or `require` of the affected direct package. |
| `potentially_reachable` | The observation is in test/config source, or source imports a direct package whose dependency path leads to the affected transitive package. |
| `not_observed` | A complete supported-source inventory was analysed and no supported import path to the package was observed. |
| `unknown` | Source was absent or incomplete, a dynamic import could not be resolved, or the lockfile did not provide a trustworthy path. |

`unknown` is the safe result whenever the analyzer cannot support a negative
conclusion. Direct-versus-transitive relationship, severity, and exploit status
never stand in for automated reachability.

## Evidence

Positive observations retain inspectable evidence:

- repository-relative source file;
- one-based line number;
- import kind (`import`, `require`, or literal dynamic import);
- imported package;
- dependency path; and
- a plain-language explanation such as `src/api.js:4 imports axios`.

The evidence is stored with dependency rows and findings, returned by the API,
and shown by the web dashboard and CLI. Manual dismissal notes are separate
user decisions and never alter reachability.

## Source collection and privacy

`weedout scan` discovers supported `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`,
`.tsx`, `.mts`, and `.cts` files below the scan root. It skips dependency,
build, coverage, cache, vendor, and hidden directories and does not follow
symlinks.

The inventory is deliberately bounded:

- at most 512 files;
- at most 512 KiB per file; and
- at most 4 MiB total.

The CLI uploads the bounded UTF-8 inventory over the authenticated scan request.
The server analyses it in memory and does not persist raw source. It stores only
the resulting state, evidence, source count, completeness flag, and bounded
analysis notes. A manifest uploaded through the browser has no source inventory,
so automated reachability is `unknown` unless earlier CLI evidence is being
carried forward for a scheduled recheck.

## Supported analysis

The analyzer recognizes static ES module imports and exports, CommonJS
`require`/`require.resolve`, and literal dynamic imports. It normalizes package
subpaths to the owning package and understands scoped npm package names.

It is intentionally not a JavaScript call-graph engine. Aliases, bundler
rewrites, runtime module names, framework dependency injection, generated code,
native bindings, and vulnerable-function invocation are outside its proof.
Non-literal imports make unobserved results `unknown`; reliable positive
observations found elsewhere remain available.

## Dependency relationship is separate

Weedout still records manifest-derived relationship facts: direct, transitive,
or development-only. Those facts describe how a package entered the dependency
tree and feed the alert policy. They are exposed as `dependency_relationship`,
not mislabeled as source reachability.

The default alert policy remains independent:

1. Known exploitation or a malicious-package signal is actionable regardless
   of other filters.
2. Critical production dependencies are actionable.
3. High-severity direct production dependencies are actionable.
4. Everything else is recorded as `filtered`, with its suppression reason.

Filtered findings remain inspectable, but they are not open findings and do not
trigger the same attention state or notifications.

## Version accuracy

A manifest range is not an installed version. For a range such as
`"lodash": "^4.17.4"`, Weedout conservatively checks the lowest permitted
version and marks the result as inexact. Upload a lockfile for exact installed
versions and dependency paths.
