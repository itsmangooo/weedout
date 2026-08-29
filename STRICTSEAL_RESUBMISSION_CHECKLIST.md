# StrictSeal resubmission checklist

Date: 30 August 2026

## Reviewer-critical behavior

- [x] Node/JavaScript automated reachability comes from supplied source observations, not direct/transitive depth or severity.
- [x] States are `reachable`, `potentially_reachable`, `not_observed`, and `unknown`.
- [x] Missing/incomplete/unsafe/non-literal analysis returns `unknown` rather than a safe negative.
- [x] Evidence includes source file, line, import/require kind, imported package, dependency path, and explanation.
- [x] Automated reachability is stored on dependencies and finding snapshots.
- [x] Scanner response, API, database, dashboard, detail view, and CLI use the same state values.
- [x] Manual dismissal status/reason remains separate from automated reachability.
- [x] Suppressed/noise findings are stored as `filtered`, not `open`.
- [x] Filtered rows are excluded from active counts, badges, email, attention excerpts, and CI-blocking finding lists.
- [x] Filtered, dismissed, and resolved views remain separately inspectable.

## StrictSeal regression project

- [x] `lodash` 4.17.11 pinned.
- [x] `minimist` 1.2.5 pinned.
- [x] `axios` 0.21.1 pinned.
- [x] `express` 4.17.1 pinned.
- [x] Case A: installed and imported package -> `reachable` with source/line evidence.
- [x] Case B: installed but unreferenced package -> `not_observed` only with a complete reliable inventory.
- [x] Case C: imported top-level package to transitive dependency -> evidence-backed `potentially_reachable` with lockfile path.
- [x] Case D: dynamic/incomplete analysis -> `unknown`.

Fixture: `tests/fixtures/strictseal/node-project/`  
Core tests: `tests/test_reachability.py`  
API/storage regression: `tests/test_api.py::TestReachabilityScanContract`

## CLI contract

- [x] `weedout --help` works and exits 0.
- [x] `weedout version` works, validates arguments, and exits sensibly.
- [x] `weedout init` works, validates arguments, uses env/flag credentials, and never prompts/echoes a key.
- [x] `weedout auth` exists with help, success, failure, and no-secret-output coverage.
- [x] `weedout create` exists with help, success, failure, and real API coverage.
- [x] `weedout scan` sends manifest, policy, and bounded source context and renders reachability.
- [x] `weedout findings` exists and renders filtered/reachability fields.
- [x] `weedout rules` exists with list/ignore/unignore validation and API coverage.
- [x] Exit 0/1/2 semantics are tested against the packaged executable.
- [x] CLI docs include the same real commands and credential boundaries.
- [x] CLI commits `7f940fc` and `a7856a5` are pushed to `main`.
- [x] Release tag `v0.3.1` completed verify, all five builds, and release publication successfully.
- [x] Unix installer exists, is publicly served, and passed a clean Alpine install with SHA-256 verification.
- [x] PowerShell installer exists, is routed by the web app, and passed pipeline-style installation with SHA-256 verification.
- [ ] After web deployment: verify public `https://weedout.dev/install.ps1` returns 200 and run exact `irm ... | iex` in a disposable environment.
- [x] Latest installer resolution selects v0.3.1; both Windows/Linux downloads verified published checksums and ran successfully.

## Free-only product

- [x] Free is the only serialized/user-facing plan.
- [x] Legacy `tier='pro'` rows map to Free behavior for database compatibility.
- [x] Pro cards, comparisons, CTAs, banners, locks, and labels are absent from normal UI.
- [x] Former gates were removed only for implemented/tested rules, profiles, full-depth scans, history, and webhooks.
- [x] Normal-user billing navigation/page/API is removed; old return URLs redirect safely.
- [x] Historical provider reconciliation remains admin-only and does not grant access.

## Landing and admin UI

- [x] Landing copy describes dependency analysis, paths, evidence, filtering, OSV/CISA, CLI, and CI exits that exist.
- [x] Source code, Secrets, and CI/config modules are visibly disabled and marked Planned.
- [x] Fake product stages/social proof/live data claims were removed.
- [x] Product preview uses real StrictSeal-style packages and real status values.
- [x] Admin uses the Weedout sidebar design language.
- [x] Admin sidebar includes only Overview, Users, historical Billing, Inbox, Compose, Docs, and Audit log.
- [x] Admin identity, theme control, Back to app, and mobile disclosure remain.
- [x] Navigation/component responsive coverage passes.
- [ ] Perform final human visual inspection at desktop and phone widths after deployment (in-app browser plugin was unavailable in this run).

## Security and validation

- [x] Server-side auth/admin/project/finding/rule ownership checks re-tested.
- [x] CSRF remains enforced for cookie-session mutations.
- [x] Bearer key scopes remain scan/read/manage and project-bound.
- [x] Source uploads are size/count/UTF-8/path/extension/context bounded.
- [x] Traversal, Windows absolute, control-character, duplicate, and symlink cases are rejected.
- [x] Uploaded source is never executed or written to disk.
- [x] Evidence is normalized before storage/output and React escapes it.
- [x] Packaged CLI test asserts credentials do not leak to output.
- [x] Existing Unix credential directories are forced to mode 0700; clean Linux tests pass.
- [x] Installer downloads were verified against published SHA-256 values.

## Verification evidence

- [x] Backend: 1725 passed, 14 skipped, 2 xfailed.
- [x] Focused security/ownership set: 309 passed.
- [x] Reachability/API set: 53 passed after upload hardening.
- [x] Installer/route set: 40 passed.
- [x] Frontend: 20 files, 137 tests passed.
- [x] Frontend lint passed.
- [x] Production Vite build passed (2,420 modules).
- [x] Ruff lint and format passed.
- [x] Alembic blank upgrade, drift check, downgrade/upgrade, and second drift check passed.
- [x] Go format, vet, and all package tests passed.
- [x] Actual packaged Windows binary command/exit/secret tests passed.
- [x] Unix and PowerShell installers downloaded, checksummed, installed, and executed a released binary.

## Resubmission notes

Automated reachability is conservative evidence, not a proof of runtime execution. Reviewers should expect `potentially_reachable` for transitive paths and `unknown` whenever static negative conclusions are unsafe. `not_observed` means no supported import was observed in a complete bounded inventory; it does not claim formal unreachability.
