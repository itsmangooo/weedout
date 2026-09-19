# Architecture audit and migration boundary

This document records the source-of-truth audit before legacy code is removed.

## Current product

- `app/core`: pure Python detection domain: manifest parsing, normalized models,
  version ranges, matching, reachability, rules, triage, and explanations.
- `app/services/scan_service.py`: orchestration plus persistence reconciliation.
  It preserves finding identity, dismissal, resolution, notification discipline,
  scan history, mirror freshness warnings, and project scheduling.
- `app/feeds` and mirror services: OSV, CISA KEV, EPSS and registry ingestion.
- `app/routes`, `app/services`, `app/models.py`: FastAPI product boundary,
  sessions, CSRF, Argon2 credentials, 2FA, API keys, users, projects, history,
  profiles, admin, notifications, docs, audit, and PostgreSQL persistence.
- `frontend`: React/Vite public and authenticated interfaces consuming same-origin
  `/api/internal/*` and public APIs.

## Target boundaries

`engine/` owns only deterministic detection. Public contracts are in
`engine/pkg/model`. The scanner accepts manifests, optional sources, rules and
normalized advisory data and returns one canonical result. Parser, advisory,
and rule providers are interfaces.

`web/` owns product identity and persistence. It calls the engine over an
internal network and reconciles canonical findings into the existing tables.
The browser never calls the engine. The engine never reads user/project tables.

## Invariants that block legacy removal

1. Existing PostgreSQL IDs and rows migrate in place; no reset or re-seed.
2. Session hashing, rotation, revocation, CSRF, Argon2, 2FA and recovery codes
   need compatibility tests before Next.js owns authentication.
3. Findings keep identity, dismissal, resolved/reopened state, and notification
   once-only semantics across engine cutover.
4. Empty mirror refuses to scan; stale mirror is explicit; advisory lookup is
   local and bounded.
5. The shared parity corpus must cover all supported ecosystems, version edge
   cases, KEV/EPSS, ignores, thresholds, reachability and remediation.
6. Every route must move from `legacy` to `next` in `route-ownership.md`, with
   response/security parity, before the fallback rewrite is removed.

## Database migration

During coexistence, Alembic is the sole schema writer. Next.js uses the same
tables and stable identifiers through explicit repositories. For each domain:

1. add contract tests against a production-shaped snapshot;
2. add a Next.js read repository and compare responses;
3. add transactional writes behind a route-specific cutover flag;
4. verify rollback and audit behavior;
5. transfer migration ownership only after no Python code writes that domain.

A final baseline migration will record the existing Alembic head without
recreating tables. Running two migration tools against the same schema is
forbidden.
