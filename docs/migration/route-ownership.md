# Route ownership ledger

The Next.js fallback rewrite is a compatibility boundary, not the final design.
Unlisted routes remain owned by the legacy FastAPI/React service.

| Capability | Current owner | Target owner | Cutover gate |
|---|---|---|---|
| `/healthz` | Next.js | Next.js | complete |
| `/readyz` web/engine readiness | Next.js | Next.js | engine health complete; database/feed parity pending |
| `/api/internal/auth/me` | Next.js | Next.js | read-only session lookup and response contract migrated |
| Public pages and SEO | Legacy | Next.js | visual, metadata, legal and redirect parity |
| Dashboard/findings/projects | Legacy | Next.js | API response and persistence reconciliation parity |
| Auth mutations/2FA/reset | Legacy | Next.js | CSRF, Argon2, rotation and revocation parity |
| Rules/profiles | Legacy | Next.js | policy parsing and audit parity |
| Admin/docs/notifications | Legacy | Next.js | authorization and audit parity |
| CLI/account APIs | Legacy | Next.js | token scope and compatibility suite |
| Advisory mirror reads | Go PostgreSQL provider | Go engine | provider implemented; production soak pending |
| Detection | Python core with Go shadow | Go engine | ecosystem/rule/reachability fixture parity |

Move one row at a time. A moved filesystem route wins before the fallback
rewrite, which keeps URLs stable and avoids a flag day.
