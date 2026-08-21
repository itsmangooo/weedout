# Weedout frontend

This directory is the isolated React/Vite presentation layer introduced by the controlled
frontend migration. Phase 5 makes the parity-complete React dashboard the canonical production
dashboard while preserving the server-rendered version as an explicit rollback route.

React owns only `/dashboard` in production. The protected `/dashboard/legacy` route renders the
unchanged `app/templates/dashboard.html` for rollback and parity checks; it is intentionally absent
from normal product navigation. Login, signup, settings, projects, alerts, billing, and admin
remain server-rendered.

## Local development

Run the Python application from the repository root:

```powershell
python -m app
```

Then start the frontend in a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173/dashboard`. Vite owns the canonical dashboard locally and proxies
`/healthz`, `/api`, and `/events` to Python on `http://localhost:8000`. It also proxies
`/dashboard/legacy`, `/login`, `/alerts`, `/targets`, and `/settings` for intentional legacy
handoffs. Browser code uses same-origin paths and needs no CORS policy.

## Commands

```powershell
npm run dev
npm run lint
npm run test -- --run
npm run build
npm run preview
```

## Ownership rules

- `src/api/` owns HTTP transport and domain API modules. Presentation components do not call
  `fetch()` directly.
- `src/app/` owns routing and global providers.
- `src/components/` contains only reusable UI, layout, feedback, and motion primitives.
- `src/features/` owns domain-specific components and hooks.
- `src/pages/` composes routes from shared and feature-owned pieces.
- `src/styles/` owns Weedout design tokens and branded global composition; Tailwind is used mainly
  for layout and responsive utilities.

Remote state belongs in TanStack Query. Local interaction state stays in React. Authentication,
authorization, validation of trusted data, billing, scanning, persistence, and ownership checks
remain in Python.

There is deliberately no `AuthProvider`. `useCurrentUser()` is a TanStack Query over one canonical
cache entry, so copying that data into React Context would create a second source of truth.
`useDashboard()` and `useOpenFindings()` follow the same rule: their server state lives only in
their Query caches.

## Visual language

The React surface has two explicit themes. Public and authentication boundary routes use the
`public` theme: warm ivory and pearl surfaces, graphite typography, a quiet green action color,
and editorial spacing. Authenticated routes use the `app` theme: neutral near-black graphite,
tonal surface separation, compact rows, and semantic red, amber, and green only where status needs
them. The palette deliberately contains no purple theme, gradients, glass effects, or decorative
glow.

Reusable tokens live in `src/styles/tokens.css` and theme values in `src/styles/themes.css`.
Marketing motion is isolated from the app shell and respects the global `reducedMotion="user"`
policy. Dashboard motion stays limited to small row/status transitions.

The public landing is organized around one Weedout-specific transformation instead of reusable
SaaS feature cards:

- the hero keeps advisory/package/path rows visually continuous while a four-beat sequence reduces
  47 matches to 12 relevant results, 3 reachable paths, and 1 exploited signal;
- a sticky, scroll-driven scene progressively removes those same kinds of rows so visual density
  falls with the decision count;
- the workflow scene draws the path from `package-lock.json` through `weedout scan`, reachability,
  and a CI decision; and
- the health check remains available under the collapsed local-preview footer disclosure instead
  of appearing as product storytelling.

Pointer depth and magnetic CTA movement are disabled on touch and under reduced-motion
preferences. Reduced motion also removes the sticky scroll duration and renders the final,
fully-filtered state directly.

Finding and project rows expose the same read-only destinations through an accessible ellipsis
button and a pointer-positioned context menu. The custom menu is scoped to the non-interactive row
surface, so links, controls, code, and every area outside those entities retain the native browser
context menu. No destructive or mutating action is exposed.

## API boundaries

`GET /healthz` remains a connectivity check, not an application-data contract.

`GET /api/internal/auth/me` is the first browser endpoint. It uses the existing opaque,
database-backed `weedout_session` cookie and returns one of three outcomes:

- `200` with `authenticated: false` when no session cookie exists;
- `200` with the explicitly serialized `id`, `email`, `is_admin`, `tier`, and `account_state` fields
  when the session is valid; or
- `401 SESSION_EXPIRED` when a cookie exists but is invalid, revoked, expired, suspended, or tied to
  an inactive account. Those cases intentionally look the same to the browser.

Responses are private and non-cacheable. `/api/internal/*` is reserved for cookie-authenticated
browser traffic; `/api/v1/*` remains the bearer-key API for CLI and machine consumers.

`GET /api/internal/dashboard` requires that same session and returns only the aggregate and project
fields rendered by `/dashboard`:

```json
{
  "data": {
    "summary": {
      "projects": 1,
      "dependencies": 143,
      "open_findings": 3,
      "exploited_findings": 1,
      "critical_findings": 2,
      "filtered_findings": 8,
      "dismissed_findings": 0,
      "resolved_findings": 4,
      "filter_rate_percent": 73
    },
    "projects": [
      {
        "id": 8,
        "name": "checkout-api",
        "ecosystem": "npm",
        "manifest_kind": "package-lock.json",
        "dependency_count": 143,
        "is_active": true,
        "has_manifest": true,
        "last_scanned_at": "2026-08-20T18:30:00Z",
        "last_scan_failed": false,
        "findings": { "open": 3, "exploited": 1, "filtered": 8 }
      }
    ]
  }
}
```

The endpoint calls `dashboard_stats()` and `list_targets()` with the authenticated user's ID.
Those services enforce target ownership in their queries; the route only copies an explicit safe
field list and never serializes ORM instances.

`GET /api/internal/findings?show=open&limit=25` is the compact finding read used by the dashboard.
The accepted `show` values are `open`, `filtered`, `dismissed`, and `resolved`; `limit` must be at
least 1 and is capped at 200 by the server. The default response is:

```json
{
  "data": [
    {
      "id": 91,
      "project": { "id": 8, "name": "checkout-api" },
      "identifier": "CVE-2026-5001",
      "package_name": "minimist",
      "installed_version": "1.2.5",
      "severity": "critical",
      "is_exploited": true,
      "reachability": "runtime_transitive",
      "status": "open",
      "detected_at": "2026-08-20T18:30:00Z"
    }
  ],
  "meta": { "show": "open", "limit": 25, "count": 1 }
}
```

`identifier` is the first CVE when the advisory carries one, otherwise the stable OSV advisory
identifier. `reachability` retains Weedout's honest manifest-level vocabulary instead of claiming
source-level vulnerable-function reachability. The shared `list_findings()` service owns the user
join, filters, urgency order, and cap for both legacy HTML reads and this endpoint. The serializer
copies only the listed fields; owner IDs, raw manifests, hashes, repository metadata, policy
content, full advisory records, and scanner internals remain server-side. Responses are
`private, no-store` and vary on `Cookie`.

The shared client accepts legacy errors during the migration while future internal endpoints use:

```json
{
  "error": {
    "code": "STABLE_CODE",
    "message": "A safe message for the user."
  }
}
```

## CSRF bootstrap for React

The `/me` request is also the CSRF bootstrap; no separate token endpoint is needed:

1. `getCurrentUser()` requests the same-origin `/api/internal/auth/me` path with
   `credentials: "include"`.
2. Python creates or reissues the host-only `weedout_csrf` cookie with `Path=/`, `SameSite=Lax`, a
   12-hour lifetime, and the environment's `Secure` setting. It remains readable by JavaScript on
   purpose; unlike `weedout_session`, it is not an authentication secret.
3. For every unsafe request, `src/api/client.js` reads that cookie and sends the same value in
   `X-CSRF-Token`. JSON objects are serialized, while `FormData` remains untouched.
4. Python's existing `verify_csrf` dependency compares the cookie and header with a constant-time
   comparison. Missing or mismatched values remain `403` responses.

The HttpOnly session cookie is never read by React and no JWT or browser token store is involved.

## Live dashboard refresh

`useLiveDashboardUpdates()` opens one credentialed, same-origin `EventSource` on the existing
`/events` endpoint while the protected dashboard is mounted. The browser's native EventSource
reconnection is used; an `error` only changes the restrained header indicator to “Reconnecting”
and never creates a toast or replaces dashboard content.

Each existing `stats` event invalidates the `dashboard` and `findings/open/25` TanStack Query keys.
Active queries then refetch their authoritative JSON responses. Event payloads are never merged
into cached objects, and SSE is not a second state store. All listeners are attached once per
mounted dashboard and removed before `EventSource.close()` during cleanup.

## Production integration

The Dockerfile uses Node 24 and the committed npm lockfile to run `npm ci` followed by
`npm run build`. Only the resulting immutable `dist` directory is copied into the unprivileged
Python image; Node and `node_modules` do not enter the runtime stage.

FastAPI serves:

- `/dashboard` — the Vite HTML entry with `Cache-Control: private, no-store` and `Vary: Cookie`;
- `/assets/*` — hashed JS, CSS, images, fonts, and lazy chunks with a one-year immutable cache;
- `/dashboard/legacy` — the protected Jinja rollback implementation.

There is no SPA catch-all. `/api`, `/webhooks`, `/static`, `/install.sh`, `/healthz`, `/readyz`,
`/events`, and every legacy product route retain their existing handlers. A missing frontend entry
returns `503`; missing assets and unknown routes return `404` rather than receiving the SPA shell.

Coolify, Traefik, and Cloudflare can continue forwarding the single Weedout origin to the Python web
service. A separate frontend hostname or CORS policy is not planned.

## Dashboard cutover and recommended Phase 6

The React dashboard now has the legacy read path's headline counts, attention priority, filter
ratio, project/scan state, 25-item open-finding excerpt, independent loading/empty/error recovery,
and live refresh. Finding and project rows retain stable IDs and isolated component boundaries;
their scoped read-only menus preserve native right-click behavior everywhere else. All finding
mutations and the full findings workflow remain in the legacy application.

The React and legacy routes call the same ownership-scoped dashboard and finding services. An
integration parity test verifies equivalent summary, project, and finding data for one account.
The built application remains compatible with the existing same-origin CSP: no `unsafe-eval`,
wildcard, `blob:` allowance, inline script, or new CSP directive was added.

Keep `dashboard.html` through a real Coolify deployment and observation window. Phase 6 should be
a bounded post-cutover cleanup: verify production telemetry and rollback readiness, then remove
`/dashboard/legacy`, `dashboard.html`, and dashboard-only legacy assets after rollback is no longer
needed. It should not migrate another feature in the same phase.
