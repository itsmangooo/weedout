# Weedout frontend

The Weedout interface is a React 19 and Vite application served by the existing Python service.
It owns the public site, authentication screens, customer workspace, project and finding views,
account settings, and the operations console. Python remains responsible for authentication,
authorization, validation, billing, scanning, persistence, and project ownership.

## Local development

Start the Python application from the repository root:

```powershell
python -m app
```

Then start Vite in a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api`, `/healthz`, `/events`, `/webhooks`, the CLI
installers, and backend static assets to `http://localhost:8000`. Browser requests remain
same-origin and need no separate CORS policy.

## Commands

```powershell
npm run dev
npm run lint
npm run test -- --run
npm run build
npm run preview
```

The repository shipping workflow lives at `../scripts/ship.sh`. It validates both applications,
checks `origin/main`, commits the selected task files, and pushes without rewriting history.

## Structure

- `src/api/` owns HTTP transport and domain API modules. Views never call `fetch()` directly.
- `src/app/` owns routing, query configuration, error boundaries, and global providers.
- `src/components/` contains reusable brand, layout, feedback, motion, and UI primitives.
- `src/features/` owns domain components and query or mutation hooks.
- `src/pages/` composes route-level experiences from shared and domain pieces.
- `src/styles/` contains the single Weedout design system and its shell-specific compositions.

Remote server state stays in TanStack Query. Local interaction state stays in React. There is no
second authentication store: `useCurrentUser()` reads the canonical query cache shared by route
guards and navigation.

## Product shells

The product has three related layouts:

- The public shell uses editorial spacing and large type for the landing page, docs, CLI guide,
  pricing, status, contact, legal, and authentication routes.
- The customer shell uses a fixed workspace rail and dense queues for overview, projects,
  findings, project dependencies, scan history, and account settings.
- The operations shell uses horizontal console navigation, compact tables, source health, account
  records, billing, inbox, campaign confirmation, docs management, and audit history.

All three consume the same typography, spacing, color, form, button, table, dialog, and status
tokens. Normal surfaces use 4–8px radii. Tags use compact status treatments; content grouping relies
on whitespace and dividers rather than repeated cards.

## Theme and motion

Light and dark palettes are complete mappings in `src/styles/themes.css`. Light uses warm paper,
deep charcoal, and forest green. Dark uses near-black forest surfaces, cream type, and muted green.
The theme control writes `weedout-theme` to local storage and applies the resolved palette to
`<html>`, so it persists across public, customer, and admin routes. The pre-paint backend script
uses the same storage key.

Landing motion is isolated in `features/landing/useLandingMotion.js`. GSAP handles masked entry,
scroll reveals, a pinned analysis sequence, and restrained parallax. Lenis is enabled only for a
fine pointer on a large viewport. The dependency field loads one Three.js scene only when it nears
the viewport; an SVG rendering is always available for reduced motion, unsupported WebGL, and
context loss. Every observer, ticker, renderer, material, and geometry is disposed on unmount.

`prefers-reduced-motion` disables animated transforms and pinning while keeping all information and
controls visible. Route transitions use opacity and a small transform, reset scroll position, and
move keyboard focus to the new main region. Finding transitions, dependency paths, and numeric
updates stay transform/opacity based.

## Landing demo boundary

The 47-alert to 3-finding sequence is explicitly marked as illustrative. Its CVEs, package paths,
source paths, severities, and counts live only in `features/landing/demo.js`; they never enter API
responses or authenticated state. The demo keeps filtering separate from source reachability and
never presents Unknown or an observed import as proof of safety or vulnerable-function execution.

The CLI transcript uses the supported `weedout scan --ci` command and mirrors the output shape from
the sibling CLI implementation. Playback is bounded, pauses and replays, and renders fully when
reduced motion is requested.

## API and security boundaries

`/api/internal/*` is reserved for cookie-authenticated browser traffic. `/api/v1/*` remains the
bearer-key API for CLI and machine consumers. The browser never reads the HttpOnly session cookie
and stores no JWT. The readable CSRF cookie is copied to `X-CSRF-Token` for unsafe requests; Python
verifies the pair before executing mutations.

Route guards improve presentation, while every customer and administrator endpoint independently
enforces authentication, role, and ownership server-side. The UI renders explicit response fields
only. It never serializes ORM records, password hashes, stored key hashes, manifests, sensitive
configuration, or arbitrary audit objects. Newly issued API tokens remain one-time component state
and are not persisted by the frontend.

Finding status controls expose only dismiss and reopen. A finding becomes resolved only when a
later scan no longer sees it. Missing evidence is displayed as Unknown, failed scans are never shown
as zero findings, and truncated finding lists declare their loaded limit.

Live dashboard updates use one credentialed same-origin `EventSource`. A `stats` event invalidates
the relevant dashboard and finding query keys, and those queries refetch authoritative JSON. Event
payloads are not merged into the cache.

## Production integration

The Docker build runs `npm ci` and `npm run build`, then copies only the immutable `dist` output
into the unprivileged Python runtime image. Python serves the Vite entry for the explicit frontend
route allowlist and serves hashed assets with long-lived cache headers. API, webhook, static,
installer, health, readiness, and event routes retain their existing handlers; there is no broad
SPA catch-all.

--