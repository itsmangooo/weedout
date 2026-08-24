# Weedout — status and handoff

Written 20 Aug 2026. Update this file rather than starting a new one.

Two repositories:

- `A:\Projects\Weedout` → `github.com/itsmangooo/weedout` — the web app
- `A:\Projects\weedout-cli` → `github.com/itsmangooo/weedout-cli` — the Go CLI
  **and** the GitHub Action (`action.yml` at the root)

---

## How to get running

```powershell
docker compose up -d db          # Postgres 17 on :5432, test DB on :5435
.\.venv\Scripts\python.exe -m alembic upgrade head
docker compose up -d --build web # http://localhost:8000
.\.venv\Scripts\python.exe -m pytest -q
.\scripts\deploy.ps1 -Message "…"
```

Tests need Postgres running or **they silently skip** — a green run with
"23 skipped" means the database was down, not that anything passed. Docker
Desktop on this machine stops on its own; restart it from
`C:\Program Files\Docker\Docker\Docker Desktop.exe`.

Current state: **1329 passed, 14 skipped, ruff clean.**

---

## Architectural decisions worth not re-litigating

**`app/core/` is pure.** No SQLAlchemy, no FastAPI, no settings. Triage,
version comparison, manifest parsing, TOTP, Discord payloads and webhook URL
validation all live there and are tested without a database. Anything that
needs IO goes in `app/services/`.

**Exit codes are a contract.** CLI: `0` clean, `1` blocking findings (`--ci`
only), `2` the scan did not run. The gap between 1 and 2 is the point — a
pipeline that treats every non-zero as "vulnerabilities found" eventually
treats an expired key as a security finding, and somebody deletes the step.
The GitHub Action inherits this; every configuration error in its scripts
exits 2, never 1.

**Malicious packages outrank everything except a withdrawal.** OSV publishes
them as `MAL-` advisories with no CVSS score, so a severity ladder files them as
`unknown` — under every threshold. They were being reported as "below severity
threshold and not exploited", i.e. as noise. `Vulnerability.is_malicious` is
checked before KEV, before reachability, and before any ignore rule, and it is
**not** tier-gated: this is CVE matching working correctly, not one of the four
Pro signals, and a malware alert behind a paywall is indefensible. The mirror
holds ~231k of these, so the data was always there.

**`notified_at` means "this person has been told."** Alerts go over two
independent channels (email, Discord). It is set if *either* succeeds, because
retrying for the one that failed would re-send on the one that worked. Both
failing leaves it unset for the next scan.

**Tier is checked at send/use time, not only at save time.** A lapsed
subscription stops Pro behaviour without anybody clearing a field, and renewal
restores it without re-entering a credential.

**Strict CSP: `script-src 'self'`.** No inline `<script>` anywhere. This is why
the theme boot is its own file, and why anything interactive is a `data-`
attribute plus a listener in `app/static/js/app.js`.

**Webhook URLs are credentials and request destinations.** See the security
section below — this is the part most easily broken by a well-meaning change.

**Naming debt:** the webhook column is still `TrackedTarget.discord_webhook_url`
and the service is still `app/services/discord_service.py`, though both now
handle custom endpoints too. Renaming means a migration and a wide diff; it is
cosmetic and deliberately deferred. `webhook_kind` says which shape it is.

**CSS source order bites repeatedly.** Several rules lost to a later
same-specificity rule (`.datalist`, `.mhero__eyebrow`, `.textarea`). When a
style mysteriously does not apply, check for a later declaration before
changing anything else. Two classes (`.datalist.cli-deps__facts`) beats
`!important`.

**One search entry point.** The sidebar palette. In-page filter boxes were
removed twice; `tests/test_design_system.py` now fails if one comes back.

---

## Security notes — read before touching webhooks

Two kinds of destination, guarded differently because they can be.

**Discord** (`app/core/discord.py`) — an allowlist of four hostnames. Ports,
userinfo, query strings, fragments and redirects are all refused. An allowlist
has to be right once; a blocklist has to anticipate every spelling of
localhost. Tested against the real attack shapes, not just "not a discord
link": `discord.com@evil.example`, `discord.com.evil.example`, `169.254.169.254`,
`?next=…`, embedded newline.

**Custom endpoints** (`app/core/webhooks.py`) — cannot be allowlisted, so it is
a deny-list of resolved addresses: loopback, private, link-local (including the
metadata address), reserved, multicast, unspecified. Uses `ipaddress`, not
string matching, so `127.1`, `::1` and `::ffff:127.0.0.1` are all caught. Every
address a hostname resolves to is checked, not just the first.

**Residual risk, stated plainly:** DNS rebinding. A name validated as public
can be re-pointed before the request is made. The window is narrow and the
value is re-validated immediately before connecting, but it is not closed.
Closing it means pinning the resolved address at connect time, which is a
change to how the HTTP client dials. Keep egress rules on the container too.

The stored URL is **re-validated on the way out**, not only at the form. It has
been through a database in between.

Webhook URLs are never rendered in full after saving, never logged, and never
copied onto `Alert` rows (those carry `discord:{target_id}`).

---

## What is built

### Recently (this stretch of work)

- **One theme for the whole product, chosen by the reader.** Light by default
  — the cream ground is the design, not a fallback — with light / match-system
  / dark in the header and the app sidebar.

  Three things are worth knowing before touching it:

  - `data-theme` lives on `<html>` and nowhere else. Each shell used to pin its
    own on a wrapper div, which is why the dashboard rendered as a dark island
    on a cream page: the body kept the other palette and showed around the
    edges.
  - `app/static/js/theme-boot.js` runs synchronously from `<head>`, ahead of
    the stylesheet, and resolves "match system" itself. Deferring it flashes
    the wrong palette at exactly the person who cared enough to choose one. It
    is a separate file because the CSP is `script-src 'self'`.
  - The status colours are per-palette. The dark set reads at **2.7:1** on
    cream — not a colour you can put a word in — so light has its own, at 5:1
    or better. `themeTokens.test.js` fails if one palette gains a token the
    other lacks.

- **The navigation is responsive for real.** The public header used to drop
  every link but the last below 40rem with a `display: none`, which is not a
  responsive layout — it is `/cli` and `/docs` becoming unreachable on a phone.
  Both shells now move their navigation into a disclosure panel instead, and
  `navigation.test.jsx` asserts the narrow panel contains the *same*
  destinations as the wide bar rather than fewer.

  Found while doing it, and fixed: the React app had **no way to sign out** —
  `signOut()` existed in the API layer and nothing called it — and nineteen
  internal links were still `<a href>`, tearing down and re-booting the whole
  application to move one screen. Both are covered by tests now.

- **The React migration, finished.** Read this before touching anything in
  `app/routes/` or `app/templates/`.

  Every screen is React. `app/templates/` holds exactly two files:

  - `base.html`, which now only wraps the error page;
  - `error.html`, which **must keep working without the React bundle**,
    because one of the things it reports is the bundle being unavailable.

  How the two halves are wired, which still matters because the shape survives:

  - `app/routes/frontend.py` serves the React shell on an **explicit list** of
    paths (`SHELL_ROUTES`), never a catch-all. A catch-all would swallow any
    route not in it and turn a real 404 into a client-side one. The explicit
    list fails the safe way round, and it is also the inventory of what the
    application serves.
  - Browser JSON lives under `/api/internal/*`, session-cookie authenticated
    with CSRF. `/api/v1/*` remains bearer-key only, for the CLI. The two never
    mix; `tests/test_route_authorization.py` asserts it.
  - `/` is the one shell route that reads the session, to redirect somebody
    already signed in to their dashboard.

  **The admin panel is the same arrangement, and worth understanding
  separately.** `/admin/*` serves the shell like every other page and is
  deliberately **not** behind `require_admin`. The shell is the same bytes for
  a stranger and for an administrator and holds no data; everything on the
  panel comes from `/api/internal/admin/*`, which is behind
  `require_internal_admin` declared once on the router. Guarding the shell too
  would mean two places that have to agree about who is an administrator, and
  the redirect a guard produces is useless to the router that receives it.
  Three tests hold this up: the shell routes are reviewed as a group in
  `PUBLIC_ROUTES`, `TestTheAdminShellHoldsNothing` asserts the bytes really are
  identical, and `TestNonAdminIsRefusedByTheApi` sweeps every endpoint by
  prefix rather than by a list.

  Two admin guards are the last thing in front of something irreversible and
  are enforced server-side, not in the dialog:

  1. Deleting an account requires its address typed back. The modal is a
     courtesy; the check is what still applies to a hand-crafted request.
  2. Sending a campaign requires the recipient count the admin agreed to in the
     preview, and 409s if the audience moved in between. A screen saying 47
     while the send reaches 48 makes the count decorative.

  **Defects found by migrating**, each now with a named test:

  - The 2FA endpoint caught a `TwoFactorError` that `verify_code` never raises
    — it returns a bool. **Every wrong code created a session.**
  - The 2FA rate limit was given its own bucket. It must share the `login`
    buckets, or an attacker who has spent the password allowance gets a fresh
    budget for guessing six digits.
  - The password-reset limit used a literal `5` while
    `password_reset_rate_limit_per_ip` is `10`, and answered `200` when
    throttled — hiding the throttle from the person waiting for the mail.
  - The React contact form offered three category values the API rejects, so
    half its options returned "invalid request" for picking what we offered.
    `TestTheFormOffersOnlyRealCategories` reads the options out of the source
    and posts each one, because that is the only thing that fails when the two
    lists diverge again.
  - The admin user page dereferenced a nullable `manifest_kind`, which 500s the
    whole page for a project added by repository URL. Latent in the rendered
    panel too.

  If you add an endpoint under `/api/internal/`, two guardrails will fail until
  you declare it in `INTERNAL_SESSION_ROUTES` (and `PUBLIC_ROUTES` if it is
  reachable signed-out). That is the intended workflow, not an obstacle.

  **Known consequence, not yet decided:** `/`, `/pricing`, `/cli` and `/docs/*`
  are client-rendered with no SSR, so a crawler that does not run JavaScript
  sees an empty shell. The mitigation is to prerender those four at build time;
  their data endpoints are public and cacheable, so nothing else has to change.

- **API key scopes + CLI/web parity** — the machine API grew from one endpoint
  to seven, so keys grew a scope: `scan` (push a scan, the default and what
  every pre-existing key already was), `read` (findings, history, counts,
  supply-chain), `manage` (all of it, plus editing rules). Enforced by
  `require_scope()` in `app/deps.py`, which answers **403 and not 401** — the
  credential is genuine, and 401 would send a CI script into a retry loop over
  a permission problem no retry can fix.

  The reason this came before the CLI work rather than after: a project key
  lives in a CI environment variable, where anyone who can read a build log can
  take it. If that key could add an ignore rule, whoever took it could silence
  the alert for the CVE they were about to exploit. Splitting the scopes was
  the precondition for putting rule editing on the API at all.

  Two guardrails in `tests/test_route_authorization.py` pin this: the API
  surface is an explicit inventory, and every route's scope is read out of the
  `require_scope` closure actually attached to it, so a handler wired to the
  wrong dependency fails even if it looks right. Both were mutation-tested.

  The CLI now has `status`, `findings`, `history`, `supply-chain` and
  `rules list|ignore|unignore`, which is everything the dashboard shows except
  the admin portal — deliberately not on the CLI. Terminal charts live in
  `internal/ui/chart.go` and always print their own scale.

  **Verified against the live local stack, not just fakes**: a real `scan` key
  was refused on `findings` and on `rules ignore`; a real `manage` key added an
  ignore rule, the next scan moved the advisory from open to filtered with the
  reason attached, and `unignore` put it back. Two bugs only real data showed:
  a *next* check in the past rendered as "8 hours ago" (now "overdue by 8
  hours"), and failed scans were charted at their reported zero, drawing a
  trough that read as the week everything got fixed (now excluded and counted
  separately). Both have tests.

- **Contact / bug report** — `/contact`, public, not tier-gated, IP rate
  limited. An authenticated sender's address comes from their session, never
  the form. The row commits *before* the notification, so a mail outage costs
  the notification and not the report. Admin inbox at `/admin/inbox`.
- **Email service** (`app/services/email_service.py`) — one
  `send_templated(db, template=, recipient=, context=)`. Templates are plain
  text in `app/templates/email/` with the subject as the first line. Writes an
  `EmailLog` row whatever happens, including `SKIPPED`.
- **Admin compose & send** — `/admin/email`. Two-request send: preview resolves
  the audience and shows the count, send carries it back and is **refused with
  409 if it no longer matches**. `{{user_email}}` and `{{project_name}}`
  substitute per recipient; somebody with no project gets "your project" so the
  sentence still reads. Plain string replacement, never Jinja.
- **Webhook alerts (Pro)** — per project, two kinds. Settings → Webhook
  alerts: pick Discord (formatted embed) or a custom endpoint (flat JSON),
  save, send a test, remove. `tiers.py` says "Discord alerts" and it is true.
- **GitHub Action** — `action.yml` at the root of the CLI repo.
  `uses: itsmangooo/weedout-cli@v1`. Downloads a release binary for the
  runner, verifies the checksum, writes a step summary, upserts a PR comment.
  `action/test/e2e.sh` drives the real scripts against a mock API (29 checks).
- **CLI** — `--fail-on critical|high` and `--json`. Released as **v0.2.0**;
  `v1` is the floating tag the action resolves.
- **Tiered scan depth** — `MatchPolicy.max_depth`, set from the owner's plan in
  `scan_service.scan_target`. Free stops at depth 1, Pro is unlimited. Packages
  out of reach are **skipped before lookup and counted** as
  `unreached_by_depth`, never folded into the suppressed count: "not checked"
  and "checked and found nothing" must not look the same. Verified end to end —
  same lockfile, Free scanned 2 and found 0, Pro scanned 3 and found 6.
- **Custom scan rules (Pro)** — per-project severity thresholds and ignore
  rules with a required reason, plus `.weedout.yml` pushed from CI. The file
  beats the interface, per setting rather than all-or-nothing: a file that says
  nothing about ignores does not wipe out ignores set in the interface, and the
  two sets are unioned. A broken policy file is discarded whole and **fails
  open** — every rule in it stops applying, which can only mean more alerts,
  never fewer. `yaml.safe_load` only.
  **An ignore never survives a KEV listing.** A rule is a judgement about a
  risk at a moment in time; confirmed exploitation is new information about the
  same risk. The override is flagged on the match and marks the rule
  `overridden_at`, so the author sees it stopped applying rather than assuming
  it held. Verified end to end: 3 actionable → 0 with rules → 2 back after a
  KEV listing, with the non-listed rule still holding.
- **EPSS (all tiers to read, Pro to gate on)** — `app/core/epss.py` parses
  FIRST's daily CSV; `refresh_epss_scores` upserts it beside the KEV refresh
  under the same lock, independently so one feed failing does not cost the
  other. 362,881 real scores verified against the live feed. The score is on
  every finding (`CVEMatch.epss_score`, denormalised) and **gates nothing until
  a project sets `epss_threshold`** — the agreed decision, pinned by tests.
  Rendered as `.signal--epss`, a labelled number rather than a coloured word,
  because "high severity" and "high EPSS" answer different questions.
  `.weedout.yml` takes `epss: {alert_above: 0.5}`, and `50` is read as 50%.
- **Typosquat detection (Pro)** — `app/core/supply_chain.py`. Not naive edit
  distance, which flags `preact` as a typo of `react`: it reports only the
  shapes attackers actually use (transposition, confusable characters,
  one-character length change, separator swap), skips names under 5 characters
  because short names are dense, skips scoped npm packages, and carries an
  explicit `KNOWN_DISTINCT` list of legitimate near-neighbours. Bounded at
  distance **2**, not 1 — Levenshtein scores a transposition as two edits, so a
  limit of 1 silently drops `lodahs`. Tests sweep every popular package and
  every known neighbour for false positives.
  Results land in `SupplyChainFinding`, a separate table with its own
  `SignalLevel` (concerning / notable / informational) that deliberately shares
  no words with `Severity`.
- **Unmaintained / single-maintainer / provenance (Pro)** — the only checks
  that need somebody else's server, so they run off a `PackageMetadata` cache
  filled by `refresh_package_metadata_task` (hourly, TTL 7 days, 300/run, 8
  concurrent). A scan reads the cache and never reaches the network.
  **`None` means "not known", never zero and never no.** PyPI's JSON API has no
  maintainer count, so it stays unknown there rather than being guessed from a
  free-text author field; provenance is npm-only. A package with no cache row,
  or one whose fetch failed, raises no signal — which is not the same as coming
  back clean, and the tests say so.
  Verified live: sigstore reports provenance, left-pad is 8 years stale and
  deprecated, PyPI's unknowns stay null.
- **Dependency chains** — `Dependency.depth` / `.via`, persisted on both
  `DependencyRecord` and `CVEMatch` (denormalised, so a finding keeps its route
  after the next parse replaces the dependency rows). Rendered as "Found via
  top → middle → lodash" on every transitive finding. npm v2/v3 lockfiles hoist,
  so depth comes from a **breadth-first walk of the dependency graph**, not from
  the `node_modules/` path — a hoisted package looks direct in the path and is
  not.

### Earlier

Auth with Argon2id, DB-backed sessions, TOTP 2FA with backup codes, API keys,
Dodo billing, the scan pipeline against a local OSV mirror, KEV cross-
referencing, the alerts UI, docs, admin panel, CSV/JSON export, SSE, the design
system with four themes.

---

## What is NOT built

The user has asked for these; none exist. **Do not write pricing or docs copy
for them** — the pricing page was previously selling "Slack & Discord
webhooks" against a `tiers.py` entry commented "Not built yet", and that is the
mistake to avoid repeating.

| Feature | State |
|---|---|
| Admin: xlsx findings export | Nothing. Needs `openpyxl`. |
| Scope selector on the *account* settings key form | Built. Both key forms offer it and both key tables show it. |
| Admin: DB backup download | Nothing. `backup_service.run_backup` exists for the scheduled job. |
| Advisory curation queue | Nothing. |
| Web push notifications | Nothing. Needs `cryptography` for VAPID + RFC 8291. |
| i18n (en-GB/en-US/ro/ru/hr) | Nothing. |
| Flat-UI design mode, theme preset rework | Nothing. |
| Quick actions + right-click context menus | Nothing. |
| Profile page improvements | Nothing. |
| Favicon / logo upgrade | Nothing. |

Also unresolved:

- The CLI and action repo have **no licence** — currently all rights reserved,
  which blocks a Marketplace listing.
- Marketplace publication needs a manual tick on the release in GitHub's UI.
- Dodo API key and webhook secret were exposed earlier and should be rotated.
- `.env.prod` has `EMAIL_BACKEND=console`, so admin bootstrap mail is skipped.
- `ADMIN_BOOTSTRAP_NOTIFY_EMAIL` is `vjecn1@gmail.com`; the account is
  `vjecni1@gmail.com`. One of them is a typo.
- Global git config points `credential.helper` at `manager-core`, which does
  not exist here (the binary is `git-credential-manager`). Harmless warning on
  every git command; left alone because it is the user's environment.

---

## Next steps, in the order I would do them

1. **The React migration is done.** Kept here as the record of what moved and
   in what order, because the shape of a slice — a JSON endpoint under
   `/api/internal/`, a React screen, tests on both sides — is the pattern to
   follow for anything new. `internal_auth_actions.py` + `pages/LoginPage.jsx`
   is the worked example.

   | Slice | Templates retired | State |
   |---|---|---|
   | Auth (login, signup, 2FA, reset) | 7 | **Done** |
   | Projects (new, detail x3) | 5 | **Done** |
   | Alerts (index, detail) | 2 | **Done** |
   | Landing + legacy dashboard | 4 | **Done** |
   | Settings | 1 | **Done** |
   | Marketing (pricing, cli, contact, docs x2, hero partial) | 6 | **Done** |
   | Billing (+ success) | 2 | **Done** |
   | Admin | 12 | **Done** |
   | base.html, error.html | 2 | **Kept, on purpose** |

   `base.html` and `error.html` stay. `error.html` is the last server-rendered
   page and has to keep working without the React bundle, because one of the
   things it reports is the bundle being unavailable; `base.html` is what wraps
   it. Do not migrate them.

   The rule that governed every slice, in case another one is ever needed: do
   not delete a template before its React screen is serving the route. The
   deletion is the last step of a slice, not the first.

2. **Pricing / landing / docs copy.** Now unblocked: every Pro feature the
   earlier brief listed is real, and the CLI reaches all of it. Write it from
   `app/tiers.py`, and check the claims against the code rather than against
   the brief. The web `/cli` page and `/docs` still describe a CLI that only
   scans; they are now out of date in the direction of underselling.
2. The rest of the table above.

Known consequence of the migration, not yet addressed:

- **The public pages are no longer server-rendered.** `/`, `/pricing`, `/cli`
  and every `/docs/*` page are now a React shell, so a search engine has to
  execute JavaScript to see them. The data endpoints are public and cacheable,
  so the fix is a prerender step at build time rather than reverting anything.
  Nobody has decided whether it matters yet.
- **The legacy asset pipeline is now dead weight, and retiring it is a slice
  of its own.** `app/static/` still holds `css/weedout.css` (7k lines),
  `js/app.js`, `js/marketing.js` and `js/cli-hero.js`. They were the whole
  application's front end; the only page that loads any of them now is
  `error.html`, through `base.html`, and it needs a fraction of the CSS and
  none of the JavaScript beyond `theme.js`.

  Not done here because it is not a tail on the migration: `test_design_system.py`
  and `test_sessions_and_theme.py` are pinned to those files and would have to
  be rewritten or retired with them, and the page at stake is the one that has
  to render when everything else has failed. Do it deliberately: give
  `error.html` a small stylesheet of its own, make it standalone rather than
  extending `base.html`, then delete the rest and the tests that describe it.

- **`base.html`'s signed-in chrome can no longer render.** The sidebar,
  command palette and shortcut sheet only appear when the template context
  carries a `user`, which only happens when the *failing route* resolved a
  session — and every HTML route left is either a static shell or `/`, which
  redirects a signed-in visitor before it can fail. The chrome is therefore
  unreachable furniture, and it goes when the point above is done.

  One thing was salvaged rather than left: its sign-out form posts to
  `/logout`, which was deleted with the Jinja auth routes and had become a
  404. `/logout` is back in `internal_auth_actions.py` as a form-posting
  sibling of the JSON endpoint, sharing the same `revoke_session` call so
  there is one way to end a session and not two.

`weedout create` is built, and the conflict it was flagged for was resolved
rather than waved through. Creating a project does need a credential that
predates the project, and the answer was not to widen API keys: it is a
**second credential type**, `CliToken`, obtained by confirming in a browser.

    project key         one project. Pushes scans, reads findings. Lives in CI,
                        where a build log exposes it.
    machine credential  the account. Creates projects, mints keys. Cannot read
                        a single finding. Lives on a laptop.

Separate tables, separate namespace (`/api/account/*`), separate dependency.
`TestAccountApiSurface` in `test_route_authorization.py` asserts in both
directions that neither reaches the other's surface. The rule that keys are
per-project is intact; what changed is that there is now a credential which is
explicitly not a key.

---

## Launch readiness

What is left before this can take money, and who owns each. Everything in the
first table needs a decision or an account that only you can make.

| Blocker | State | Owner |
|---|---|---|
| Licences | **Done.** AGPL-3.0 server, MIT CLI, source link in the footer for AGPL §13 | — |
| `/terms`, `/privacy` | **Drafted** at `app/content/legal.py`, every legal decision marked `[[LIKE THIS]]`. `test_legal_pages.py` has two xfail tests that pass once the placeholders are gone — remove the markers in the same commit that fills them in | You: entity, jurisdiction, addresses, retention periods |
| `MAIL_RELAYHOST` | Empty. Warned at boot, and the warning explains the consequence: password-reset mail from a bare VPS is spam-foldered, which locks people out invisibly | You: a sending provider account |
| Secret rotation | Runbook in `DEPLOY.md`. The values pasted into a chat during setup have not been rotated | You: Dodo dashboard, Coolify |
| Off-box backups | **Implemented** (`BACKUP_S3_*`), switched off | You: bucket and credentials |
| Uptime monitoring | Nothing. `/status` reports feed freshness but runs *inside* the service, so it cannot report the service being down — that needs something watching from outside | You: pick a provider |
| Error monitoring | Nothing. Structured JSON logs with request ids exist; nothing aggregates or alerts on them | You: pick a provider |

Not blocking, but worth deciding:

- **Public pages are not server-rendered.** `/`, `/pricing`, `/cli`, `/status`,
  `/terms`, `/privacy` and every `/docs/*` page are a React shell, so a search
  engine has to run JavaScript to see them. The data endpoints are public and
  cacheable, so the fix is a prerender step at build time. Nobody has decided
  whether it matters.
- **`STATUS_SHOW_ADOPTION` is off**, so `/status` publishes feed health but not
  account or project counts. Turn it on when the numbers say something worth
  saying; a figure chosen to flatter would poison the honest half of that page.
- **The legacy asset pipeline is dead weight** — see below.

---

## Testing conventions

- Tests describe the property, not the method: `test_a_send_is_refused_if_the_audience_grew`.
- A guardrail test is only worth having if it fails on the real bug. Several
  here have a companion that proves it (`test_the_guard_would_notice`). Do that.
- `tests/test_admin_access.py` derives the route list from the app, so a new
  admin endpoint is covered automatically. Detail routes need a fixture row or
  they 404 for reasons unrelated to access control.
- `send_new_match_digest` does not commit — the caller does. A test that
  asserts on a persisted field must `await db.commit()` before `db.refresh()`,
  or it will reload the row and discard exactly what it is checking.

## Browser automation, for whoever picks this up

`resize_window` reports success and leaves the viewport unchanged, so mobile
layouts have not been visually confirmed — they are reasoned about from the CSS
instead, and the spacing scale deliberately lives outside the breakpoints so
phones inherit it. The automated tab is always backgrounded, so
`requestAnimationFrame` never fires and animation cannot be observed directly;
verify shader behaviour by compiling it into an offscreen context with
`preserveDrawingBuffer` and comparing frames at two times. The Chrome profile
also has `prefers-reduced-motion: reduce` set, which is why reduced-motion
paths are what render there by default.
