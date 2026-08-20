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

Current state: **1262 passed, 14 skipped, ruff clean.**

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
| Typosquat heuristic (name similarity, no advisory) | Nothing. Malicious-package *advisories* are handled — see below. |
| Unmaintained package risk | Nothing. |
| Provenance checks | Nothing. |
| Admin: xlsx findings export | Nothing. Needs `openpyxl`. |
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

1. **Typosquat heuristic** — edit distance against top packages per
   ecosystem. Pure core, Pro-gated. Malicious *advisories* are already handled.
2. **Unmaintained + provenance** — these need a `package_metadata` cache with a
   TTL and a refresh job: they are per-package outbound HTTP to the npm and
   PyPI registries, which must never happen inline in a scan.
3. The rest of the table above.

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
