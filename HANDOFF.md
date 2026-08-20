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

Current state: **1142 passed, 14 skipped, ruff clean.**

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
| Tiered scan depth (Free shallow / Pro full) | Nothing. `MatchPolicy` exists but `MatchPolicy(...)` is never constructed outside its own module — every scan uses `DEFAULT_POLICY`. |
| Dependency chain display ("found via: a → b → c") | Nothing. The parser does recurse, but no chain is stored on `CVEMatch`. |
| Custom scan rules / severity overrides / CVE suppression | Nothing. |
| `.weedout.yml` policy file | Nothing. The CLI's `.weedout` holds an API key and URL — a different thing. |
| EPSS scores | Nothing. |
| Malicious / typosquat detection | Nothing. |
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

1. **Tiered scan depth.** Add `max_depth` to `MatchPolicy`, pass it from the
   owner's tier in `scan_service._run_pipeline`, and store the resolved chain on
   `CVEMatch` so "found via" can be shown. Test that a Free project does not
   return a finding that only exists at depth 3.
2. **Custom scan rules.** Suppression with a required reason and an audit
   trail. **Judgment call to decide and document, not guess:** should a
   suppressed CVE auto-resurface when it becomes KEV-listed? My recommendation
   is yes — a suppression is a judgement about a risk profile that has since
   changed — but it must be stated in the docs either way.
3. **EPSS.** Surface as its own signal. **Do not fold it into severity tiering
   silently** — the user asked for this to be flagged. Suggest adding it as an
   off-by-default `MatchPolicy` flag so turning it on is a deliberate act.
4. The rest of the table above.

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
