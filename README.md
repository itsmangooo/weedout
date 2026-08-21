# Weedout

A reachable-CVE watchlist for small dev teams.

Connect a dependency manifest and get alerted only about vulnerabilities that
are **actually being exploited in the wild** (CISA KEV) or **severe and reachable
in the code you actually ship**. Everything else is recorded, counted, and left
alone — the number of advisories Weedout did *not* interrupt you with is shown
on the dashboard, and every one of them is browsable with the reason it was
filtered.

Supports `package.json`, `package-lock.json`, `requirements.txt` and `go.mod`.

---

## Quick start (Docker)

The fastest path to a running stack — app, worker and Postgres:

```bash
git clone <your-repo-url> weedout && cd weedout
cp .env.example .env

# Generate a real secret key and put it in .env
python -c "import secrets; print(secrets.token_urlsafe(48))"

docker compose up --build
```

Open <http://localhost:8000>. Migrations run automatically on the web
container's first start.

If port 5432 is already taken on your machine, set `POSTGRES_PORT` in `.env` to a
free port before starting. That only changes the host-side mapping — containers
still reach Postgres on 5432 internally.

## Local development (without Docker for the app)

You still need Postgres; the easiest way is to run just that container.

```bash
# 1. Postgres
docker compose up -d db

# 2. Virtual environment
python -m venv .venv
.venv/Scripts/activate        # Windows
# source .venv/bin/activate   # macOS / Linux
pip install -e ".[dev]"

# 3. Configuration
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into SECRET_KEY

# 4. Schema
alembic upgrade head

# 5. Run
python -m app
```

Open <http://localhost:8000>, create an account, and add a manifest. The first
scan runs immediately.

### React frontend migration

The controlled frontend migration lives in [`frontend/`](frontend/README.md). It runs as an
isolated Vite development application on <http://localhost:5173> and proxies requests to the
existing Python application on port 8000. Phase 5 makes the React view at `/dashboard` canonical,
serves its hashed build output from `/assets`, and retains the protected Jinja implementation at
`/dashboard/legacy` as an unlinked rollback path. Every mutation and all other product routes remain
unchanged.

> **Use `python -m app`, not `uvicorn app.main:app`.** When uvicorn is given an
> import string it creates its event loop *before* importing the application,
> which is too late to switch Windows off the `ProactorEventLoop` that psycopg
> cannot use. `app/__main__.py` sets the policy first, then starts uvicorn. It is
> the same entrypoint the container uses.

## Running the tests

```bash
pytest                    # everything
pytest tests/test_matching.py tests/test_versions.py tests/test_manifests.py
```

Integration tests need Postgres. They create a `weedout_test` database
automatically and roll back each test in a transaction. Point them elsewhere with
`WEEDOUT_TEST_DATABASE_URL`. If Postgres is unreachable, those tests skip and
the pure unit tests still run.

Lint and format:

```bash
ruff check .
ruff format .
```

---

## How the filtering works

This is the product, so it is worth stating plainly. A finding is surfaced when:

| Rule | Why it clears the bar |
|---|---|
| The CVE is in **CISA's KEV catalog** | Exploitation has been observed in the wild. Overrides everything, including dev-only scope. |
| **Critical** severity, ships to production | Critical findings in running code are actionable without waiting for evidence of exploitation. |
| **High** severity in a **direct** dependency | You can upgrade a direct dependency today. That is what makes it actionable rather than merely true. |

Everything else is suppressed with a recorded reason: dev-only dependency,
transitive and not exploited, below the severity threshold, or advisory
withdrawn.

Weedout reads manifests — it does **not** analyse your source code and will
never claim to know whether you call the vulnerable function.
[`docs/reachability.md`](docs/reachability.md) states exactly what "reachable"
means here and where the limits are.

### A manifest range is not an installed version

`"lodash": "^4.17.4"` could be any version from 4.17.4 up. Weedout assumes the
lowest version the range permits and **says so on every finding it affects**,
rather than presenting a guess as a fact. Upload a lockfile for exact answers.

### Data sources

- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** —
  the "this is actually being exploited" signal. Refreshed every 6 hours.
- **[OSV.dev](https://osv.dev)** — advisories, aggregating the GitHub Advisory
  Database, PyPA and the Go vulnerability database. Mirrored locally in full.

### The advisory mirror

The worker pulls OSV's per-ecosystem bulk exports into `vulnerabilities` and
`vulnerability_affected` on a schedule. **A scan performs no outbound HTTP at
all** — it is a parse plus a handful of indexed queries.

That is what makes a synchronous CI endpoint possible. A pipeline blocking on
`POST /api/v1/scan` waits on one database round trip rather than on somebody
else's uptime.

The trade is explicit: results are as fresh as the last successful sync. Three
things are in place because of it, and each exists to catch a specific way the
data can go quietly wrong:

- **Empty mirror refuses to scan.** Reporting every project clean because
  nothing is loaded is the most dangerous wrong answer this system can give, so
  it is a hard failure — `503` on the API, a failed run on the dashboard.
- **Stale mirror still scans, but says so.** Every response carries the warning
  rather than silently serving old data.
- **Row counts are recorded per ecosystem, per sync.** A feed that starts
  returning a fraction of its advisories still returns `200`, so the count is
  the only thing that gives it away. The admin panel lists each ecosystem
  separately: one aggregate "OSV" row could read green while the Go export had
  been failing for a week, and every Go user would be told they were clean.

Seed it on a fresh deployment with `python -m app.jobs.runner sync-mirror`.
The worker deliberately does *not* pull it on boot — it is hundreds of
megabytes, and paying that on every restart would make deploys slow.

---

## Architecture

```
app/
├── core/            Pure domain logic. No SQLAlchemy, no FastAPI, no settings.
│   ├── types.py       Shared enums and dataclasses
│   ├── versions.py    SemVer / PEP 440 ordering and range evaluation
│   ├── manifests.py   Parsing the four manifest formats
│   ├── cvss.py        CVSS v3.1 base scoring, severity normalisation
│   ├── osv.py         Raw OSV JSON -> Vulnerability
│   ├── matching.py    Triage: what is worth interrupting someone for
│   └── explain.py     Turning a decision into plain language
├── feeds/           HTTP clients for CISA KEV and OSV.dev
├── services/        Business logic over the database
├── routes/          Thin HTTP handlers
├── jobs/            Scheduled work (APScheduler) + a CLI runner
├── charts.py        SVG chart geometry (computed here so it's testable)
├── markdown.py      Markdown rendering, with raw HTML disabled
├── manage.py        Operator CLI: admin bootstrap
├── templates/       Jinja2, server-rendered
└── static/          CSS, screenshots, and vanilla JS (no build step)
```

Admin code is confined to `routes/admin.py` and `services/admin_service.py`, so
"what can an administrator do?" is answerable by reading two files rather than
grepping for privilege checks.

**`app/core/` is the important boundary.** Nothing in it may import SQLAlchemy,
FastAPI or application settings. All CVE matching is plain functions over plain
dataclasses, which is why the triage policy can be tested exhaustively without a
database, an HTTP client or a web request.

### Background jobs

Deliberately not Celery. The workload is a few periodic sweeps over a table
already in Postgres; a broker, a result backend and a worker fleet would be more
infrastructure than that needs, and a solo maintainer pays for it forever.

APScheduler runs in-process by default. Set `RUN_SCHEDULER_IN_WEB=false` and run
a dedicated worker (as `docker-compose.yml` does):

```bash
python -m app.jobs.runner loop          # scheduler in the foreground
python -m app.jobs.runner scan          # one sweep, then exit
python -m app.jobs.runner sync-mirror   # pull OSV advisories into the mirror
python -m app.jobs.runner refresh-kev   # pull the KEV catalog, then exit
python -m app.jobs.runner sweep         # purge expired sessions
```

The one-shot commands exist so cron or a systemd timer can drive everything
instead of a long-lived process. A PostgreSQL advisory lock makes it safe to run
several replicas — a second worker declines the tick rather than double-scanning
and double-emailing.

### Notification discipline

Three rules keep the volume honest, and they are tested:

1. Only findings triage marked actionable are ever emailed.
2. Each finding notifies **once** — `CVEMatch.notified_at` is the guard.
3. One scan produces one digest, not one email per CVE.

A finding you dismiss stays dismissed across re-scans. A finding that disappears
because you upgraded is marked resolved, not deleted. A resolved finding that
comes back re-notifies, because that is genuinely news. Scans you trigger
yourself do not also arrive by email — you are already looking at the results.

---

## Authentication

Email and password, with **server-side sessions**: the cookie carries a random
256-bit token and the database stores only its SHA-256 hash. Every request
validates against a row, which is precisely what makes logout and remote
revocation take effect immediately — the property a self-contained JWT cannot
offer.

- Passwords are hashed with Argon2id and transparently re-hashed on login when
  the parameters are out of date.
- **Changing a password** from Settings requires the current one, and signs the
  account out of every *other* session while reissuing the acting one.
- **Forgotten passwords** use an emailed single-use link — see below.
- Failed logins run a dummy verification so "no such user" and "wrong password"
  take the same time.
- All mutating routes are CSRF-protected (double-submit cookie).
- **Email and password is the only way in.** There is no social sign-in and no
  signed-cookie session middleware; the one credential path is the one above.

### Password reset

`/forgot-password` → emailed link → `/reset-password?token=…`.

The token is a bearer credential and is treated as one: 256 bits from
`secrets`, **only its SHA-256 hash is stored**, single-use, and valid for one
hour (`PASSWORD_RESET_TTL_MINUTES`). Redeeming it revokes every session on the
account *and* every other outstanding reset link — "I forgot my password" and
"someone else is in my account" overlap often enough to assume the worse one.

**The request step leaks nothing.** A registered address, an unregistered one,
a suspended account and a malformed address all produce the identical page.
`request_password_reset` returns `None` in every case and never raises, so
there is no value for a caller to branch on. A test asserts the responses are
byte-identical rather than merely similar.

Requests are capped per account per hour (`PASSWORD_RESET_MAX_PER_HOUR`,
default 5); without a cap the endpoint is a free mailbox-flooding tool aimed at
any address an attacker knows. Suspended accounts cannot be reset — that would
hand back an account an administrator deliberately closed — and suspending
someone invalidates any link already sitting in their inbox.

A successful reset does **not** sign the user in. Every session was just
revoked, and proving the new password works now beats discovering later that it
wasn't what they thought they typed.

### API keys

Machine callers authenticate with `Authorization: Bearer wo_…`. Same
construction as sessions — 256 bits from `secrets`, only the SHA-256 hash
stored — with three deliberate differences:

- **Scoped to one project, not to the account.** A CI runner builds one
  repository, so a key leaked from a build log can only push results for that
  repository. It also removes a class of mistake from the API: the client never
  names a destination project, so it cannot name the wrong one.
- **Shown once.** There is no code path that can recover the plaintext. "Show
  it again" is not a feature that was left out; it is the property that makes a
  database leak not also a credential leak.
- **`wo_` prefix.** A fixed prefix is what secret scanners key off. A key that
  looks like anonymous base64 is one nobody can flag on its way into a public
  repository.

`require_api_key` in `app/deps.py` is entirely separate from the session
dependencies. It reads no cookie — so a logged-in browser cannot be tricked
into making an authenticated API call, which is also why these routes need no
CSRF token — and every failure (missing, malformed, unknown, revoked,
suspended owner) produces one indistinguishable 401. Distinguishing "revoked"
from "unrecognised" would confirm to anyone holding a list of leaked strings
which ones were once real.

---

## Scanning from CI

```bash
pip install weedout-cli
export WEEDOUT_API_KEY=wo_...
weedout scan --ci
```

`weedout scan` finds a manifest, uploads it to `POST /api/v1/scan`, and prints
the counts. The endpoint is **synchronous** — no worker, no job id to poll —
because the caller is a pipeline that is blocking on the answer anyway. That is
affordable only because of the local mirror.

The CLI lives in `cli/` and ships as a **separate distribution** (`weedout-cli`)
with **no runtime dependencies**. It gets installed into the same environment as
the project being built, so anything it brought with it would become a version
constraint someone else's build has to satisfy — to solve a problem that is one
POST request and one argument parser wide. `urllib` and `argparse` are enough.

Detection prefers the file that states a fact: `package-lock.json` over
`package.json`. `node_modules` is never searched, and the walk is two levels
deep — a repository root is where a manifest lives, and wandering through a
monorepo would make the tool report on an arbitrary sub-package.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | The scan ran. Nothing blocking. |
| `1` | The scan ran and found something critical or actively exploited (`--ci` only). |
| `2` | The scan did **not** run — bad key, unreachable service, no manifest. |

The gap between `1` and `2` is the point. A pipeline that treats every non-zero
exit as "vulnerabilities found" will eventually treat an expired API key as a
security finding, and someone will fix it by deleting the step. Without `--ci`,
findings are reported and the command still exits `0`: adding a security tool
should not be the thing that breaks the build first.

### Key resolution order

`--api-key` → `WEEDOUT_API_KEY` → `api_key` in `.weedout`.

The environment beating the file is the one that matters. CI injects secrets as
environment variables, and a `.weedout` that got committed must never quietly
override the key the pipeline was configured with — authenticating as the wrong
account is worse than failing to authenticate at all.

A composite GitHub Action is in `.github/action.yml`, referenced as
`uses: itsmangooo/weedout/.github@v1`. The path suffix is required from that
location — GitHub resolves a bare `owner/repo@ref` to an `action.yml` at the
repository root, so moving the file there is all it takes to shorten it.

---

## Documentation

Public docs at `/docs`, written and edited by the administrator at
`/admin/docs`. A deliberately small CMS — slug, title, Markdown body, published
flag, manual ordering. Anything more (revisions, per-page permissions, draft
preview links) is machinery for a team, and there is one author.

**Raw HTML is disabled in the Markdown renderer.** Only an admin can author
pages, so this is not the last line of defence — but a CMS that renders
arbitrary HTML turns any future compromise of one admin account, or one careless
paste from an external source, into stored XSS across the public site. Turning
it off costs nothing (Markdown expresses everything a docs page needs) and
removes the need for an HTML sanitiser entirely, because no untrusted HTML is
ever produced.

Drafts are invisible to everyone: `/docs/<slug>` returns 404 for an unpublished
page whether the visitor is anonymous, signed in, or the administrator. Editing
happens in the admin panel, so "unpublished" means the same thing to everybody.

Four starter pages — getting started, uploading a lockfile, understanding
severity tiers, CI integration — are seeded on first boot, idempotently by slug,
so redeploying never duplicates them or overwrites your edits. Their content is
lifted from this README and `docs/reachability.md` rather than rewritten, so
there is one explanation of the product's behaviour.

The editor is a textarea with a live preview. The preview renders a small
Markdown subset client-side just to check structure while writing; what
publishes is always rendered server-side by the real parser.

## Landing page

The **Recently flagged** section is live data — the most recent critical or
actively-exploited findings across every account, deduplicated by (CVE, package)
and cached for five minutes.

Everything shown is already public: package names, versions, CVE ids and
advisory summaries, published by npm, PyPI, Go and OSV. `app/services/public_service.py`
never selects a user id, an email, a project name or a manifest, and
`tests/test_landing.py` asserts none of those appear in the response.
Suspended accounts are excluded, and one popular vulnerable package appears once
rather than once per customer — repetition would leak how many customers use it.

When there is no data the section is **absent**, not filled with invented
examples. The entire claim of that section is that it is real.

Animations are CSS transitions driven by one `IntersectionObserver`. They
respect `prefers-reduced-motion`, degrade to plain visible content with
JavaScript off, and carry a failsafe that reveals everything after three
seconds — a decorative animation must never be able to leave content
permanently invisible.

## Admin panel

A single super-admin, at `/admin`. Four sections plus an audit log.

### Appointing the admin

There is deliberately no "become admin" page. Two routes, both requiring access
the host rather than a browser:

```bash
# 1. Set ADMIN_EMAIL in the environment. That address is promoted the first
#    time it signs in (or signs up). It must be a real account.
ADMIN_EMAIL=you@example.com

# 2. Or appoint one from a shell.
python -m app.manage promote-admin you@example.com
python -m app.manage demote-admin  you@example.com   # refuses to remove the last one
python -m app.manage list-admins
```

Both paths write to the audit log, so an admin appearing is never invisible.

### Access control

`require_admin` is declared on the router, so it applies to every route under
`/admin` including ones added later without a second thought.

- Anonymous visitors are redirected to log in.
- A signed-in **non-admin** gets a hard **403** — not a redirect (which would
  loop), and not a 404 (hiding the URL protects nothing while making a real
  misconfiguration harder to spot).

Hiding the nav link is presentation, not security. `tests/test_admin_access.py`
enumerates the admin routes **from the running application** and asserts a
non-admin gets 403 on every one, so a new endpoint is covered automatically
rather than depending on someone remembering to add it to a list.

### What's in it

| Section | What it shows |
|---|---|
| **Overview** | Feed health, platform counts, and cumulative signups |
| **Users** | Paginated + searchable list; per-user detail, projects, alert history |
| **Billing** | MRR, active/on-hold/cancelled counts, subscriber list |
| **Docs** | Create, edit, publish and delete documentation pages |
| **Audit log** | Every administrative action, append-only |

**Feed health leads the overview on purpose.** If CISA KEV or OSV silently
stops returning data, nothing visibly breaks — scans still succeed, dashboards
still render, and every user is quietly told they have no vulnerabilities. That
is the failure mode most worth surfacing in a product whose whole claim is
knowing what's exploited.

### Actions

- **Change tier** — for comps, support credits and refunds. Deliberately does
  *not* touch the Dodo subscription fields, which the webhook owns; the audit
  entry records that the change was a manual override.
- **Suspend / unsuspend** — reversible, and destroys nothing. Suspension blocks
  sign-in, invalidates open sessions on their next request, and removes the
  account's projects from the scan queue (so a suspended account stops
  consuming OSV quota and stops emailing someone who can't sign in to act on
  it). Manifests, findings and history are untouched, so unsuspending restores
  the account exactly as it was.

- **Delete** — permanent, and gated on typing the account's email address.
  Removes the account, its tracked projects, dependencies, findings, scan
  history, alert records, sessions and reset tokens, by `ON DELETE CASCADE` at
  the database level rather than an application loop, so nothing is orphaned
  even if it is ever run outside the ORM. The shared advisory cache is global
  and is deliberately left alone.

An admin cannot suspend or delete themselves, or another admin, and the last
remaining administrator cannot be deleted or demoted — otherwise the only
administrator can lock everyone out of the panel that would undo it. That check
(`is_last_admin`) is shared by the web delete path and
`python -m app.manage demote-admin`, so the two cannot disagree.

The deletion is recorded in the audit log **with the email retained**.
`AdminAuditLog.target_user_id` is `ON DELETE SET NULL` while `target_email` is
a plain column, so the entry — and every earlier entry about that account —
survives the row it describes. An audit trail that loses the identity of the
thing it describes records nothing worth having.

### Revenue figures

MRR is summed from what the Dodo webhooks stored, not from a live API call:
this page is checked often and shouldn't hang because Dodo is slow. Annual
plans are divided by twelve, and a multi-period cadence ("every 3 months") is
folded into its interval unit. Comped Pro accounts with no subscription are
counted and reported separately, so the headline is an explicit floor rather
than a quietly wrong number. Anything with financial consequence — refunds,
disputes — links out to Dodo rather than being reimplemented here.

## Billing

[Dodo Payments](https://dodopayments.com), chosen because it acts as merchant of
record and handles VAT and sales tax globally — which matters when the seller is
outside the usual merchant jurisdictions. The alternative is registering for tax
in every market you sell into.

| | Free | Pro |
|---|---|---|
| Projects | 1 | Unlimited |
| Check frequency | Daily | Every 4 hours |
| Email alerts | Yes | Yes |
| Slack / Discord webhooks | — | Planned |
| History | 30 days | 365 days |

Plan limits live in one place, `app/tiers.py`. Nothing else in the codebase
branches on `user.tier` directly, so changing pricing means editing one table.

To enable checkout, set `DODO_ENABLED=true` plus the API key, webhook secret and
product ID. The app refuses to start if any are missing rather than silently
running with billing half-configured.

Checkout is a plain link to Dodo's hosted page — no embedded SDK, so no
third-party script runs on the site and the Content-Security-Policy stays strict
even with billing switched on. The account is identified by a `reference_id`
passed at checkout and echoed back on every webhook, so a payment ties to the
right account even when the customer pays with a different email.

Point a Dodo webhook at `POST /webhooks/dodo`. **The webhook is the only thing
that grants paid access** — the browser is never trusted to report that a payment
succeeded. Signatures follow the [Standard Webhooks](https://www.standardwebhooks.com)
spec: HMAC-SHA256 over `{id}.{timestamp}.{raw body}` with the base64-decoded
signing secret, plus a timestamp check so a captured webhook cannot be replayed
to keep resetting a cancelled subscription to active.

`on_hold` is Dodo's dunning state and **keeps** paid access — locking someone out
while their bank retries is how you lose a customer who was about to pay.

Cancellations honour time already paid for: the webhook records an end date and
an hourly job applies the downgrade once that date passes.

## Email

Three backends, selected by `EMAIL_BACKEND`:

- `console` — logs the message. The local default, so development needs no mail
  server and no test message can escape to a real address.
- `smtp` — any submission service.
- `resend` — Resend's HTTP API, for hosts that block outbound SMTP.

---

## Configuration

Everything is environment-driven; see [`.env.example`](.env.example) for local
development and [`.env.prod.example`](.env.prod.example) for a deployment.
Nothing that must be secret has a default — the process refuses to boot rather
than run with a guessable key.

Selected variables:

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | *(required)* | Min 32 chars. Signs the OAuth state cookie. |
| `DATABASE_URL` | *(required)* | Note the `+psycopg` driver suffix. |
| `BASE_URL` | `http://localhost:8000` | Used in email links and OAuth redirects. Must be https in production. |
| `TRUSTED_CLIENT_IP_HEADER` | `cf-connecting-ip` | Which header carries the real client IP. See below. |
| `RUN_SCHEDULER_IN_WEB` | `true` | Set false when running a dedicated worker. |
| `SCAN_TICK_MINUTES` | `15` | How often the sweep looks for due targets. |
| `KEV_REFRESH_HOURS` | `6` | How often the KEV catalog is re-pulled. |
| `MIRROR_REFRESH_HOURS` | `12` | How often OSV's bulk exports are re-pulled. |
| `MIRROR_STALE_AFTER_HOURS` | `48` | Past this, scans warn rather than fail. |
| `API_SCAN_MAX_BYTES` | `5 MB` | Upload cap on `POST /api/v1/scan`. |
| `API_SCAN_RATE_LIMIT_PER_HOUR` | `60` | Scans per **project** per hour. |
| `LOGIN_RATE_LIMIT_PER_IP` | `15` | Failed sign-ins per IP per window. |
| `LOGIN_RATE_LIMIT_PER_ACCOUNT` | `8` | Failed sign-ins per account per window. |
| `LOGIN_RATE_LIMIT_WINDOW_MINUTES` | `15` | The window both apply over. |
| `SIGNUP_RATE_LIMIT_PER_IP` | `5` | Accounts creatable per IP per hour. |
| `PASSWORD_RESET_RATE_LIMIT_PER_IP` | `10` | Reset requests per IP per hour. |
| `EMAIL_BACKEND` | `console` | `console`, `smtp` or `resend`. |
| `DODO_ENABLED` | `false` | Requires three more values when true. |
| `ADMIN_EMAIL` | *(unset)* | Promoted to super-admin on first sign-in. |
| `PASSWORD_RESET_TTL_MINUTES` | `60` | Lifetime of a reset link. |
| `PASSWORD_RESET_MAX_PER_HOUR` | `5` | Reset emails per account per hour. |

### Production refuses unsafe configuration

With `ENVIRONMENT=production` the settings validator refuses to start on
`DEBUG=true`, a placeholder or low-entropy `SECRET_KEY`, a non-`https` or
`localhost` `BASE_URL`, `SESSION_COOKIE_SECURE=false`, or `DB_ECHO=true`. Every
problem is reported at once rather than one per restart.

These are all *silent* failures otherwise: the app boots, serves pages and looks
healthy while cookies go out without `Secure` or the deployment runs on a key
published in a public example file. `_check_production_hardening` in
`app/config.py`; `tests/test_production_config.py`.

A second, softer list is logged at startup (`app.config_warning`) for
configuration that is legal but probably unintended — `EMAIL_BACKEND=console`
in production, an unset proxy header, no admin.

### Rate limiting

Login, signup and password reset are limited; the scan API is limited per
project. Counted in Postgres rather than in process memory, because the app can
run as more than one replica and an in-process counter would multiply every
limit by however many are up and reset on each deploy.

Sign-in counts **failures only**, against two buckets — per IP and per account.
A legitimate user is never throttled by their own successful sign-ins, and an
office behind one NAT address is not collectively locked out for one person's
typo. The check runs *before* the Argon2 verification, so a rejected attempt
costs one indexed count rather than 19 MiB and real CPU.

`TRUSTED_CLIENT_IP_HEADER` is load-bearing for this. Behind a proxy every
request arrives from the proxy's address, so without it the per-IP limits
collapse into a single shared bucket and the first attacker locks out
everybody. Set it to the header your proxy sets — and **unset it** if the app
is not behind one, or anyone can spoof a fresh bucket per request.

## Deploying

See [DEPLOY.md](DEPLOY.md) and
[`docker-compose.prod.yml`](docker-compose.prod.yml). Migrations run
automatically on every deploy as part of the web container's start command.

### Database migrations

Alembic from day one. Never edit the schema by hand.

```bash
alembic upgrade head                              # apply
alembic revision --autogenerate -m "add column"   # after editing app/models.py
alembic check                                     # fail if models and schema disagree
alembic downgrade -1                              # roll back one
```

`alembic check` is worth running in CI: it catches a model change that nobody
generated a migration for.

## Operations

- `GET /healthz` — liveness. Touches nothing external.
- `GET /readyz` — readiness. Returns 503 if the database is unreachable. A stale
  KEV catalog is *reported* but does not fail the check: the app still serves,
  and briefly-old exploitation data is not a reason to pull an instance out of
  rotation.

Logs are structured via `structlog` — human-readable locally, JSON in production
(`LOG_FORMAT=json`), with a request ID bound to every line within a request.

### Email

The production stack runs its own SMTP server — a Postfix **relay**, not a mail
server that delivers to the internet itself. The app hands messages to it over
the Compose network; it hands them to a provider.

Direct delivery from a VPS does not work in practice: cloud address ranges are
blocklisted by default, most hosts block outbound port 25, and Gmail and Yahoo
have required SPF+DKIM+DMARC since 2024. Password-reset mail would be
spam-foldered without a bounce anyone notices.

The local Postfix still earns its keep. `send_email` failing loses a password
reset; Postfix accepts the message and retries for days, so a provider outage is
invisible to users. It publishes no port and refuses to relay for any sender
domain but its own, so it cannot become an open relay.

```bash
# Verify delivery without triggering a real password reset.
docker compose --env-file .env.prod -f docker-compose.prod.yml   exec web python -m app.manage test-email you@example.com
```

Locally, `EMAIL_BACKEND=console` logs messages instead of sending them. To read
one — or to exercise the admin bootstrap, which refuses the console backend
because it would log the generated password — start the catcher:

```bash
docker compose --profile mail up -d mailpit   # then http://localhost:8025
```

Provider setup and the DNS records are in [DEPLOY.md](DEPLOY.md#email).

### Backups

The worker takes a compressed `pg_dump` daily (`scripts/backup.sh`), prunes to
`BACKUP_KEEP`, and pushes a copy to any S3-compatible bucket when one is
configured. Signed with SigV4 from the standard library — no AWS SDK in the
image. On by default in `docker-compose.prod.yml`, off elsewhere.

Two things are deliberate. A dump is written under a temporary name and only
renamed once `pg_dump`'s completion marker and a gzip integrity check both pass,
because a truncated dump is indistinguishable from a good one until the day you
need it. And a dump that could not be copied off-box shows as **failing** on the
admin health board rather than green: a backup on the same disk as the database
survives a bad migration and nothing else.

Take one by hand before a risky migration:

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec worker python -m app.jobs.runner backup
```

The restore procedure — including a safe scratch-database rehearsal — is in
[DEPLOY.md](DEPLOY.md#restoring). `tests/test_backup.py` dumps, restores into a
scratch database and reads the rows back, so "it restores" is asserted rather
than assumed.

---

## What is deliberately not built yet

- **No source-code scanning.** This is dependency-manifest matching. See
  `docs/reachability.md`.
- **No Slack/Discord webhooks.** The email path works end to end first; the tier
  flag exists so adding them touches one table.
- **No GitHub sign-in.** It was started and removed rather than left
  half-finished. Re-adding it means re-answering the question that stopped it:
  linking a GitHub identity to an existing password account by matching email
  addresses is an account-takeover path unless the address is known-verified on
  both sides. Nothing in the schema or the config presumes an answer any more,
  which is the point — the next attempt starts from that decision.
- **No GitHub App / repo auto-sync.** Manual upload and the CLI are enough to
  validate the idea. `TrackedTarget.repo_url` is reserved for it. Unrelated to
  sign-in.
- **No `/insights` page.** The aggregate queries exist and are parameterised by
  window (`trending_cves`, `trending_packages` in `public_service.py`); only the
  landing section consumes them today. A standalone page is a template away, and
  would not be paid-gated — it is public information about public packages.

## License

Not yet chosen.
