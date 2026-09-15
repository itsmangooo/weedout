# Deploying Weedout

Target setup: a single VM running Docker, with Cloudflare Tunnel terminating
TLS and forwarding through Coolify/Traefik to the web container. No application
or database port is published directly to the internet.

```
internet → Cloudflare edge (TLS) → cloudflared → Coolify/Traefik → web:8000
                                                                    ├── worker
                                                                    └── postgres (compose network only)
```

---

## 1. Prepare the configuration

```bash
git clone <repo> weedout && cd weedout
cp .env.prod.example .env.prod
```

Fill in `.env.prod`. Three values are required and the stack will not start
without them:

| Variable | How to produce it |
|---|---|
| `BASE_URL` | The public origin, e.g. `https://weedout.dev`. Must be `https://`. |
| `SECRET_KEY` | `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `POSTGRES_PASSWORD` | Same command. It is a real credential. |

Strongly recommended:

- `TRUSTED_CLIENT_IP_HEADER=cf-connecting-ip` — **required behind Cloudflare.**
  Without it every request appears to come from the tunnel, so the per-IP rate
  limits collapse into one shared bucket and the first brute-force attempt
  locks out every user. Cloudflare sets and overwrites this header at the edge,
  so a client cannot forge it. If you ever move off Cloudflare, change or unset
  it — pointing it at a header nothing sets lets anyone spoof their way past
  the limits.
- `MAIL_RELAYHOST` and its credentials. The stack ships its own SMTP relay, but
  it needs a provider to do the last mile — without one, password-reset mail is
  spam-foldered or rejected. See [Email](#email); it takes about five minutes.
- `ADMIN_BOOTSTRAP_NOTIFY_EMAIL` if you want the first admin created for you.
- `ADMIN_EMAIL` — the address promoted to admin on first sign-in.

`.env.prod` is gitignored. Never commit it.

### What is checked for you

Two independent layers, both fail loudly rather than starting in a bad state:

- **compose** uses `${VAR:?message}` for anything without a safe default, so a
  missing variable stops the deploy with a message naming it.
- **the app** re-validates at boot and refuses to serve in production with
  `DEBUG=true`, a placeholder or low-entropy `SECRET_KEY`, a non-`https`
  or `localhost` `BASE_URL`, `SESSION_COOKIE_SECURE=false`, or `DB_ECHO=true`.
  All problems are reported at once. See `_check_production_hardening` in
  `app/config.py`.

---

## 2. Start the stack

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d --build
```

This starts four containers:

- **db** — Postgres 17. No published host port; reachable only on the compose
  network.
- **mail** — a Postfix relay the app hands outbound mail to. No published port
  either. See [Email](#email) for the provider and DNS setup it needs.
- **web** — runs `alembic upgrade head` and then the server on container port
  `8000`, reachable through Coolify/Traefik. **Migrations run automatically on every deploy**;
  there is no manual step to forget, and `upgrade head` is a no-op when there is nothing
  to apply.
- **worker** — the scheduler: scans, KEV refresh, advisory mirror sync,
  subscription expiry, credential sweep.

All four use `restart: unless-stopped`, so a crash or a host reboot brings
them back.

Check it came up through the public origin and from inside the web container:

```bash
docker compose -f docker-compose.prod.yml ps
curl -s https://weedout.dev/healthz
docker compose -f docker-compose.prod.yml exec web \
  python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/healthz').read().decode())"
docker compose -f docker-compose.prod.yml logs web | grep app.config_warning
```

Any `app.config_warning` lines are configuration that is legal but probably not
what you want — read them before going further.

### Dashboard cutover verification

The image builds the locked React application with Node 24, copies only Vite's
immutable output into the Python runtime, and serves it from the same origin.
After each deployment verify:

```bash
curl -sS -D - -o /dev/null https://weedout.dev/dashboard
curl -sS -D - -o /dev/null https://weedout.dev/dashboard/legacy
```

`/dashboard` is the canonical React shell and must be non-cacheable. Hashed
`/assets/*` responses must be `public, max-age=31536000, immutable` and include
the main JS/CSS plus the lazy `DashboardPage-*` chunk. `/dashboard/legacy`
remains session-protected and is the temporary operational rollback path; do
not add it to product navigation.

In an authenticated browser, compare `/dashboard` with `/dashboard/legacy` for
the same account, then verify direct refresh, narrow layout, `/api/internal/*`
cookies, the readable `weedout_csrf` bootstrap, and the `/events` live indicator.
The event response sets `X-Accel-Buffering: no`, `Cache-Control: private,
no-cache, no-store, no-transform`, and `Vary: Cookie`; no additional Traefik or
Cloudflare rule should be added unless an observed production trace shows
buffering. Keep the existing CSP—same-origin scripts, styles, API calls, and
EventSource require no broader directive.

---

## 3. Seed the advisory mirror

**Do this before announcing the site.** Scans read from a local mirror of OSV's
advisory database. Until it is populated every scan fails loudly (by design —
an empty mirror would otherwise report every project clean, which is the most
dangerous wrong answer this product can give).

```bash
docker compose -f docker-compose.prod.yml exec worker \
  python -m app.jobs.runner sync-mirror
```

Takes roughly 20–30 minutes and downloads a few hundred megabytes. Expect
around 260,000 advisories across npm, PyPI and Go. It is not pulled on worker
boot, because paying that on every restart would make deploys slow — the
scheduled job keeps it fresh from then on (`MIRROR_REFRESH_HOURS`, default 12).

Confirm:

```bash
curl -s localhost:8000/readyz
# {"status":"ok", ..., "checks":{"advisory_mirror":"ok", "kev_feed":"ok", ...}}
```

`"advisory_mirror":"empty"` means the sync has not run or did not finish.

---

## 4. Point Cloudflare Tunnel at it

Install `cloudflared` on the host and create a tunnel with a public hostname of
`weedout.dev` routed to `http://127.0.0.1:8000`.

```yaml
# ~/.cloudflared/config.yml
tunnel: <tunnel-id>
credentials-file: /root/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: weedout.dev
    service: http://127.0.0.1:8000
  - service: http_status:404
```

```bash
cloudflared service install
systemctl enable --now cloudflared
```

The app sets HSTS, a strict CSP, `X-Frame-Options: DENY` and
`X-Content-Type-Options: nosniff` itself, so no extra Cloudflare rules are
needed for those. Leave Cloudflare's TLS mode on **Full (strict)** or higher.

---

## 5. Create the admin account

There is no admin password in the codebase and no "become admin" page — an
administrator is an ordinary account that has been promoted. There are three
ways to get the first one, in order of least effort.

### Automatic, on deploy

If no administrator exists, the app creates one for `ADMIN_EMAIL` with a
generated password and emails the plaintext **once** to
`ADMIN_BOOTSTRAP_NOTIFY_EMAIL`. Sign in with it and change it immediately.

It runs on web-container startup and is safe to hit repeatedly: an advisory lock
stops two replicas racing, and once an administrator exists it does nothing. It
will never regenerate an existing owner's password, and an account that already
matches `ADMIN_EMAIL` is promoted rather than replaced.

Two requirements, both of which make it skip loudly rather than half-work:

- `ADMIN_BOOTSTRAP_NOTIFY_EMAIL` must be set. It is deliberately *not*
  `ADMIN_EMAIL`: at the moment the account is created nobody can sign in to read
  mail sent to it, and a typo in `ADMIN_EMAIL` would deliver the credential to
  whoever owns the typo.
- `EMAIL_BACKEND` must be `smtp` or `resend`. **`console` is refused** — that
  backend "delivers" by writing the message body to the log, which would put a
  live admin password into the log stream.

Check what happened:

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  logs web | grep -E "admin_bootstrap|bootstrap\."
```

### Explicitly, as a deploy step

The same operation, with its outcome printed. Idempotent, so it is safe to leave
in a deploy script permanently:

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec web python -m app.manage ensure-admin
```

### By hand

Sign up normally at `https://weedout.dev/signup`, then promote that account.
This needs no email configuration at all:

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec web python -m app.manage promote-admin you@example.com
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec web python -m app.manage list-admins
```

Then open `/admin` and check **Feed health** — it leads the page. Every feed
should read `ok` with a plausible row count.

---

## Routine operations

### Deploying a change

```bash
git pull
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d --build
```

Migrations run as part of the web container's start command.

### Updating the built-in docs

The 14 built-in documentation pages are checked at web startup. Missing pages
are created. A page whose body exactly matches a previously shipped built-in
version is upgraded to the current copy, so untouched production docs follow a
deploy. Any page edited in `/admin/docs` has a different content hash and is
left alone.

Check deliberate customizations and replace them only when that is intended:

```bash
# Report which pages differ from this release. Changes nothing.
docker compose --env-file .env.prod -f docker-compose.prod.yml   exec web python -m app.manage reseed-docs

# Overwrite drifted pages. Discards edits made to those pages in /admin/docs.
docker compose --env-file .env.prod -f docker-compose.prod.yml   exec web python -m app.manage reseed-docs --force
```

Publication state and ordering are preserved; only title, summary and body are
replaced.

### Watching it

```bash
docker compose -f docker-compose.prod.yml logs -f web worker
```

Logs are JSON in production (`LOG_FORMAT=json`) with a request id on every line
within a request. Container logs are capped at 10 MB × 5 files per service, so
they cannot fill the disk.

Uvicorn's access log is deliberately silenced: it records the full request
target including the query string, which would write password-reset tokens into
the logs in plaintext. The app emits its own structured request line with
method, path, status and duration — and never the query.

### Rotating a secret

Every secret below can be replaced without downtime, and each one has a
different order of operations. Getting the order wrong is how a rotation turns
into an outage, so they are written out rather than left to be worked out at
the moment somebody is already worried.

**Rotate on a schedule, and rotate on suspicion.** Suspicion includes: a value
pasted into a chat window, a terminal, a screenshot, a ticket, or any log you
did not write yourself. A secret that has been *seen* by something that keeps
history is a secret that has been disclosed, whether or not anybody read it.
There is no way to un-see one, and the cost of rotating unnecessarily is ten
minutes.

| Secret | Where it lives | Blast radius if leaked |
|---|---|---|
| `SECRET_KEY` | `.env.prod` | Session cookies and signed challenges can be forged |
| `DODO_WEBHOOK_SECRET` | `.env.prod` + Dodo dashboard | Forged historical subscription records |
| `POSTGRES_PASSWORD` | `.env.prod` + the database | Everything |
| Email provider key | `.env.prod` + the provider | Mail sent as you, from your domain |
| Pusher / realtime credentials | `.env.prod` + the provider | Whatever that channel carries |

#### `SECRET_KEY`

Signs session cookies and the two-factor challenge. Changing it invalidates
every session, so everybody is signed out — which is the point when you are
rotating on suspicion.

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put it in `.env.prod`, redeploy. Nothing else to do; there is no other copy.

#### `DODO_WEBHOOK_SECRET`

This one is different: the secret is shared, so it cannot be rotated on one
side alone. Signature verification fails for everything sent with the other
value, and a rejected webhook is a historical record that silently did not
arrive.

1. Rotate it in the Dodo dashboard and copy the new value.
2. Put it in `.env.prod` and redeploy **immediately**.
3. Check the logs for `billing.webhook_signature_invalid` over the next few
   minutes.
4. If any events were rejected in the gap, replay them from the Dodo dashboard.

If the gap is a concern, take the outage deliberately: a few minutes of
rejected webhooks you know about and can replay beats a forged one you do not.

#### `POSTGRES_PASSWORD`

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec db psql -U weedout -c "ALTER USER weedout WITH PASSWORD 'new-value';"
```

Then update `.env.prod` (both `POSTGRES_PASSWORD` and the copy inside
`DATABASE_URL`) and redeploy. The running containers keep their open
connections until they restart, so the change and the redeploy do not have to
be simultaneous — but do not leave them apart for long, because anything that
reconnects in between fails.

#### Email and realtime provider keys

Same shape as the Dodo API key: create the new one, deploy it, verify, then
revoke the old. Verify by actually sending something — a password reset to an
address you control — rather than by the absence of errors. A mail key that is
wrong produces silence, and silence is what a working mail key produces too.

#### After any rotation

- Check `/readyz` and the admin feed board.
- Check the logs for authentication failures against whatever you rotated.
- Note the date. "When did we last rotate this?" should not need archaeology.

### Health endpoints

| Endpoint | Purpose |
|---|---|
| `/healthz` | Liveness. Touches nothing external. |
| `/readyz` | Readiness. 503 if the database is unreachable; reports feed and mirror state without failing on them. |

Both are unauthenticated and report states rather than details — no connection
strings, no exception text, nothing about how the app is wired together.

---

## Email

Weedout sends two things that must arrive: password-reset links, and the
one-time admin bootstrap password. Both are worthless in a spam folder.

The stack runs its own SMTP server — the `mail` service, Postfix — but it is a
**relay**, not a mail server that delivers to the internet itself:

```
app ──25──> mail (Postfix)  ──587 TLS──>  provider  ──> recipient
            in-stack queue              reputation + DKIM
```

### Why it relays instead of delivering directly

Running the last mile yourself from a VPS does not work in practice, and the
failure is silent:

- Cloud and VPS address ranges are on blocklists (Spamhaus PBL) by default.
- Most hosts block outbound port 25 and will not unblock it on request.
- A fresh IP has no sending reputation, so early mail is treated as suspect.
- Since February 2024 Gmail and Yahoo require SPF, DKIM and DMARC and enforce
  it. Mail that fails is rejected or filed as spam without a bounce you notice.

Handing off to a provider gets you their reputation and their DKIM signing. The
local Postfix still earns its place:

- **It queues.** `send_email` failing means a lost password reset. Postfix
  accepts the message immediately and retries for days, so a provider outage is
  invisible to users. Verified: with the provider stopped, the app's send still
  succeeds, the message sits in the queue, and it is delivered on recovery.
- **Credentials live in one container** instead of in the app.
- **Nothing is exposed.** The relay publishes no ports; only the Compose network
  can submit to it, and it refuses to relay for any sender domain except
  `MAIL_SENDER_DOMAIN`.

### 1. Pick a provider

Any SMTP provider works. Free tiers are enough for this volume.

| Provider | Relay host | Notes |
|---|---|---|
| Resend | `[smtp.resend.com]:587` | Simplest setup; also has an HTTP backend |
| Mailgun | `[smtp.mailgun.org]:587` | |
| Postmark | `[smtp.postmarkapp.com]:587` | Strong on transactional deliverability |
| Amazon SES | `[email-smtp.<region>.amazonaws.com]:587` | Cheapest at volume; starts sandboxed |

The square brackets are not decoration — they tell Postfix to use that host
directly instead of looking up its MX record.

Put the credentials in `.env.prod`:

```
MAIL_RELAYHOST=[smtp.resend.com]:587
MAIL_RELAYHOST_USERNAME=resend
MAIL_RELAYHOST_PASSWORD=re_...
MAIL_RELAYHOST_TLS_LEVEL=encrypt
MAIL_SENDER_DOMAIN=weedout.dev
MAIL_HOSTNAME=mail.weedout.dev
```

`MAIL_RELAYHOST_TLS_LEVEL=encrypt` refuses to hand the password over an
unencrypted connection. Do not lower it.

### 2. Add the DNS records

**This is the part that decides whether mail is delivered.** Your provider will
give you exact values; the shape is always the same. All on `weedout.dev`, via
Cloudflare DNS.

| Type | Name | Value | Purpose |
|---|---|---|---|
| TXT | `@` | `v=spf1 include:<provider> ~all` | Authorises the provider to send as you |
| CNAME/TXT | provider-specific | provided by the provider | DKIM signing key |
| TXT | `_dmarc` | `v=DMARC1; p=none; rua=mailto:you@weedout.dev` | Policy + failure reports |

Notes that catch people out:

- **One SPF record per domain.** If you already have one, merge the `include:`
  into it. Two TXT records both starting `v=spf1` is a permanent error and fails
  everything.
- **Start DMARC at `p=none`.** It reports without rejecting. Read the reports for
  a couple of weeks, then move to `p=quarantine` and eventually `p=reject`.
  Starting at `p=reject` with a misconfigured SPF blackholes your own mail.
- **Set the DKIM records to "DNS only" in Cloudflare** (grey cloud). Proxying a
  mail record breaks it.
- `MAIL_HOSTNAME` should resolve. An A record for `mail.weedout.dev` pointing at
  the host is enough; some providers reject a HELO that is not a real FQDN.

Check the records once they have propagated:

```bash
dig +short TXT weedout.dev
dig +short TXT _dmarc.weedout.dev
```

### 3. Verify it end to end

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec web python -m app.manage test-email you@gmail.com
```

That prints the resolved configuration, sends one message, and reports the
error if the relay refuses it. It tells you the relay *accepted* the message —
for the hop that actually matters, read the relay's log:

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  logs mail | grep -E "status=(sent|deferred|bounced)"
```

`status=sent` means the provider took it. Then **check the message did not land
in spam** — that is the failure mode that looks like success.

Inspect the queue if something is stuck:

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml exec mail postqueue -p
docker compose --env-file .env.prod -f docker-compose.prod.yml exec mail postqueue -f   # retry now
```

### Local development

`EMAIL_BACKEND=console` is the local default: messages are logged, nothing is
sent, and no test message can escape to a real address.

To actually look at an email — or to exercise the admin bootstrap, which refuses
to run on the console backend — start the mail catcher:

```bash
docker compose --profile mail up -d mailpit
```

Then set `EMAIL_BACKEND=smtp`, `SMTP_HOST=mailpit`, `SMTP_PORT=1025`,
`SMTP_USE_TLS=false` and read everything at <http://localhost:8025>. Mailpit
accepts any recipient and delivers nowhere.

### Troubleshooting

| Symptom | Cause |
|---|---|
| `Relay access denied` | Sender domain is not `MAIL_SENDER_DOMAIN` — check `EMAIL_FROM` |
| `Recipient address rejected: ... nullMX` | The recipient's domain publishes a null MX and accepts no mail. `example.com` does this; it is not a bug |
| `status=deferred`, `Connection refused` | `MAIL_RELAYHOST` wrong, or the host blocks outbound 587 |
| `authentication failed` | Wrong `MAIL_RELAYHOST_USERNAME` / `PASSWORD` |
| Mail sends but lands in spam | DNS. Recheck SPF, DKIM and DMARC — this is nearly always it |
| Nothing sends, no errors | `EMAIL_BACKEND` is still `console`; the app warns about this at startup |

---


## Backups

The advisory mirror and the KEV catalog are reproducible from upstream. Users,
projects, findings, dismissals, API keys and the audit log are not — losing the
database loses the product.

The worker takes a compressed `pg_dump` on a schedule, prunes old ones, and
pushes a copy off-box. It is on by default in `docker-compose.prod.yml`.

| Variable | Default | Notes |
|---|---|---|
| `BACKUP_ENABLED` | `true` in prod | Off by default elsewhere. |
| `BACKUP_INTERVAL_HOURS` | `24` | Daily. |
| `BACKUP_KEEP` | `7` | Local dumps retained; `0` disables pruning. |
| `BACKUP_S3_BUCKET` | *(unset)* | Set this to get dumps off the box. |
| `BACKUP_S3_ENDPOINT` | *(unset)* | `https://<account-id>.r2.cloudflarestorage.com` for R2. |
| `BACKUP_S3_ACCESS_KEY_ID` | *(unset)* | |
| `BACKUP_S3_SECRET_ACCESS_KEY` | *(unset)* | |
| `BACKUP_S3_PREFIX` | `weedout` | Key prefix within the bucket. |
| `BACKUP_S3_REGION` | `auto` | What Cloudflare R2 documents. |

### Off-box storage is the whole point

**A dump on the same disk as the database it came from protects against a bad
migration and nothing else.** If the host dies, the backups die with it.

Until `BACKUP_S3_BUCKET` is set, every run prints `local-only` and the admin
health board shows the backup row as **failing** — because a local-only backup
is not what anyone means by "we have backups".

Cloudflare R2 is the easy option: no egress fees, and you already have a
Cloudflare account for the tunnel.

1. **R2 → Create bucket**, named `weedout-backups`.
2. **R2 → Manage API tokens → Create token**, scoped to *Object Read & Write*
   on that bucket only. A token that can only write backups is one that cannot
   do anything else if the host is compromised.
3. Copy the Access Key ID, the Secret Access Key, and the S3 endpoint (it looks
   like `https://<account-id>.r2.cloudflarestorage.com`) into `.env.prod`.
4. Add a lifecycle rule on the bucket if you want retention beyond the local
   `BACKUP_KEEP` — the app prunes its own directory, never the bucket.

Any S3-compatible endpoint works (R2, S3, Backblaze B2, MinIO). Requests are
signed with SigV4 using only the standard library, so there is no AWS SDK in
the image.

### Taking one by hand

Do this before any risky migration. It runs exactly the same script the
schedule does:

```
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec worker python -m app.jobs.runner backup
```

Dumps land in the `backups` volume at `/var/backups/weedout`. To list them, or
copy one out to the host:

```
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec worker ls -la /var/backups/weedout

docker compose --env-file .env.prod -f docker-compose.prod.yml \
  cp worker:/var/backups/weedout/weedout-20260818T031500Z.sql.gz .
```

### Checking they are actually running

`/admin` → **Feed health** has a **Database backup** row showing the last
successful run and the dump size in bytes. It reads `failing` if the dump
failed *or* if it could not be copied off-box, and `stale` if nothing has
succeeded in twice the configured interval.

The size is worth a glance: a dump that is suddenly a few kilobytes is a broken
backup that every status field would otherwise call healthy.

```
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  logs worker | grep backup
```

### Restoring

**This is the part that makes a backup real.** Do the scratch-database version
now, while nothing is wrong, rather than reading it for the first time during
an outage.

The dump is plain SQL under gzip, so a restore is one pipe. It opens with
`DROP TABLE IF EXISTS` for everything it creates, so it also restores cleanly
over a database that already has objects.

**Into a scratch database — safe, changes nothing:**

```
docker compose --env-file .env.prod -f docker-compose.prod.yml exec worker sh -c '
  DUMP=/var/backups/weedout/weedout-20260818T031500Z.sql.gz
  ADMIN="postgresql://weedout:$POSTGRES_PASSWORD@db:5432/postgres"
  TARGET="postgresql://weedout:$POSTGRES_PASSWORD@db:5432/weedout_restore_test"

  psql "$ADMIN" -c "DROP DATABASE IF EXISTS weedout_restore_test WITH (FORCE)"
  psql "$ADMIN" -c "CREATE DATABASE weedout_restore_test"
  gunzip -c "$DUMP" | psql -q "$TARGET"
  psql "$TARGET" -c "SELECT count(*) AS users FROM users"
  psql "$TARGET" -c "SELECT count(*) AS projects FROM tracked_targets"
'
```

If those counts look right, the backup is good. Drop the scratch database when
you are done:

```
docker compose --env-file .env.prod -f docker-compose.prod.yml exec worker sh -c '
  psql "postgresql://weedout:$POSTGRES_PASSWORD@db:5432/postgres" \
    -c "DROP DATABASE IF EXISTS weedout_restore_test WITH (FORCE)"
'
```

**Over the live database — a real recovery:**

```
# 1. Stop everything that writes. The restore drops tables and will otherwise
#    block on open transactions.
docker compose --env-file .env.prod -f docker-compose.prod.yml stop web worker

# 2. Restore. The db container has psql; the dump comes in over stdin.
gunzip -c weedout-20260818T031500Z.sql.gz \
  | docker compose --env-file .env.prod -f docker-compose.prod.yml \
      exec -T db psql -q -U weedout -d weedout

# 3. Bring it back up. The web container runs `alembic upgrade head` on start,
#    so a dump taken against an older schema is migrated forward for you.
docker compose --env-file .env.prod -f docker-compose.prod.yml start web worker
```

From an off-box copy, fetch it first — anything that speaks S3 will do:

```
aws s3 cp --endpoint-url "$BACKUP_S3_ENDPOINT" \
  s3://weedout-backups/weedout/weedout-20260818T031500Z.sql.gz .
```

Afterwards, re-seed the advisory mirror if the dump predates the last sync. It
is large and reproducible, so it is not worth waiting on mid-recovery:

```
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  exec worker python -m app.jobs.runner sync-mirror
```

> **Still yours to decide:** how long to keep dumps in the bucket. The app
> prunes its own directory to `BACKUP_KEEP`; retention in R2 is a lifecycle
> rule, which only you can size against what you are willing to pay to store.

---


## Publishing the CLI to PyPI

`weedout-cli` is a separate distribution in `cli/`, published by
`.github/workflows/publish-cli.yml` on a `v*` tag. There is **no PyPI API token**
anywhere in this repository — uploads use Trusted Publishing (OIDC), where PyPI
exchanges a short-lived GitHub identity token for upload rights.

### One-time setup

The very first release has nothing on PyPI to attach a publisher to, so register
a *pending* one:

**PyPI → Account settings → Publishing → Add a pending publisher**

| Field | Value |
|---|---|
| PyPI project name | `weedout-cli` |
| Owner | `itsmangooo` |
| Repository | `weedout` |
| Workflow name | `publish-cli.yml` |
| Environment | `pypi` |

⚠ **The workflow filename is part of the credential.** If the registered name
and this file's name differ by even a character, the upload fails with "not a
trusted publisher" and retrying will never help. Same for the environment: the
workflow declares `environment: pypi`, so either register that name or delete the
block from the workflow. Nothing else authorises the upload, which is the point.

After the first successful release the publisher moves from pending to a normal
one under the project's own **Manage → Publishing**.

### Releasing

```bash
# 1. Bump the single source of truth.
#    cli/weedout_cli/__init__.py  ->  __version__ = "0.2.0"

# 2. Rehearse without publishing: Actions → Publish CLI → Run workflow.
#    Builds, checks metadata, and installs the wheel in a clean venv.

# 3. Tag and push.
git tag v0.2.0 && git push origin v0.2.0
```

The workflow refuses to publish when the tag and `__version__` disagree, checked
before anything is built — otherwise `v0.2.0` could ship a wheel that reports
`0.1.0`, and a version number on PyPI is only usable once.

### Locally, before tagging

```bash
cd cli
python -m build
python -m twine check --strict dist/*

python -m venv /tmp/smoke
/tmp/smoke/bin/pip install dist/*.whl
/tmp/smoke/bin/weedout --help
```

## Security posture

What is in place, and where it is enforced:

| Area | Where |
|---|---|
| Session cookies `HttpOnly` + `Secure` + `SameSite=lax`, server-side and instantly revocable | `app/routes/auth.py`, `app/config.py` |
| CSRF on every cookie-authenticated mutation (double-submit) | `app/deps.py`, audited by `tests/test_route_authorization.py` |
| Rate limits on login (per IP and per account), signup and password reset | `app/services/rate_limit_service.py` |
| API key auth for `/api/v1/scan`, hashed at rest, no cookie read | `app/deps.py`, `app/services/api_key_service.py` |
| Admin routes behind a router-level `require_admin`, 403 not 404 | `app/routes/admin.py` |
| Dodo webhook rejected unless the HMAC signature verifies | `app/routes/billing.py`, `app/security.py` |
| Argon2id passwords, transparently rehashed | `app/security.py` |
| Production config refusals | `app/config.py` |
| No secrets in logs; access log silenced | `app/logging_config.py` |

Every one of those has tests that fail if it is removed — see
`tests/test_route_authorization.py`, `tests/test_rate_limiting.py`,
`tests/test_production_config.py`, `tests/test_logging_hygiene.py` and
`tests/test_billing.py`.

### Rotating a secret

`SECRET_KEY` only signs the OAuth-state cookie; application sessions are
database rows, so rotating it does not sign anyone out. Change it in
`.env.prod` and redeploy.

Rotating `POSTGRES_PASSWORD` needs the database updated too:

```bash
docker compose -f docker-compose.prod.yml exec db \
  psql -U weedout -c "ALTER USER weedout PASSWORD 'new-value'"
# then update .env.prod and redeploy
```

---

## Troubleshooting

**The stack will not start and compose names a variable.** That variable is
missing from `.env.prod`. Add it.

**`Refusing to start in production with unsafe configuration`.** The app
checked its own settings and found something dangerous. The message lists every
problem; fix them all and redeploy.

**Every scan fails with a mirror error.** The advisory mirror is empty. Run the
sync from step 3.

**Users report being locked out of sign-in.** Check that
`TRUSTED_CLIENT_IP_HEADER` is set. Without it, all traffic through the tunnel
shares one rate-limit bucket.

**Password reset emails never arrive.** Check `EMAIL_BACKEND`. If it is
`console`, the messages are in the web container's logs rather than in
anyone's inbox.
