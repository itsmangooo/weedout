# Deploying Weedout

Target setup: a single VM running Docker, with Cloudflare Tunnel terminating
TLS and forwarding to the app on loopback. No ports open to the internet.

```
internet → Cloudflare edge (TLS) → cloudflared → 127.0.0.1:8000 → web
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
- `EMAIL_BACKEND` + SMTP credentials. Leaving it as `console` means password
  reset links are written to the log instead of being delivered. The app logs a
  warning at startup if you do.
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

This starts three containers:

- **db** — Postgres 17. No published host port; reachable only on the compose
  network.
- **web** — runs `alembic upgrade head` and then the server, bound to
  `127.0.0.1:8000`. **Migrations run automatically on every deploy**; there is
  no manual step to forget, and `upgrade head` is a no-op when there is nothing
  to apply.
- **worker** — the scheduler: scans, KEV refresh, advisory mirror sync,
  subscription expiry, credential sweep.

All three use `restart: unless-stopped`, so a crash or a host reboot brings
them back.

Check it came up:

```bash
docker compose -f docker-compose.prod.yml ps
curl -s localhost:8000/healthz
docker compose -f docker-compose.prod.yml logs web | grep app.config_warning
```

Any `app.config_warning` lines are configuration that is legal but probably not
what you want — read them before going further.

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

The admin is an ordinary account that has been promoted; there is no admin
password anywhere in the codebase.

1. Sign up at `https://weedout.dev/signup` with the address in `ADMIN_EMAIL`.
   It is promoted automatically on first sign-in.

Or, if you left `ADMIN_EMAIL` unset:

```bash
docker compose -f docker-compose.prod.yml exec web \
  python -m app.manage promote-admin you@example.com
docker compose -f docker-compose.prod.yml exec web \
  python -m app.manage list-admins
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

### Backups

Nothing here backs up the database. The advisory mirror and KEV catalog are
reproducible from upstream, but users, projects, findings, dismissals and the
audit log are not.

```bash
docker compose -f docker-compose.prod.yml exec -T db \
  pg_dump -U weedout weedout | gzip > weedout-$(date +%F).sql.gz
```

> **TODO (needs a decision):** schedule this and put the output somewhere off
> the box. Both the cadence and the destination are yours to choose.

### Health endpoints

| Endpoint | Purpose |
|---|---|
| `/healthz` | Liveness. Touches nothing external. |
| `/readyz` | Readiness. 503 if the database is unreachable; reports feed and mirror state without failing on them. |

Both are unauthenticated and report states rather than details — no connection
strings, no exception text, nothing about how the app is wired together.

---

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
