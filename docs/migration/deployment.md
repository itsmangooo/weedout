# Migration deployment and Coolify

During migration the deployable graph is:

```text
internet -> Coolify/Traefik -> weedout-web:3000
                                 |-> weedout-engine:8080 (private)
                                 |-> legacy:8000 (private fallback)
                                 `-> PostgreSQL:5432 (private)
worker -> PostgreSQL and advisory upstreams
```

Only `weedout-web` receives a public hostname. Do not assign a public domain or
host port to `weedout-engine`, `legacy`, or PostgreSQL. Configure:

- `LEGACY_WEB_URL=http://legacy:8000`
- `ENGINE_INTERNAL_URL=http://engine:8080`
- `ENGINE_DATABASE_URL=postgresql://...` for the private advisory mirror
- the existing `DATABASE_URL`, mail, secrets and proxy identity settings

Build `web/Dockerfile` as `weedout-web` and `engine/Dockerfile` as
`weedout-engine`. The engine is stateless and can scale independently when its
advisory provider is shared. The legacy worker and Alembic migration step remain
until their domains move to Next.js.

`docker-compose.migration.yml` is the local reference. It publishes Next.js on
port 3000, PostgreSQL only for local tools, and no engine or legacy host port.
The engine can also run alone with `docker build -t weedout-engine engine`.
Its `/healthz` endpoint reports process liveness. `/readyz` also verifies the
configured advisory provider and refuses readiness when the indexed mirror is
empty, avoiding false clean scans during an incomplete feed bootstrap.
