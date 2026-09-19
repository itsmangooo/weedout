# Weedout Web migration application

`web/` is the Next.js application that will own Weedout's public pages,
dashboard, authentication, persistence, administration, notifications, docs,
integrations, and engine orchestration.

The migration is deliberately incremental. Filesystem routes implemented here
are owned by Next.js. The fallback rewrite sends every route not yet migrated
to `LEGACY_WEB_URL`, preserving current UI, cookies, CSRF, APIs, and data while
parity tests move one capability at a time. This boundary is temporary and
must disappear before the legacy application is removed.

```bash
npm install
LEGACY_WEB_URL=http://localhost:8000 ENGINE_INTERNAL_URL=http://localhost:8080 npm run dev
```

Current Next-owned routes:

- `GET /healthz`: web liveness.
- `GET /readyz`: private engine readiness through the web boundary.

`src/server/engine/client.ts` is server-only. Browser traffic does not call the
engine directly. `src/server/db/client.ts` connects to the existing PostgreSQL
database without changing or resetting it. The legacy Alembic migrations remain
schema authority until a verified baseline and dual-read parity suite are in
place; two migration systems must never write the same schema concurrently.

See `docs/migration/architecture-audit.md` and `route-ownership.md` at the
repository root for the migration gates.
