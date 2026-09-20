import assert from "node:assert/strict";
import { access } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ownedRoutes = [
  "dashboard", "findings", "projects", "profiles", "settings", "landing", "pricing", "status", "docs",
];

const ownedNestedRoutes = [
  "admin/[...segments]",
  "alerts/[matchId]",
  "alerts/[matchId]/status",
  "auth/forgot-password",
  "auth/reset-password",
  "cli-tokens",
  "cli-tokens/[tokenId]/revoke",
  "contact",
  "projects/[targetId]/webhook",
  "projects/[targetId]/webhook/test",
  "projects/[targetId]/webhook/remove",
  "settings/organisation",
  "settings/showcase",
  "settings/alerts",
  "settings/password",
  "settings/sessions/[sessionId]/revoke",
  "settings/sessions/revoke-others",
  "settings/2fa/start",
  "settings/2fa/confirm",
  "settings/2fa/codes",
  "settings/2fa/disable",
  "settings/api-keys",
  "settings/api-keys/[keyId]/revoke",
];

test("core product routes are implemented by Next.js instead of relying on the legacy fallback", async () => {
  for (const route of ownedRoutes) {
    await assert.doesNotReject(access(path.join(process.cwd(), "src", "app", "api", "internal", route, "route.ts")));
  }
});

test("account, administration, finding detail and webhook routes are Next.js owned", async () => {
  for (const route of ownedNestedRoutes) {
    await assert.doesNotReject(access(path.join(process.cwd(), "src", "app", "api", "internal", ...route.split("/"), "route.ts")));
  }
  await assert.doesNotReject(access(path.join(process.cwd(), "src", "app", "events", "route.ts")));
});

test("machine APIs, billing webhook, exports and installers are Next.js owned", async () => {
  const routes = [
    "api/account/projects",
    "api/account/projects/[projectId]",
    "api/account/keys",
    "api/account/keys/regenerate",
    "api/account/whoami",
    "api/v1/[...segments]",
    "webhooks/dodo",
    "targets/[targetId]/[export]",
  ];
  for (const route of routes) {
    await assert.doesNotReject(access(path.join(process.cwd(), "src", "app", ...route.split("/"), "route.ts")));
  }
  await assert.doesNotReject(access(path.join(process.cwd(), "public", "install.sh")));
  await assert.doesNotReject(access(path.join(process.cwd(), "public", "install.ps1")));
});
