import assert from "node:assert/strict";
import test from "node:test";

import { InvalidWebhook, validateWebhook } from "../src/server/webhooks/destination.ts";

test("Discord webhooks accept only the documented HTTPS destination shape", async () => {
  const valid = await validateWebhook(
    "https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz_123456",
    "discord",
  );
  assert.equal(valid.kind, "discord");
  assert.equal(valid.host, "discord.com");

  await assert.rejects(
    validateWebhook("https://discord.com.example/api/webhooks/123456/abcdefghijklmnopqrstuvwxyz", "discord"),
    InvalidWebhook,
  );
  await assert.rejects(
    validateWebhook("http://discord.com/api/webhooks/123456/abcdefghijklmnopqrstuvwxyz", "discord"),
    InvalidWebhook,
  );
});

test("custom webhook destinations refuse private network addresses", async () => {
  await assert.rejects(validateWebhook("https://127.0.0.1/hook", "custom"), InvalidWebhook);
  await assert.rejects(validateWebhook("https://[::1]/hook", "custom"), InvalidWebhook);
});
