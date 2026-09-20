import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import { verifyDodoSignature } from "../src/server/billing/dodo-signature.ts";

test("Dodo signatures use the raw body and decoded whsec key", () => {
  const key = Buffer.from("test signing key");
  const secret = `whsec_${key.toString("base64")}`;
  const body = Buffer.from('{"type":"subscription.active"}');
  const timestamp = "1800000000";
  const signature = createHmac("sha256", key).update(Buffer.concat([Buffer.from(`msg_1.${timestamp}.`), body])).digest("base64");
  assert.equal(verifyDodoSignature({ body, webhookId: "msg_1", timestamp, signature: `v1,${signature}`, secret, nowSeconds: 1800000000 }), true);
  assert.equal(verifyDodoSignature({ body: Buffer.from("{}"), webhookId: "msg_1", timestamp, signature: `v1,${signature}`, secret, nowSeconds: 1800000000 }), false);
});

test("Dodo signatures reject stale deliveries", () => {
  assert.equal(verifyDodoSignature({ body: Buffer.from("{}"), webhookId: "msg", timestamp: "1", signature: "v1,bad", secret: "secret", nowSeconds: 1000 }), false);
});
