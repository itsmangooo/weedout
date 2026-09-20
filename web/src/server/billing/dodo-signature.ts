import { createHmac, timingSafeEqual } from "node:crypto";

function signingKey(secret: string) {
  const value = secret.trim().replace(/^whsec_/, "");
  try {
    const decoded = Buffer.from(value, "base64");
    if (decoded.length > 0 && decoded.toString("base64").replace(/=+$/, "") === value.replace(/=+$/, "")) return decoded;
  } catch { /* use the literal secret below */ }
  return Buffer.from(value, "utf8");
}

export function verifyDodoSignature(input: {
  body: Uint8Array;
  webhookId: string | null;
  timestamp: string | null;
  signature: string | null;
  secret: string;
  nowSeconds?: number;
  maxAgeSeconds?: number;
}) {
  const { body, webhookId, timestamp, signature, secret } = input;
  if (!webhookId || !timestamp || !signature || !secret) return false;
  const sentAt = Number(timestamp.trim());
  if (!Number.isInteger(sentAt) || Math.abs((input.nowSeconds ?? Date.now() / 1000) - sentAt) > (input.maxAgeSeconds ?? 300)) return false;
  const signed = Buffer.concat([Buffer.from(`${webhookId}.${timestamp.trim()}.`), Buffer.from(body)]);
  const expected = createHmac("sha256", signingKey(secret)).update(signed).digest("base64");
  for (const part of signature.split(/\s+/)) {
    const [version, candidate] = part.split(",", 2);
    if (version !== "v1" || !candidate) continue;
    const left = Buffer.from(expected);
    const right = Buffer.from(candidate);
    if (left.length === right.length && timingSafeEqual(left, right)) return true;
  }
  return false;
}
