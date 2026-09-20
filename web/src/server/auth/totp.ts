import "server-only";

import { createHash, createHmac, randomInt, timingSafeEqual } from "node:crypto";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const backupAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

function decodeBase32(value: string) {
  const clean = value.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
  let bits = "";
  for (const character of clean) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("invalid base32");
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  return Buffer.from(bytes);
}

function codeAt(secret: string, counter: number) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", decodeBase32(secret)).update(buffer).digest();
  const offset = digest[digest.length - 1] & 15;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
}

export function verifyTotp(secret: string, submitted: string): number | null {
  const clean = submitted.replace(/\D/g, "");
  if (clean.length !== 6) return null;
  const step = Math.floor(Date.now() / 30_000);
  let matched: number | null = null;
  for (let delta = -1; delta <= 1; delta += 1) {
    const candidate = codeAt(secret, step + delta);
    if (timingSafeEqual(Buffer.from(candidate), Buffer.from(clean))) matched = step + delta;
  }
  return matched;
}

export function normalizeBackupCode(value: string) {
  return value.toUpperCase().replace(/[^ABCDEFGHJKMNPQRSTUVWXYZ23456789]/g, "");
}

export function backupCodeHash(value: string) {
  return createHash("sha256").update(normalizeBackupCode(value)).digest("hex");
}

export function generateTotpSecret() {
  return Array.from({ length: 32 }, () => alphabet[randomInt(alphabet.length)]).join("");
}

export function provisioningUri(secret: string, account: string, issuer = "Weedout") {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export function generateBackupCodes(count = 10) {
  return Array.from({ length: count }, () => {
    const raw = Array.from({ length: 10 }, () => backupAlphabet[randomInt(backupAlphabet.length)]).join("");
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  });
}
