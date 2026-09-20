import "server-only";

import { hash, verify } from "@node-rs/argon2";

const options = {
  algorithm: 2,
  memoryCost: 19 * 1024,
  timeCost: 2,
  parallelism: 1,
  outputLen: 32,
};

const common = new Set([
  "password", "password1", "password123", "12345678", "123456789", "1234567890",
  "qwertyuiop", "letmein123", "iloveyou1", "adminadmin", "welcome123", "changeme123",
]);

export function passwordProblem(password: string): string | null {
  if (password.length < 10) return "Password must be at least 10 characters.";
  if (password.length > 1024) return "Password is too long.";
  if (common.has(password.toLowerCase())) return "That password is too common. Please choose another.";
  return null;
}

export async function hashPassword(password: string) {
  return hash(password, options);
}

export async function verifyPassword(passwordHash: string | null, password: string) {
  if (!passwordHash || password.length > 1024) return false;
  try { return await verify(passwordHash, password); } catch { return false; }
}
