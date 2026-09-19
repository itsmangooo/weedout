import "server-only";

import { cookies } from "next/headers";

// Session validation remains behind the legacy compatibility boundary until
// the Argon2, 2FA, CSRF, session rotation, and revocation parity suite moves.
export async function legacySessionCookie(): Promise<string | undefined> {
  const jar = await cookies();
  return jar.get(process.env.SESSION_COOKIE_NAME ?? "weedout_session")?.value;
}
