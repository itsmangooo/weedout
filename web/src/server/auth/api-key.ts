import "server-only";

import { createHash, randomBytes } from "node:crypto";

export function newApiKey() {
  const token = `wo_${randomBytes(32).toString("base64url")}`;
  return { token, hash: createHash("sha256").update(token).digest("hex"), prefix: token.slice(0, 11) };
}
