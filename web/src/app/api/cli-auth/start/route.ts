import { randomBytes } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/server/db/client";
import { clientIp } from "@/server/http/client";
import { opaqueHash } from "@/server/auth/bearer";
const alphabet = "ABCDEFGHJKMNPQRTUVWXY34679";
function userCode() { const chars = Array.from({ length: 8 }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join(""); return `${chars.slice(0,4)}-${chars.slice(4)}`; }
export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({})) as { device_label?: unknown };
  let code = userCode(); for (let i=0;i<5;i+=1) { const clash=await db()<Array<{id:number}>>`SELECT id FROM cli_auth_requests WHERE user_code=${code}`; if (!clash.length) break; code=userCode(); }
  const device = randomBytes(32).toString("base64url");
  await db()`INSERT INTO cli_auth_requests (user_code, device_code_hash, device_label, ip_address, expires_at) VALUES (${code}, ${opaqueHash(device)}, ${typeof body.device_label === "string" ? body.device_label.trim().slice(0,120) : ""}, ${clientIp(request)}, now()+interval '10 minutes')`;
  const base=(process.env.BASE_URL ?? request.nextUrl.origin).replace(/\/$/,"");
  return NextResponse.json({ user_code: code, verification_url: `${base}/cli-auth?code=${code}`, verification_url_plain: `${base}/cli-auth`, device_code: device, expires_in: 600, interval: 3 }, { headers: { "Cache-Control": "no-store" } });
}
