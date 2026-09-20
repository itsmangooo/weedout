import { NextRequest } from "next/server";
import { db } from "@/server/db/client";
import { authenticated, privateResponse } from "@/server/http/responses";
export async function GET(request: NextRequest) { const auth=await authenticated(request);if("response" in auth)return auth.response;const data=await db()<Array<{id:number;prefix:string;device_label:string;created_at:Date;last_used_at:Date|null;expires_at:Date}>>`SELECT id,prefix,device_label,created_at,last_used_at,expires_at FROM cli_tokens WHERE user_id=${auth.user.id} AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC`;return privateResponse({data},request); }
