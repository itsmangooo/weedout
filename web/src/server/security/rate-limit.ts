import "server-only";

import { createHash } from "node:crypto";
import { db } from "@/server/db/client";

export function rateLimitBucket(action:string,kind:string,value:string){return `${action}:${kind}:${createHash("sha256").update(value.trim().toLowerCase()).digest("hex").slice(0,32)}`;}
export async function rateLimitAllowed(bucket:string,limit:number,windowHours:number){
  if(limit<=0)return true;
  const rows=await db()<Array<{count:string|number}>>`SELECT count(*) AS count FROM rate_limit_hits WHERE bucket=${bucket} AND created_at>=now()-(${windowHours}*interval '1 hour')`;
  return Number(rows[0]?.count??0)<limit;
}
export async function recordRateLimitHit(bucket:string){await db()`INSERT INTO rate_limit_hits (bucket) VALUES (${bucket})`;}
