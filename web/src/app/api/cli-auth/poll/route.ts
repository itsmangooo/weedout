import { randomBytes } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/server/db/client";
import { opaqueHash } from "@/server/auth/bearer";
type Pending={id:number;approved_by_user_id:number|null;approved_at:Date|null;denied_at:Date|null;collected_at:Date|null;expires_at:Date;device_label:string;email:string|null};
export async function POST(request: NextRequest) {
 const body=await request.json().catch(()=>({})) as {device_code?:unknown}; const code=typeof body.device_code==="string"?body.device_code:"";
 const rows=await db()<Pending[]>`SELECT r.id,r.approved_by_user_id,r.approved_at,r.denied_at,r.collected_at,r.expires_at,r.device_label,u.email FROM cli_auth_requests r LEFT JOIN users u ON u.id=r.approved_by_user_id WHERE r.device_code_hash=${opaqueHash(code)} LIMIT 1`;
 const row=rows[0]; if(!row||row.collected_at||row.expires_at<=new Date()) return NextResponse.json({state:"expired",interval:3},{headers:{"Cache-Control":"no-store"}}); if(row.denied_at)return NextResponse.json({state:"denied",interval:3},{headers:{"Cache-Control":"no-store"}}); if(!row.approved_at||!row.approved_by_user_id)return NextResponse.json({state:"pending",interval:3},{headers:{"Cache-Control":"no-store"}});
 const token=`woa_${randomBytes(32).toString("base64url")}`; await db().begin(async(sql)=>{await sql.unsafe("INSERT INTO cli_tokens (user_id,token_hash,prefix,device_label,expires_at) VALUES ($1,$2,$3,$4,now()+interval '180 days')",[row.approved_by_user_id,opaqueHash(token),token.slice(0,11),row.device_label]);await sql.unsafe("UPDATE cli_auth_requests SET collected_at=now() WHERE id=$1",[row.id]);});
 return NextResponse.json({state:"approved",token,email:row.email},{headers:{"Cache-Control":"no-store"}});
}
