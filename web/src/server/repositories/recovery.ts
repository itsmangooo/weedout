import "server-only";

import { createHash, randomBytes } from "node:crypto";
import { hashPassword, passwordProblem } from "@/server/auth/password";
import { db } from "@/server/db/client";
import { sendEmail } from "@/server/mail/transport";

const tokenHash=(token:string)=>createHash("sha256").update(token).digest("hex");
const emailPattern=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function requestReset(emailValue:unknown,ipAddress:string){
  const email=typeof emailValue==="string"?emailValue.trim().toLowerCase():"";
  if(!emailPattern.test(email)||email.length>320)return;
  const users=await db()<Array<{id:number;email:string;is_active:boolean;is_suspended:boolean}>>`SELECT id,email,is_active,is_suspended FROM users WHERE email=${email} LIMIT 1`;
  const user=users[0];if(!user||!user.is_active||user.is_suspended)return;
  const recent=await db()<Array<{count:string|number}>>`SELECT count(*) AS count FROM password_reset_tokens WHERE user_id=${user.id} AND created_at>=now()-interval '1 hour'`;
  if(Number(recent[0]?.count??0)>=Number(process.env.PASSWORD_RESET_MAX_PER_HOUR??5))return;
  const token=randomBytes(32).toString("base64url");
  await db()`INSERT INTO password_reset_tokens (user_id,token_hash,expires_at,requested_ip) VALUES (${user.id},${tokenHash(token)},now()+(${Number(process.env.PASSWORD_RESET_TTL_MINUTES??60)}*interval '1 minute'),${ipAddress.slice(0,64)||null})`;
  const ttl=Number(process.env.PASSWORD_RESET_TTL_MINUTES??60);const base=(process.env.BASE_URL??"http://localhost:3000").replace(/\/$/,"");
  const text=["Someone asked to reset the password for your Weedout account.","", "To choose a new one, open this link:","",`${base}/reset-password?token=${token}`,"",`The link works once and expires in ${ttl>=60?`${Math.floor(ttl/60)} hour${ttl>=120?"s":""}`:`${ttl} minutes`}.`,"","If this wasn't you, you can ignore this email. Your password has not changed."].join("\n");
  try{await sendEmail(user.email,"Reset your Weedout password",text);}catch(error){console.error("password_reset.email_failed",{userId:user.id,error:String(error)});}
}

export class ResetError extends Error{constructor(public code:string,message:string){super(message);}}
export async function completeReset(tokenValue:unknown,passwordValue:unknown,confirmValue:unknown){
  const token=typeof tokenValue==="string"?tokenValue:"";const password=typeof passwordValue==="string"?passwordValue:"";
  if(!token||token.length>512)throw new ResetError("INVALID_REQUEST","Enter a valid reset token.");
  if(password!==confirmValue)throw new ResetError("INVALID_REQUEST","Those passwords don't match.");
  const problem=passwordProblem(password);if(problem)throw new ResetError("WEAK_PASSWORD",problem);
  const passwordHash=await hashPassword(password);
  const changed=await db().begin(async(sql)=>{
    const records=await sql.unsafe<Array<{id:number;user_id:number}>>("SELECT p.id,p.user_id FROM password_reset_tokens p JOIN users u ON u.id=p.user_id WHERE p.token_hash=$1 AND p.used_at IS NULL AND p.expires_at>now() AND u.is_active=true AND u.is_suspended=false LIMIT 1 FOR UPDATE",[tokenHash(token)]);
    const record=records[0];if(!record)return false;
    await sql.unsafe("UPDATE password_reset_tokens SET used_at=now() WHERE user_id=$1 AND used_at IS NULL",[record.user_id]);
    await sql.unsafe("UPDATE users SET password_hash=$1,updated_at=now() WHERE id=$2",[passwordHash,record.user_id]);
    await sql.unsafe("UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL",[record.user_id]);
    return true;
  });
  if(!changed)throw new ResetError("INVALID_TOKEN","That reset link is no longer valid.");
}
