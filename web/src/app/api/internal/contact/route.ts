import { NextRequest } from "next/server";
import { resolveSession,SESSION_COOKIE } from "@/server/auth/session";
import { db } from "@/server/db/client";
import { clientIp } from "@/server/http/client";
import { csrfFailure,errorResponse,privateResponse,validCsrf } from "@/server/http/responses";
import { sendEmail } from "@/server/mail/transport";
import { rateLimitAllowed,rateLimitBucket,recordRateLimitHit } from "@/server/security/rate-limit";
const emailPattern=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;const categories=new Set(["bug","feedback","billing","other"]);
export async function POST(request:NextRequest){
  if(!validCsrf(request))return csrfFailure(request);const ip=clientIp(request);const bucket=rateLimitBucket("contact","ip",ip);
  if(!await rateLimitAllowed(bucket,5,1))return errorResponse(429,"RATE_LIMITED","That is a lot of messages in one hour. Give it a little while, or email us directly if it is urgent.",request);
  const body=await request.json().catch(()=>({})) as Record<string,unknown>;const message=typeof body.message==="string"?body.message.trim():"";
  if(message.length<10||message.length>8000)return errorResponse(400,"INVALID_REQUEST","Tell us a bit more — at least a sentence.",request);
  const category=typeof body.category==="string"&&categories.has(body.category)?body.category:"other";
  const sessionToken=request.cookies.get(SESSION_COOKIE)?.value;const user=sessionToken?await resolveSession(sessionToken):null;
  const email=user?.email??(typeof body.email==="string"?body.email.trim().toLowerCase():"");
  if(!emailPattern.test(email)||email.length>320)return errorResponse(400,"INVALID_REQUEST","We need an address to reply to.",request);
  await recordRateLimitHit(bucket);
  const rows=await db()<Array<{id:number}>>`INSERT INTO contact_messages (user_id,email,category,message,user_agent,ip_address) VALUES (${user?.id??null},${email},${category},${message},${request.headers.get("user-agent")?.slice(0,300)||null},${ip.slice(0,64)||null}) RETURNING id`;
  const admin=process.env.ADMIN_EMAIL??process.env.ADMIN_BOOTSTRAP_NOTIFY_EMAIL;
  if(admin){const text=[`Category: ${category}`,`From: ${email}`,`Account: ${user?"yes":"no (logged out)"}`,"",message,"",`${(process.env.BASE_URL??"http://localhost:3000").replace(/\/$/,"")}/admin/inbox/${rows[0].id}`].join("\n");try{await sendEmail(admin,"New Weedout contact message",text);await db()`UPDATE contact_messages SET notified_at=now() WHERE id=${rows[0].id}`;}catch(error){console.error("contact.notify_failed",{messageId:rows[0].id,error:String(error)});}}
  return privateResponse({data:{sent:true,message:"Thanks — that reached us. We reply to everything, usually within a day."}},request);
}
