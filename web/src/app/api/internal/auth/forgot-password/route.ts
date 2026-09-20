import { NextRequest } from "next/server";
import { clientIp } from "@/server/http/client";
import { csrfFailure,errorResponse,privateResponse,validCsrf } from "@/server/http/responses";
import { requestReset } from "@/server/repositories/recovery";
import { rateLimitAllowed,rateLimitBucket,recordRateLimitHit } from "@/server/security/rate-limit";
export async function POST(request:NextRequest){if(!validCsrf(request))return csrfFailure(request);const bucket=rateLimitBucket("pwreset","ip",clientIp(request));if(!await rateLimitAllowed(bucket,Number(process.env.PASSWORD_RESET_RATE_LIMIT_PER_IP??10),1))return errorResponse(429,"RATE_LIMITED","Too many reset requests from here.",request);await recordRateLimitHit(bucket);const body=await request.json().catch(()=>({})) as Record<string,unknown>;await requestReset(body.email,clientIp(request));return privateResponse({data:{sent:true,message:"If that address has an account, a reset link is on its way."}},request);}
