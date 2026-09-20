import { NextRequest } from "next/server";
import { setSessionCookie } from "@/server/auth/lifecycle";
import { clientIp } from "@/server/http/client";
import { accountActionFailure, requireCsrf } from "@/server/http/account-action";
import { authenticated, privateResponse } from "@/server/http/responses";
import { changePassword } from "@/server/repositories/account-actions";
export async function POST(request: NextRequest) { const csrf=requireCsrf(request);if(csrf)return csrf;const auth=await authenticated(request);if("response" in auth)return auth.response;const body=await request.json().catch(()=>({})) as Record<string,unknown>;try{const token=await changePassword(auth.user.id,body.current_password,body.new_password,request.headers.get("user-agent"),clientIp(request));const response=privateResponse({data:{changed:true,message:"Password changed. Other sessions were signed out."}},request);setSessionCookie(response,token);return response;}catch(error){return accountActionFailure(error,request);} }
