import { NextRequest } from "next/server";
import { accountActionFailure, requireCsrf } from "@/server/http/account-action";
import { authenticated, privateResponse } from "@/server/http/responses";
import { disableTwoFactor } from "@/server/repositories/account-actions";
export async function POST(request: NextRequest) { const csrf=requireCsrf(request);if(csrf)return csrf;const auth=await authenticated(request);if("response" in auth)return auth.response;const body=await request.json().catch(()=>({})) as Record<string,unknown>;try{await disableTwoFactor(auth.user.id,body.password);return privateResponse({data:{two_factor_enabled:false}},request);}catch(error){return accountActionFailure(error,request);} }
