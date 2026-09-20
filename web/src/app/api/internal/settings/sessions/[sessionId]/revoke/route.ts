import { NextRequest } from "next/server";
import { accountActionFailure, requireCsrf } from "@/server/http/account-action";
import { authenticated, privateResponse } from "@/server/http/responses";
import { revokeSessionById } from "@/server/repositories/account-actions";
export async function POST(request: NextRequest,{params}:{params:Promise<{sessionId:string}>}) { const csrf=requireCsrf(request);if(csrf)return csrf;const auth=await authenticated(request);if("response" in auth)return auth.response;try{await revokeSessionById(auth.user.id,Number((await params).sessionId));return privateResponse({data:{revoked:true}},request);}catch(error){return accountActionFailure(error,request);} }
