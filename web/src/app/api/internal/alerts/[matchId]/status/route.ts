import { NextRequest } from "next/server";
import { requireCsrf } from "@/server/http/account-action";
import { authenticated,errorResponse,privateResponse } from "@/server/http/responses";
import { setAlertStatus } from "@/server/repositories/alert-detail";
export async function POST(request:NextRequest,{params}:{params:Promise<{matchId:string}>}){const csrf=requireCsrf(request);if(csrf)return csrf;const auth=await authenticated(request);if("response" in auth)return auth.response;const body=await request.json().catch(()=>({})) as Record<string,unknown>;const result=await setAlertStatus(auth.user.id,Number((await params).matchId),body.status,body.note??"");if(result&&"error" in result)return errorResponse(400,"INVALID_REQUEST",result.error,request);if(!result)return errorResponse(404,"NOT_FOUND","That finding doesn't exist.",request);return privateResponse({data:result},request);}
