import { NextRequest } from "next/server";
import { authenticated,errorResponse,privateResponse } from "@/server/http/responses";
import { alertDetail } from "@/server/repositories/alert-detail";
export async function GET(request:NextRequest,{params}:{params:Promise<{matchId:string}>}){const auth=await authenticated(request);if("response" in auth)return auth.response;const detail=await alertDetail(auth.user.id,Number((await params).matchId));if(!detail)return errorResponse(404,"NOT_FOUND","That finding doesn't exist.",request);return privateResponse(detail,request);}
