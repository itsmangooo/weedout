import { NextRequest } from "next/server";
import { db } from "@/server/db/client";
import { requireCsrf } from "@/server/http/account-action";
import { authenticated,errorResponse,privateResponse } from "@/server/http/responses";
export async function POST(request:NextRequest,{params}:{params:Promise<{tokenId:string}>}){const csrf=requireCsrf(request);if(csrf)return csrf;const auth=await authenticated(request);if("response" in auth)return auth.response;const rows=await db()<Array<{id:number}>>`UPDATE cli_tokens SET revoked_at=coalesce(revoked_at,now()) WHERE id=${Number((await params).tokenId)} AND user_id=${auth.user.id} RETURNING id`;if(!rows.length)return errorResponse(404,"NOT_FOUND","That machine isn't signed in.",request);return privateResponse({data:{revoked:true}},request);}
