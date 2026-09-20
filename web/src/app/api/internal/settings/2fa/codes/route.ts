import { NextRequest } from "next/server";
import { accountActionFailure, requireCsrf } from "@/server/http/account-action";
import { authenticated, privateResponse } from "@/server/http/responses";
import { regenerateCodes } from "@/server/repositories/account-actions";
export async function POST(request: NextRequest) { const csrf=requireCsrf(request);if(csrf)return csrf;const auth=await authenticated(request);if("response" in auth)return auth.response;try{return privateResponse({data:{backup_codes:await regenerateCodes(auth.user)}},request);}catch(error){return accountActionFailure(error,request);} }
