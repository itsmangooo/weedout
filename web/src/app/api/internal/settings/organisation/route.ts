import { NextRequest } from "next/server";
import { accountActionFailure, requireCsrf } from "@/server/http/account-action";
import { authenticated, privateResponse } from "@/server/http/responses";
import { setOrganisation } from "@/server/repositories/account-actions";
export async function POST(request: NextRequest) { const csrf=requireCsrf(request); if(csrf)return csrf; const auth=await authenticated(request);if("response" in auth)return auth.response;const body=await request.json().catch(()=>({})) as Record<string,unknown>;try{return privateResponse({data:await setOrganisation(auth.user,body.name,body.website)},request);}catch(error){return accountActionFailure(error,request);} }
