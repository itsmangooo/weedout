import { NextRequest } from "next/server";
import { csrfFailure,errorResponse,privateResponse,validCsrf } from "@/server/http/responses";
import { completeReset,ResetError } from "@/server/repositories/recovery";
export async function POST(request:NextRequest){if(!validCsrf(request))return csrfFailure(request);const body=await request.json().catch(()=>({})) as Record<string,unknown>;try{await completeReset(body.token,body.password,body.password_confirm);return privateResponse({data:{reset:true,message:"Password changed. Sign in with it."}},request);}catch(error){if(error instanceof ResetError)return errorResponse(400,error.code,error.message,request);throw error;}}
