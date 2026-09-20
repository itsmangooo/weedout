import { NextRequest } from "next/server";
import {
  AdminError,auditData,billingData,changeUser,deleteDoc,deleteUserAccount,docsData,emailComposer,
  inboxData,inboxMessage,overviewData,previewEmail,saveDoc,sendCampaign,setInboxStatus,userData,usersData,
} from "@/server/admin/service";
import { clientIp } from "@/server/http/client";
import { authenticated,csrfFailure,errorResponse,privateResponse,validCsrf } from "@/server/http/responses";

async function admin(request:NextRequest){const auth=await authenticated(request);if("response" in auth)return auth;if(!auth.user.isAdmin)return {response:errorResponse(403,"ADMIN_REQUIRED","Administrator access is required.",request)};return auth;}
function fail(error:unknown,request:NextRequest){if(error instanceof AdminError)return errorResponse(error.status,error.code,error.message,request);throw error;}
export async function GET(request:NextRequest,{params}:{params:Promise<{segments:string[]}>}){const auth=await admin(request);if("response" in auth)return auth.response;const parts=(await params).segments;try{
  if(parts[0]==="overview"&&parts.length===1)return privateResponse({data:await overviewData(request.nextUrl.searchParams.get("days"))},request);
  if(parts[0]==="users"&&parts.length===1){const result=await usersData(request.nextUrl);return privateResponse({data:result.payload,query:result.query},request);}
  if(parts[0]==="users"&&parts.length===2)return privateResponse({data:await userData(Number(parts[1]))},request);
  if(parts[0]==="billing"&&parts.length===1)return privateResponse({data:await billingData()},request);
  if(parts[0]==="docs"&&parts.length===1)return privateResponse({data:await docsData()},request);
  if(parts[0]==="docs"&&parts.length===2)return privateResponse({data:await docsData(Number(parts[1]))},request);
  if(parts[0]==="inbox"&&parts.length===1)return privateResponse({data:await inboxData(request.nextUrl.searchParams.get("show"))},request);
  if(parts[0]==="inbox"&&parts.length===2)return privateResponse({data:await inboxMessage(Number(parts[1]))},request);
  if(parts[0]==="email"&&parts.length===1)return privateResponse({data:await emailComposer()},request);
  if(parts[0]==="audit"&&parts.length===1)return privateResponse({data:await auditData()},request);
  return errorResponse(404,"NOT_FOUND","No such admin endpoint.",request);
}catch(error){return fail(error,request);}}

export async function POST(request:NextRequest,{params}:{params:Promise<{segments:string[]}>}){if(!validCsrf(request))return csrfFailure(request);const auth=await admin(request);if("response" in auth)return auth.response;const parts=(await params).segments;const body=await request.json().catch(()=>({})) as Record<string,unknown>;const ip=clientIp(request);try{
  if(parts[0]==="users"&&parts.length===3&&["suspend","unsuspend","showcase"].includes(parts[2]))return privateResponse({data:{user:await changeUser(auth.user,Number(parts[1]),parts[2],body,ip)}},request);
  if(parts[0]==="users"&&parts.length===3&&parts[2]==="delete")return privateResponse({data:await deleteUserAccount(auth.user,Number(parts[1]),body.confirm_email,ip)},request);
  if(parts[0]==="docs"&&parts.length===1)return privateResponse({data:await saveDoc(auth.user,undefined,body,ip)},request);
  if(parts[0]==="docs"&&parts.length===2)return privateResponse({data:await saveDoc(auth.user,Number(parts[1]),body,ip)},request);
  if(parts[0]==="docs"&&parts.length===3&&parts[2]==="delete")return privateResponse({data:await deleteDoc(auth.user,Number(parts[1]),ip)},request);
  if(parts[0]==="inbox"&&parts.length===3&&parts[2]==="status")return privateResponse({data:await setInboxStatus(auth.user,Number(parts[1]),body,ip)},request);
  if(parts[0]==="email"&&parts.length===2&&parts[1]==="preview")return privateResponse({data:await previewEmail(body)},request);
  if(parts[0]==="email"&&parts.length===2&&parts[1]==="send")return privateResponse({data:await sendCampaign(auth.user,body,ip)},request);
  return errorResponse(404,"NOT_FOUND","No such admin endpoint.",request);
}catch(error){return fail(error,request);}}
