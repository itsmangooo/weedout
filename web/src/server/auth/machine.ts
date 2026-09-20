import "server-only";

import { NextRequest,NextResponse } from "next/server";
import { bearer,cliIdentity } from "./bearer";

export async function machineAuthenticated(request:NextRequest){const token=bearer(request);if(token?.startsWith("wo_")&&!token.startsWith("woa_"))return {response:machineError(403,"wrong_credential","That is a project key. This needs the machine credential from `weedout auth` — a project key cannot create projects.")};const identity=await cliIdentity(token);if(!identity)return {response:machineError(401,"unauthenticated",token?"That machine credential is not valid. Run `weedout auth` again.":"Run `weedout auth` to sign this machine in.",true)};return {identity};}
export function machineError(status:number,error:string,message:string,authenticate=false,extra:Record<string,unknown>={}){const headers:Record<string,string>={"Cache-Control":"no-store"};if(authenticate)headers["WWW-Authenticate"]="Bearer";return NextResponse.json({detail:{error,message,...extra}},{status,headers});}
export function machineResponse(body:unknown,status=200){return NextResponse.json(body,{status,headers:{"Cache-Control":"no-store"}});}
