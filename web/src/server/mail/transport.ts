import "server-only";

import nodemailer from "nodemailer";

export class EmailError extends Error {}

function flag(name:string, fallback:boolean){const value=process.env[name];return value===undefined?fallback:value.toLowerCase()==="true";}

export async function sendEmail(to:string,subject:string,text:string){
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to))throw new EmailError("invalid recipient address");
  const backend=process.env.EMAIL_BACKEND??"console";
  const from=process.env.EMAIL_FROM??"Weedout <alerts@weedout.dev>";
  try{
    if(backend==="console"){
      console.info("email.console",{to,subject,text});
      return;
    }
    if(backend==="resend"){
      const apiKey=process.env.RESEND_API_KEY;
      if(!apiKey)throw new EmailError("RESEND_API_KEY is required");
      const response=await fetch(process.env.RESEND_API_URL??"https://api.resend.com/emails",{method:"POST",headers:{Authorization:`Bearer ${apiKey}`,"Content-Type":"application/json"},body:JSON.stringify({from,to:[to],subject,text}),signal:AbortSignal.timeout(30_000)});
      if(!response.ok)throw new EmailError(`Resend returned HTTP ${response.status}: ${(await response.text()).slice(0,300)}`);
      return;
    }
    if(backend==="smtp"){
      const host=process.env.SMTP_HOST;if(!host)throw new EmailError("SMTP_HOST is required");
      const secure=flag("SMTP_USE_SSL",false);
      const transporter=nodemailer.createTransport({host,port:Number(process.env.SMTP_PORT??(secure?465:587)),secure,requireTLS:flag("SMTP_USE_TLS",true)&&!secure,auth:process.env.SMTP_USERNAME?{user:process.env.SMTP_USERNAME,pass:process.env.SMTP_PASSWORD??""}:undefined,connectionTimeout:30_000,disableFileAccess:true,disableUrlAccess:true});
      await transporter.sendMail({from,to,subject,text});
      return;
    }
    throw new EmailError(`unknown email backend: ${backend}`);
  }catch(error){if(error instanceof EmailError)throw error;throw new EmailError(`${backend} delivery failed: ${String(error)}`);}
}
