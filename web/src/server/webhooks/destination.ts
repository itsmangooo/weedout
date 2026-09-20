import { lookup } from "node:dns/promises";
import ipaddr from "ipaddr.js";

const discordHosts=new Set(["discord.com","discordapp.com","canary.discord.com","ptb.discord.com"]);
const discordPath=/^\/api(?:\/v\d{1,2})?\/webhooks\/(\d{5,25})\/([A-Za-z0-9_-]{20,120})\/?$/;
export class InvalidWebhook extends Error{}

function parsed(raw:unknown,max:number){
  const value=typeof raw==="string"?raw.trim():"";if(!value)throw new InvalidWebhook("Paste the URL to post to.");
  if(value.length>max)throw new InvalidWebhook("That URL is too long.");if(/[\s\x00-\x1f]/.test(value))throw new InvalidWebhook("That URL contains spaces or line breaks.");
  let url:URL;try{url=new URL(value);}catch{throw new InvalidWebhook("That is not a valid URL.");}
  if(url.protocol!=="https:")throw new InvalidWebhook("The URL has to start with https://.");
  if(url.username||url.password)throw new InvalidWebhook("That URL should not contain a username or password.");
  return {value,url};
}
export async function validateWebhook(raw:unknown,kind:unknown){
  const type=kind==="custom"?"custom":"discord";const {value,url}=parsed(raw,type==="custom"?500:300);
  if(type==="discord"){
    if(!discordHosts.has(url.hostname)||url.port)throw new InvalidWebhook("That is not a Discord webhook URL. It should begin https://discord.com/api/webhooks/.");
    if(url.search||url.hash||!discordPath.test(url.pathname))throw new InvalidWebhook("That looks like a Discord link but not a webhook. Copy the Webhook URL from Discord's integration settings.");
  }else{
    if(url.port&&url.port!=="443")throw new InvalidWebhook("Only the standard https port is allowed.");
    let addresses:{address:string}[];try{addresses=await lookup(url.hostname,{all:true,verbatim:true});}catch{throw new InvalidWebhook(`That hostname does not resolve: ${url.hostname}`);}
    if(!addresses.length)throw new InvalidWebhook(`That hostname does not resolve: ${url.hostname}`);
    for(const {address} of addresses){let ip=ipaddr.parse(address);if(ip.kind()==="ipv6"&&(ip as ipaddr.IPv6).isIPv4MappedAddress())ip=(ip as ipaddr.IPv6).toIPv4Address();if(ip.range()!=="unicast")throw new InvalidWebhook("That address is inside a private network. A webhook has to point somewhere reachable from the public internet.");}
  }
  return {url:value,kind:type,host:url.hostname};
}

export async function deliverWebhook(url:string,kind:string,project:string){
  const destination=await validateWebhook(url,kind);
  const payload=kind==="custom"?{source:"weedout",event:"webhook.test",project,message:"This is a test from Weedout. Real alerts carry findings."}:{username:"Weedout",embeds:[{title:"Webhook connected",color:0x6d4de8,description:`This is a test message for **${project.slice(0,100)}**.\n\nReal alerts arrive here only when a finding clears the project's rules.`,footer:{text:"Weedout · test message"}}]};
  let response:Response;try{response=await fetch(destination.url,{method:"POST",headers:{"Content-Type":"application/json","User-Agent":"weedout"},body:JSON.stringify(payload),redirect:"manual",signal:AbortSignal.timeout(10_000)});}catch(error){return {ok:false,error:error instanceof DOMException&&error.name==="TimeoutError"?"Discord did not answer in time.":"Could not reach the webhook endpoint."};}
  if(response.ok)return {ok:true};
  const permanent:Record<number,string>={400:"The endpoint rejected the message as malformed.",401:"Discord rejected the webhook token. Create a new webhook and paste its URL.",403:"Discord refused the post. Check the webhook still has access to that channel.",404:"That webhook no longer exists. Create a new webhook and paste its URL."};
  return {ok:false,error:permanent[response.status]??(response.status===429?"Discord is rate limiting this webhook. Try again later.":`The endpoint answered ${response.status}. Try again later.`)};
}
