import type { NextRequest } from "next/server";

export function clientIp(request: NextRequest) {
  const trusted = process.env.TRUSTED_CLIENT_IP_HEADER?.toLowerCase();
  if (trusted) return request.headers.get(trusted)?.split(",", 1)[0].trim() || "unknown";
  return request.headers.get("x-forwarded-for")?.split(",", 1)[0].trim() || "unknown";
}

export function safeNext(value: unknown) {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) return "/dashboard";
  return value;
}
