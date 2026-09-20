import { NextRequest, NextResponse } from "next/server";
import { handleDodoSubscription } from "@/server/billing/dodo";
import { verifyDodoSignature } from "@/server/billing/dodo-signature";

export async function POST(request: NextRequest) {
  const enabled = ["1", "true", "yes", "on"].includes((process.env.DODO_ENABLED ?? "").toLowerCase());
  const secret = process.env.DODO_WEBHOOK_SECRET;
  if (!enabled || !secret) return NextResponse.json({ detail: "Billing is not enabled." }, { status: 404 });
  const body = new Uint8Array(await request.arrayBuffer());
  if (!verifyDodoSignature({
    body,
    webhookId: request.headers.get("webhook-id"),
    timestamp: request.headers.get("webhook-timestamp"),
    signature: request.headers.get("webhook-signature"),
    secret,
  })) return NextResponse.json({ detail: "Invalid signature" }, { status: 401 });
  let payload: unknown;
  try { payload = JSON.parse(new TextDecoder().decode(body)); }
  catch { return NextResponse.json({ detail: "Invalid JSON body" }, { status: 400 }); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return NextResponse.json({ ok: true, handled: false });
  const event = payload as Record<string, unknown>;
  if (typeof event.type !== "string" || !event.type.startsWith("subscription.") || !event.data || typeof event.data !== "object" || Array.isArray(event.data)) {
    return NextResponse.json({ ok: true, handled: false });
  }
  try {
    return NextResponse.json({ ok: true, handled: await handleDodoSubscription(event.data as Record<string, unknown>) });
  } catch (error) {
    console.error("dodo.handler_failed", error);
    return NextResponse.json({ detail: "Webhook processing failed" }, { status: 500 });
  }
}
