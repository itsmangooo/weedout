import "server-only";

import { db } from "@/server/db/client";

type Payload = Record<string, unknown>;
type UserRow = { id: number; tier: string; dodo_customer_id: string | null; dodo_subscription_id: string | null };

function text(value: unknown) { return typeof value === "string" && value ? value : null; }
function customerId(data: Payload) {
  const customer = data.customer;
  return customer && typeof customer === "object" && !Array.isArray(customer)
    ? text((customer as Payload).customer_id) ?? text(data.customer_id)
    : text(data.customer_id);
}
function metadataUserId(data: Payload) {
  const metadata = data.metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return null;
  const value = (metadata as Payload).user_id;
  return typeof value === "string" || typeof value === "number" ? Number(value) : null;
}
function timestamp(value: unknown) {
  if (typeof value !== "string" || !value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}
function price(data: Payload) {
  let amount = data.recurring_pre_tax_amount;
  if (amount === undefined && Array.isArray(data.product_cart) && data.product_cart[0] && typeof data.product_cart[0] === "object") amount = (data.product_cart[0] as Payload).amount;
  let cents = Number(amount);
  if (!Number.isInteger(cents) || cents < 0) return null;
  const rawCount = Number(data.payment_frequency_count ?? 1);
  const count = Number.isInteger(rawCount) && rawCount > 0 ? rawCount : 1;
  if (count > 1) cents = Math.round(cents / count);
  return {
    cents,
    interval: typeof data.payment_frequency_interval === "string" ? data.payment_frequency_interval.toLowerCase() : "month",
    currency: typeof data.currency === "string" && data.currency ? data.currency.slice(0, 3).toUpperCase() : null,
  };
}

async function findUser(data: Payload) {
  const sql = db();
  for (const candidate of [Number(data.reference_id), metadataUserId(data)]) {
    if (!Number.isInteger(candidate) || Number(candidate) <= 0) continue;
    const rows = await sql<UserRow[]>`SELECT id,tier,dodo_customer_id,dodo_subscription_id FROM users WHERE id=${candidate} LIMIT 1`;
    if (rows[0]) return rows[0];
  }
  const customer = customerId(data);
  if (customer) {
    const rows = await sql<UserRow[]>`SELECT id,tier,dodo_customer_id,dodo_subscription_id FROM users WHERE dodo_customer_id=${customer} LIMIT 1`;
    if (rows[0]) return rows[0];
  }
  const subscription = text(data.subscription_id);
  if (subscription) {
    const rows = await sql<UserRow[]>`SELECT id,tier,dodo_customer_id,dodo_subscription_id FROM users WHERE dodo_subscription_id=${subscription} LIMIT 1`;
    if (rows[0]) return rows[0];
  }
  const customerObject = data.customer;
  const email = customerObject && typeof customerObject === "object" && !Array.isArray(customerObject) ? text((customerObject as Payload).email)?.trim().toLowerCase() : null;
  if (email) {
    const rows = await sql<UserRow[]>`SELECT id,tier,dodo_customer_id,dodo_subscription_id FROM users WHERE email=${email} LIMIT 1`;
    if (rows[0]) return rows[0];
  }
  return null;
}

export async function handleDodoSubscription(data: Payload) {
  const user = await findUser(data);
  if (!user) return false;
  const status = text(data.status)?.toLowerCase() ?? null;
  const subscription = text(data.subscription_id) ?? user.dodo_subscription_id;
  const customer = customerId(data) ?? user.dodo_customer_id;
  const product = text(data.product_id);
  const endsAt = timestamp(data.next_billing_date) ?? timestamp(data.cancelled_at ?? data.expires_at);
  const recurring = price(data);
  const sql = db();
  await sql.begin(async (transaction) => {
    const tx = transaction as unknown as typeof sql;
    await tx`
      UPDATE users SET
        dodo_subscription_id=${subscription}, dodo_customer_id=${customer}, subscription_status=${status},
        dodo_product_id=coalesce(${product},dodo_product_id), subscription_ends_at=${endsAt}, tier='free',
        subscription_amount_cents=coalesce(${recurring?.cents ?? null},subscription_amount_cents),
        subscription_interval=coalesce(${recurring?.interval ?? null},subscription_interval),
        subscription_currency=coalesce(${recurring?.currency ?? null},subscription_currency)
      WHERE id=${user.id}`;
    if (user.tier !== "free") await tx`UPDATE tracked_targets SET next_scan_at=now()+interval '4 hours' WHERE user_id=${user.id} AND is_active=true AND next_scan_at IS NOT NULL`;
  });
  return true;
}
