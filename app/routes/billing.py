"""Verified ingestion of legacy Dodo subscription records.

Subscriptions no longer grant product access. The signed webhook remains so
administrators can reconcile historical invoices, refunds and disputes without
discarding database compatibility.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.config import get_settings
from app.core.types import Tier
from app.deps import DbSession
from app.logging_config import get_logger
from app.models import User
from app.security import verify_dodo_signature
from app.services.plan_service import apply_tier_change

log = get_logger(__name__)

router = APIRouter(tags=["billing"])

#: Provider states recorded as active historical subscriptions.
ACTIVE_STATUSES = {"active", "trialing", "on_hold"}

#: Provider states that end a historical subscription.
ENDED_STATUSES = {"cancelled", "canceled", "expired", "failed", "paused"}


@router.post("/webhooks/dodo", include_in_schema=False)
async def dodo_webhook(request: Request, db: DbSession):
    """Handle a Dodo Payments notification.

    Signature verification uses the raw request body — re-serialising parsed
    JSON changes byte-for-byte content and invalidates the HMAC.

    Returns 200 for events we do not act on, so Dodo stops retrying them, and
    401 only for a genuinely bad signature.
    """
    settings = get_settings()
    if not settings.dodo_enabled or not settings.dodo_webhook_secret:
        raise HTTPException(status_code=404, detail="Billing is not enabled.")

    raw_body = await request.body()

    if not verify_dodo_signature(
        raw_body=raw_body,
        webhook_id=request.headers.get("webhook-id"),
        webhook_timestamp=request.headers.get("webhook-timestamp"),
        signature_header=request.headers.get("webhook-signature"),
        secret=settings.dodo_webhook_secret,
    ):
        log.warning("dodo.invalid_signature", webhook_id=request.headers.get("webhook-id"))
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload: dict[str, Any] = await request.json()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    event_type = str(payload.get("type") or "")
    data = payload.get("data")
    if not isinstance(data, dict):
        log.warning("dodo.malformed_payload", event_type=event_type)
        return JSONResponse({"ok": True, "handled": False})

    log.info(
        "dodo.webhook_received",
        event_type=event_type,
        webhook_id=request.headers.get("webhook-id"),
    )

    # Dodo namespaces subscription lifecycle events under `subscription.*`.
    # Payment events carry no subscription state we do not already get from
    # these, so they are acknowledged and ignored rather than double-counted.
    if not event_type.startswith("subscription."):
        return JSONResponse({"ok": True, "handled": False})

    try:
        handled = await _handle_subscription_event(db, event_type, data)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        log.exception("dodo.handler_failed", event_type=event_type, error=str(exc))
        raise HTTPException(status_code=500, detail="Webhook processing failed") from exc

    return JSONResponse({"ok": True, "handled": handled})


async def _handle_subscription_event(db: DbSession, event_type: str, data: dict[str, Any]) -> bool:
    """Apply one subscription event to the account it belongs to.

    Every `subscription.*` event carries the full subscription object, so a
    single handler covering all of them is both simpler and more robust than
    one per event name: an event type Dodo adds later still updates the state
    correctly instead of being silently dropped.
    """
    user = await _find_user(db, data)
    if user is None:
        log.warning("dodo.user_not_found", subscription_id=data.get("subscription_id"))
        return False

    status = str(data.get("status") or "").lower()

    user.dodo_subscription_id = data.get("subscription_id") or user.dodo_subscription_id
    user.dodo_customer_id = _customer_id(data) or user.dodo_customer_id
    user.subscription_status = status or None

    # The product is an identifier, not a price, so it is recorded here rather
    # than inside the amount parsing — a payload that omits the amount should
    # still tell us which product was bought.
    product_id = data.get("product_id")
    if isinstance(product_id, str) and product_id:
        user.dodo_product_id = product_id

    _record_subscription_price(user, data)

    ends_at = _parse_timestamp(data.get("next_billing_date")) or _parse_timestamp(
        data.get("cancelled_at") or data.get("expires_at")
    )
    user.subscription_ends_at = ends_at

    if status not in ACTIVE_STATUSES | ENDED_STATUSES:
        # Preserve unfamiliar provider state for reconciliation. It still has
        # no bearing on access now that the product has one Free entitlement.
        log.warning("dodo.unknown_status", user_id=user.id, status=status)
    new_tier = Tier.FREE

    if user.tier is not new_tier:
        log.info(
            "dodo.tier_changed",
            user_id=user.id,
            old_tier=str(user.tier),
            new_tier=str(new_tier),
            status=status,
            event_type=event_type,
        )
    # Normalise any legacy database value without deleting payment history.
    await apply_tier_change(db, user, new_tier)
    return True


def _customer_id(data: dict[str, Any]) -> str | None:
    customer = data.get("customer")
    if isinstance(customer, dict):
        value = customer.get("customer_id")
        if isinstance(value, str) and value:
            return value
    value = data.get("customer_id")
    return value if isinstance(value, str) and value else None


async def _find_user(db: DbSession, data: dict[str, Any]) -> User | None:
    """Locate the account this subscription belongs to.

    Four strategies, most reliable first: the reference we set at checkout, our
    own metadata, the stored customer id, then the customer's email. Email is
    last because it is the one a customer can change at the payment provider.
    """
    for candidate in (data.get("reference_id"), _metadata_user_id(data)):
        if candidate is None:
            continue
        try:
            user = await db.get(User, int(candidate))
        except (TypeError, ValueError):
            continue
        if user is not None:
            return user

    customer_id = _customer_id(data)
    if customer_id:
        user = await db.scalar(select(User).where(User.dodo_customer_id == customer_id))
        if user is not None:
            return user

    subscription_id = data.get("subscription_id")
    if isinstance(subscription_id, str) and subscription_id:
        user = await db.scalar(select(User).where(User.dodo_subscription_id == subscription_id))
        if user is not None:
            return user

    customer = data.get("customer")
    if isinstance(customer, dict):
        email = customer.get("email")
        if isinstance(email, str) and email:
            return await db.scalar(select(User).where(User.email == email.strip().lower()))

    return None


def _metadata_user_id(data: dict[str, Any]) -> str | None:
    metadata = data.get("metadata")
    if isinstance(metadata, dict):
        value = metadata.get("user_id")
        if isinstance(value, str | int):
            return str(value)
    return None


def _parse_timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _record_subscription_price(user: User, data: dict[str, Any]) -> None:
    """Capture the recurring amount so revenue can be summed locally.

    Dodo reports the amount in the currency's minor unit as an integer, with
    the cadence split across `payment_frequency_interval` ("Month"/"Year") and
    `payment_frequency_count`. A count above one — billed every 3 months, say —
    is normalised here so MRR does not treat it as a monthly charge.

    Defensively typed throughout: a payload shape we do not recognise must
    leave the stored values untouched rather than zero them. MRR quietly
    dropping to zero is worse than MRR being briefly stale.
    """
    amount = data.get("recurring_pre_tax_amount")
    if amount is None:
        product_cart = data.get("product_cart")
        if isinstance(product_cart, list) and product_cart:
            first = product_cart[0]
            if isinstance(first, dict):
                amount = first.get("amount")

    try:
        cents = int(amount)
    except (TypeError, ValueError):
        return
    if cents < 0:
        return

    interval = data.get("payment_frequency_interval")
    interval = interval.lower() if isinstance(interval, str) else None

    try:
        count = int(data.get("payment_frequency_count", 1) or 1)
    except (TypeError, ValueError):
        count = 1
    count = max(count, 1)

    # Fold a multi-period cadence into the interval unit, so "every 3 months"
    # becomes a monthly figure a third the size.
    if count > 1:
        cents = round(cents / count)

    user.subscription_amount_cents = cents
    user.subscription_interval = interval or "month"

    currency = data.get("currency")
    if isinstance(currency, str) and currency:
        user.subscription_currency = currency[:3].upper()
