"""Billing, for the React application.

Read-only, deliberately. The only mutation in this whole area is Dodo's
webhook, which lives in app/routes/billing.py and is authenticated by an HMAC
over the raw body rather than by a session — nothing here can grant or revoke a
plan, and that is the point: the thing that changes what somebody has paid for
should be the thing that took the payment.

The checkout link is a plain URL to Dodo's hosted page. No embedded SDK, so
nothing third-party runs in the browser and the CSP stays strict.
"""

from __future__ import annotations

from fastapi import APIRouter, Response

from app.core.types import Tier
from app.deps import AppSettings, CurrentInternalUser
from app.routes.billing import build_checkout_url
from app.tiers import limits_for

router = APIRouter(prefix="/api/internal", tags=["internal-billing"])


@router.get("/billing")
async def billing(response: Response, settings: AppSettings, user: CurrentInternalUser) -> dict:
    """What this account is on, and where to go to change it."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"

    limits = limits_for(user.tier)
    is_pro = user.tier is Tier.PRO

    return {
        "data": {
            "tier": str(user.tier),
            "plan_name": limits.display_name,
            "is_pro": is_pro,
            # Whether this deployment can take a payment at all. A self-hosted
            # instance with no Dodo credentials should say so plainly rather
            # than show a checkout button that goes nowhere.
            "checkout_enabled": settings.dodo_enabled,
            # None when Dodo is off or no product is configured for Pro. The
            # page distinguishes the two, because "not set up here" and "we
            # cannot sell you this" are different problems.
            "checkout_url": build_checkout_url(settings, user) if not is_pro else None,
            "subscription_status": user.subscription_status,
            "subscription_ends_at": user.subscription_ends_at,
        }
    }
