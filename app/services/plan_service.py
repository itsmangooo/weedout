"""Normalise legacy tier values to Weedout's single Free entitlement."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.types import Tier
from app.logging_config import get_logger
from app.models import TrackedTarget, User, utcnow
from app.tiers import limits_for, scan_interval_for

log = get_logger(__name__)

__all__ = ["apply_tier_change", "plan_summary"]


async def apply_tier_change(db: AsyncSession, user: User, new_tier: Tier) -> bool:
    """Normalise an account and its written scan schedule to Free."""
    # ``pro`` is a legacy database value, not a product entitlement. Every
    # caller is normalised here so an old admin client or delayed payment
    # webhook cannot recreate the retired plan.
    new_tier = Tier.FREE

    if user.tier is new_tier:
        return False

    previous = user.tier
    user.tier = new_tier
    await db.flush()

    rescheduled = await _reschedule(db, user, new_tier)

    log.info(
        "plan.changed",
        user_id=user.id,
        was=str(previous),
        now=str(new_tier),
        rescheduled=rescheduled,
    )
    return True


async def _reschedule(db: AsyncSession, user: User, tier: Tier) -> int:
    """Move every active project onto the current Free cadence."""
    interval = scan_interval_for(tier)
    now = utcnow()

    targets = (
        await db.scalars(
            select(TrackedTarget).where(
                TrackedTarget.user_id == user.id,
                TrackedTarget.is_active.is_(True),
                # Null means "scan on the next tick", which is sooner than any
                # cadence. Rescheduling it would push a brand-new project
                # backwards, which would delay its first scan.
                TrackedTarget.next_scan_at.is_not(None),
            )
        )
    ).all()

    for target in targets:
        target.next_scan_at = now + interval

    await db.flush()
    return len(targets)


def plan_summary(tier: Tier | str) -> dict:
    """Return the single Free capability set in the shape the CLI reads."""
    limits = limits_for(tier)

    return {
        "tier": "free",
        "name": limits.display_name,
        # None means the whole tree. The same convention as `MatchPolicy`, so
        # the client is not asked to learn a second one.
        "scan_depth": limits.scan_depth,
        "custom_rules": limits.custom_rules,
        "scan_interval_hours": round(limits.scan_interval.total_seconds() / 3600),
        "max_projects": limits.max_targets,
    }
