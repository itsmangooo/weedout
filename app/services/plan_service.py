"""Changing an account's plan, and making the change land everywhere at once.

There is exactly one function here worth reading, and it exists because a tier
is not the only thing that has to change when a plan does.

Reading the tier is already live: nothing caches it, so the next request an
account makes is served under the new plan with no window and nothing to
invalidate. That half needs no help.

What does not update itself is anything already *written down* under the old
plan. Today that is one thing, `TrackedTarget.next_scan_at`, which a scan sets
from the cadence in force when it finished. Upgrade a Free account and the
four-hourly checks it has started paying for do not begin until the next daily
scan happens to run — up to a full day of having bought something and not
received it. Downgrade one and the reverse: a cancelled account stays on the
fast cadence, doing work nobody is paying for.

So every plan change goes through here, and `test_plan_changes_take_effect.py`
asserts statically that nothing assigns `user.tier` anywhere else. A
rescheduling that only some of the three call sites did would be worse than
none — it would work when an admin changed a plan by hand and not when a
customer actually paid, which is precisely the path nobody tests manually.
"""

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
    """Move an account to a plan, and bring everything written down with it.

    Returns whether anything changed. A webhook that repeats itself — and they
    do — must not keep shifting the schedule, or a chatty provider becomes a
    way to have an account scanned continuously.
    """
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
    """Move every active project onto the new cadence.

    Measured from now rather than from the last scan. Measuring from the last
    scan would be more precise and occasionally absurd: an account upgrading a
    week after its last scan would have a next-scan time in the past, and the
    scheduler would treat a plan change as a reason to scan immediately — which
    is a way to turn one upgrade into a thundering herd.
    """
    interval = scan_interval_for(tier)
    now = utcnow()

    targets = (
        await db.scalars(
            select(TrackedTarget).where(
                TrackedTarget.user_id == user.id,
                TrackedTarget.is_active.is_(True),
                # Null means "scan on the next tick", which is sooner than any
                # cadence. Rescheduling it would push a brand-new project
                # backwards, which is the opposite of what an upgrade should do.
                TrackedTarget.next_scan_at.is_not(None),
            )
        )
    ).all()

    for target in targets:
        target.next_scan_at = now + interval

    await db.flush()
    return len(targets)


def plan_summary(tier: Tier | str) -> dict:
    """What this account can do, in the shape the CLI reads.

    On every machine-facing response, so a client can notice a plan change at
    the first command after it and say so. A CLI cannot be pushed to — it runs,
    prints and exits — so the honest version of "in real time" is that the very
    next thing it does reflects the change and tells you.

    Capabilities rather than a label. "You are on Pro" means nothing on its own;
    "so scans now reach the whole tree" is the sentence worth printing.
    """
    limits = limits_for(tier)

    return {
        "tier": str(limits.tier),
        "name": limits.display_name,
        # None means the whole tree. The same convention as `MatchPolicy`, so
        # the client is not asked to learn a second one.
        "scan_depth": limits.scan_depth,
        "custom_rules": limits.custom_rules,
        "scan_interval_hours": round(limits.scan_interval.total_seconds() / 3600),
        "max_projects": limits.max_targets,
    }
