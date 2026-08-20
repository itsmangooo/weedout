"""Plan limits, in one place.

Every tier question in the application routes through `limits_for()` or one of
the `can_*` helpers. No route, template or job may branch on
`user.tier == Tier.PRO` directly — when pricing changes (and it will), the
change should be confined to the `PLANS` table below.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from app.core.types import Tier

__all__ = ["PLANS", "PlanLimits", "can_add_target", "limits_for", "scan_interval_for"]


@dataclass(frozen=True, slots=True)
class PlanLimits:
    tier: Tier
    display_name: str
    price_label: str
    #: None means unlimited.
    max_targets: int | None
    scan_interval: timedelta
    email_alerts: bool
    webhook_alerts: bool
    history_days: int
    #: How deep into the dependency tree a scan looks. None is all the way.
    #: 1 means direct dependencies and theirs, and no further.
    scan_depth: int | None
    features: tuple[str, ...]

    @property
    def scan_frequency_label(self) -> str:
        hours = self.scan_interval.total_seconds() / 3600
        if hours >= 24:
            days = round(hours / 24)
            return "Once daily" if days == 1 else f"Every {days} days"
        return f"Every {round(hours)} hours" if hours != 1 else "Hourly"

    @property
    def targets_label(self) -> str:
        if self.max_targets is None:
            return "Unlimited projects"
        return "1 project" if self.max_targets == 1 else f"Up to {self.max_targets} projects"


PLANS: dict[Tier, PlanLimits] = {
    Tier.FREE: PlanLimits(
        tier=Tier.FREE,
        display_name="Free",
        price_label="$0",
        max_targets=1,
        scan_interval=timedelta(hours=24),
        email_alerts=True,
        webhook_alerts=False,
        history_days=30,
        scan_depth=1,
        features=(
            "1 project",
            "Checked once daily",
            "Direct dependencies and theirs",
            "Email alerts",
            "KEV + reachability filtering",
        ),
    ),
    Tier.PRO: PlanLimits(
        tier=Tier.PRO,
        display_name="Pro",
        price_label="$12",
        max_targets=None,
        scan_interval=timedelta(hours=4),
        email_alerts=True,
        webhook_alerts=True,
        history_days=365,
        scan_depth=None,
        features=(
            "Unlimited projects",
            "Checked every 4 hours",
            "The whole dependency tree, however deep",
            "Email alerts",
            "Discord and custom webhooks",
            "Full alert history",
        ),
    ),
}


def limits_for(tier: Tier | str) -> PlanLimits:
    """The limits that apply to a tier. Unknown values fall back to Free.

    Falling back rather than raising matters: a subscription row written by a
    future version of the app must degrade a user to the free plan, never take
    the whole request down.
    """
    if isinstance(tier, str):
        try:
            tier = Tier(tier)
        except ValueError:
            return PLANS[Tier.FREE]
    return PLANS.get(tier, PLANS[Tier.FREE])


def can_add_target(tier: Tier | str, current_count: int) -> bool:
    limits = limits_for(tier)
    if limits.max_targets is None:
        return True
    return current_count < limits.max_targets


def target_limit_message(tier: Tier | str) -> str:
    limits = limits_for(tier)
    if limits.max_targets is None:
        return ""
    noun = "project" if limits.max_targets == 1 else "projects"
    return (
        f"The {limits.display_name} plan tracks {limits.max_targets} {noun}. "
        "Upgrade to Pro for unlimited projects."
    )


def scan_depth_for(tier: Tier | str) -> int | None:
    """How deep this plan looks. None is all the way down."""
    return limits_for(tier).scan_depth


def depth_label(tier: Tier | str) -> str:
    """A phrase for the plan's reach, for the interface to say out loud."""
    depth = scan_depth_for(tier)
    if depth is None:
        return "the whole tree"
    if depth == 0:
        return "direct dependencies only"
    if depth == 1:
        return "direct dependencies and theirs"
    return f"{depth} levels deep"


def scan_interval_for(tier: Tier | str) -> timedelta:
    return limits_for(tier).scan_interval


def can_use_webhooks(tier: Tier | str) -> bool:
    return limits_for(tier).webhook_alerts


def history_cutoff_days(tier: Tier | str) -> int:
    return limits_for(tier).history_days
