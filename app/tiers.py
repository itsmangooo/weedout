"""The single Free entitlement, with legacy tier-value compatibility."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from app.core.types import Tier

__all__ = ["PLANS", "PlanLimits", "limits_for", "scan_interval_for"]


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
    #: Whether per-project severity overrides, ignore rules and `.weedout.yml`
    #: apply.
    custom_rules: bool
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


FREE_PLAN = PlanLimits(
    tier=Tier.FREE,
    display_name="Free",
    price_label="$0",
    max_targets=None,
    scan_interval=timedelta(hours=4),
    email_alerts=True,
    webhook_alerts=True,
    history_days=365,
    scan_depth=None,
    custom_rules=True,
    features=(
        "Unlimited projects",
        "Full dependency tree analysis",
        "Automated Node reachability with evidence",
        "Custom scan rules and .weedout.yml",
        "Email, Discord and custom webhook alerts",
        "One year of alert history",
        "CLI and CI-compatible exit behavior",
    ),
)

# Kept only so legacy ``tier='pro'`` rows remain readable. There is one
# entitlement and both database values resolve to it.
PLANS: dict[Tier, PlanLimits] = {Tier.FREE: FREE_PLAN, Tier.PRO: FREE_PLAN}


def limits_for(tier: Tier | str) -> PlanLimits:
    """The limits that apply to a tier. Unknown values fall back to Free.

    Falling back rather than raising matters: a subscription row written by a
    future version of the app must degrade a user to the free plan, never take
    the whole request down.
    """
    return FREE_PLAN


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


def history_cutoff_days(tier: Tier | str) -> int:
    return limits_for(tier).history_days
