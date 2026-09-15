"""The product exposes one Free entitlement, including for legacy tier rows."""

from datetime import timedelta

from app.core.types import Tier
from app.tiers import (
    FREE_PLAN,
    PLANS,
    depth_label,
    history_cutoff_days,
    limits_for,
    scan_depth_for,
    scan_interval_for,
)


def test_free_is_the_only_entitlement():
    assert limits_for(Tier.FREE) is FREE_PLAN
    assert limits_for(Tier.PRO) is FREE_PLAN
    assert limits_for("enterprise-plus") is FREE_PLAN
    assert PLANS[Tier.FREE] is PLANS[Tier.PRO]


def test_every_shipped_capability_is_free():
    assert FREE_PLAN.max_targets is None
    assert FREE_PLAN.scan_depth is None
    assert FREE_PLAN.custom_rules is True
    assert FREE_PLAN.email_alerts is True
    assert FREE_PLAN.webhook_alerts is True
    assert FREE_PLAN.history_days == 365
    assert FREE_PLAN.scan_interval == timedelta(hours=4)


def test_legacy_rows_get_the_same_labels_and_cadence():
    for tier in (Tier.FREE, Tier.PRO, "unknown"):
        assert scan_depth_for(tier) is None
        assert depth_label(tier) == "the whole tree"
        assert scan_interval_for(tier) == timedelta(hours=4)
        assert history_cutoff_days(tier) == 365
