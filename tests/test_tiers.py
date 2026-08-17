"""Plan limits and tier gating.

Everything that varies by plan resolves through this module, so these tests are
the whole surface area of "what does paying change?".
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.core.types import Tier
from app.tiers import (
    PLANS,
    can_add_target,
    can_use_webhooks,
    limits_for,
    scan_interval_for,
    target_limit_message,
)


class TestLimitsFor:
    def test_known_tiers_resolve(self):
        assert limits_for(Tier.FREE).tier is Tier.FREE
        assert limits_for(Tier.PRO).tier is Tier.PRO

    def test_string_values_resolve(self):
        assert limits_for("free").tier is Tier.FREE
        assert limits_for("pro").tier is Tier.PRO

    def test_unknown_values_degrade_to_free_rather_than_raising(self):
        # A subscription row written by a future version must downgrade the
        # user, not take the request down.
        assert limits_for("enterprise-plus").tier is Tier.FREE
        assert limits_for("").tier is Tier.FREE


class TestTargetLimits:
    def test_free_tier_allows_exactly_one_project(self):
        assert can_add_target(Tier.FREE, 0) is True
        assert can_add_target(Tier.FREE, 1) is False
        assert can_add_target(Tier.FREE, 5) is False

    def test_pro_tier_is_unlimited(self):
        assert can_add_target(Tier.PRO, 0) is True
        assert can_add_target(Tier.PRO, 999) is True

    def test_limit_message_names_the_upgrade(self):
        message = target_limit_message(Tier.FREE)
        assert "1 project" in message
        assert "Pro" in message

    def test_unlimited_plan_has_no_limit_message(self):
        assert target_limit_message(Tier.PRO) == ""


class TestScanIntervals:
    def test_free_is_daily(self):
        assert scan_interval_for(Tier.FREE) == timedelta(hours=24)

    def test_pro_is_more_frequent(self):
        assert scan_interval_for(Tier.PRO) < scan_interval_for(Tier.FREE)

    @pytest.mark.parametrize(
        ("tier", "expected"), [(Tier.FREE, "Once daily"), (Tier.PRO, "Every 4 hours")]
    )
    def test_frequency_labels_read_naturally(self, tier, expected):
        assert limits_for(tier).scan_frequency_label == expected

    @pytest.mark.parametrize(
        ("tier", "expected"), [(Tier.FREE, "1 project"), (Tier.PRO, "Unlimited projects")]
    )
    def test_target_labels_read_naturally(self, tier, expected):
        assert limits_for(tier).targets_label == expected


class TestFeatureFlags:
    def test_webhooks_are_a_paid_feature(self):
        assert can_use_webhooks(Tier.FREE) is False
        assert can_use_webhooks(Tier.PRO) is True

    def test_email_alerts_are_available_on_every_plan(self):
        # The core product should not be paywalled; frequency and scale are.
        assert all(plan.email_alerts for plan in PLANS.values())

    def test_pro_keeps_history_longer(self):
        assert limits_for(Tier.PRO).history_days > limits_for(Tier.FREE).history_days


class TestPlanTableIntegrity:
    def test_every_tier_has_a_plan(self):
        assert set(PLANS) == set(Tier)

    def test_each_plan_is_keyed_by_its_own_tier(self):
        for tier, plan in PLANS.items():
            assert plan.tier is tier

    def test_every_plan_advertises_features(self):
        for plan in PLANS.values():
            assert plan.features
            assert plan.price_label
