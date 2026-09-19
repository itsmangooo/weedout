"""Regression audit for the single Free product and removed paywalls."""

from pathlib import Path

from app.core.types import Ecosystem, Severity, Tier
from app.services.finding_service import history_window
from app.services.rules_service import build_policy
from app.services.target_service import create_empty_target
from app.tiers import FREE_PLAN, limits_for


async def test_free_can_create_multiple_projects(db, user):
    first = await create_empty_target(db, user, "first", Ecosystem.NPM)
    second = await create_empty_target(db, user, "second", Ecosystem.NPM)

    assert first.id != second.id


async def test_free_policy_has_full_depth_and_custom_rules(db, user):
    target = await create_empty_target(db, user, "rules", Ecosystem.NPM)
    target.direct_threshold = Severity.MEDIUM
    effective = await build_policy(db, target, user)

    assert effective.policy.max_depth is None
    assert effective.policy.direct_threshold.value == "medium"
    assert not any("plan" in note.lower() for note in effective.notes)


def test_legacy_tier_value_cannot_change_capabilities():
    assert limits_for(Tier.PRO) is FREE_PLAN
    assert limits_for(Tier.FREE) is FREE_PLAN
    assert history_window(Tier.FREE, "resolved") == 365
    assert history_window(Tier.PRO, "resolved") == 365


def test_normal_user_frontend_has_no_billing_or_upgrade_surface():
    root = Path(__file__).parents[1]
    shell = (root / "frontend/src/components/layout/DashboardShell.jsx").read_text(encoding="utf-8")
    router = (root / "frontend/src/app/router.jsx").read_text(encoding="utf-8")
    pricing = (root / "frontend/src/pages/PricingPage.jsx").read_text(encoding="utf-8")

    assert 'to: "/billing"' not in shell
    assert '"../pages/BillingPage"' not in router
    assert "Pro plan" not in pricing
    assert "upgrade" not in pricing.lower()


def test_free_feature_list_only_claims_working_capabilities():
    claims = set(FREE_PLAN.features)
    assert "Automated Node reachability with evidence" in claims
    assert "Full dependency tree analysis" in claims
    assert "Custom scan rules and .weedout.yml" in claims
    assert "CLI and CI-compatible exit behavior" in claims
