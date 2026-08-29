"""Legacy tier values resolve to the same single Free entitlement."""

from __future__ import annotations

from datetime import timedelta

from app.core.types import Ecosystem, Tier
from app.models import TrackedTarget, utcnow
from app.services.plan_service import apply_tier_change, plan_summary
from app.tiers import FREE_PLAN, limits_for, scan_interval_for


def test_plan_summary_is_free_for_every_database_value():
    expected = plan_summary(Tier.FREE)
    assert expected == plan_summary(Tier.PRO) == plan_summary("unknown")
    assert expected == {
        "tier": "free",
        "name": "Free",
        "scan_depth": None,
        "custom_rules": True,
        "scan_interval_hours": 4,
        "max_projects": None,
    }


def test_legacy_tier_has_identical_capabilities():
    assert limits_for(Tier.PRO) is FREE_PLAN
    assert scan_interval_for(Tier.PRO) == timedelta(hours=4)


async def test_tier_change_service_cannot_recreate_pro(db, user):
    changed = await apply_tier_change(db, user, Tier.PRO)
    assert changed is False
    assert user.tier is Tier.FREE


async def test_legacy_database_value_is_normalised_and_rescheduled(db, user):
    user.tier = Tier.PRO
    target = TrackedTarget(
        user_id=user.id,
        name="legacy-project",
        ecosystem=Ecosystem.NPM,
        next_scan_at=utcnow() + timedelta(days=1),
    )
    db.add(target)
    await db.flush()

    changed = await apply_tier_change(db, user, Tier.FREE)

    assert changed is True
    assert user.tier is Tier.FREE
    delta = target.next_scan_at - utcnow()
    assert timedelta(hours=3, minutes=59) < delta <= timedelta(hours=4)


async def test_project_and_rules_api_report_the_free_capabilities(client, db, pro_user):
    from tests.conftest import api_key_for
    from tests.test_api import make_target

    target = await make_target(db, pro_user)
    key = await api_key_for(db, target, scope="manage")
    await db.commit()
    headers = {"Authorization": f"Bearer {key}"}

    project = (await client.get("/api/v1/project", headers=headers)).json()
    rules = (await client.get("/api/v1/rules", headers=headers)).json()

    for body in (project, rules):
        assert body["plan"]["tier"] == "free"
        assert body["plan"]["custom_rules"] is True
        assert body["plan"]["scan_depth"] is None
