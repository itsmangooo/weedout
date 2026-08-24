"""A plan change has to reach a running CLI, and it has to reach it now.

Somebody who has just paid should get what they paid for on their next
command, not on their next billing cycle. Somebody who has just been downgraded
should stop getting Pro behaviour on their next command, not keep it until a
cache expires. Both directions matter, and the second one matters more: a
scanner that keeps applying rules the account no longer has is a scanner
reporting on rules nobody is enforcing.

A CLI cannot be pushed to. It runs, prints, exits, and there is nothing to send
an event to. So "in real time" means two separate things, and this file is
about proving both:

1. **Nothing is cached**, so the very next request reflects the new plan. There
   is nothing to invalidate and no window to be stale in.
2. **Nothing scheduled is stale**, which is the part that was not true. The
   next scheduled scan was pinned to the cadence of the plan that was in force
   the last time a scan ran, so somebody upgrading could wait a full day for
   the four-hourly checks they had started paying for.

`TestTheCliIsToldTheStateChanged` covers the third piece: the plan is on the
wire, so the CLI can say what happened rather than silently behaving
differently.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.core.types import Tier
from app.models import utcnow
from app.services.rules_service import build_policy
from app.tiers import scan_depth_for, scan_interval_for
from tests.conftest import api_key_for, set_csrf


async def a_scanned_project(db, owner):
    """A project that has run one scan, so it has a next_scan_at."""
    from app.services.scan_service import scan_target
    from tests.test_scan_pipeline import make_target, seed_mirror

    await seed_mirror(db)
    target = await make_target(db, owner)
    await scan_target(db, target)
    # Flushed here, not left pending. A test that calls `db.refresh` after a
    # no-op would otherwise read `None` and look like a rescheduling bug.
    await db.flush()
    return target


class TestNothingIsCached:
    """The half that already worked, pinned so it keeps working.

    A tier cached anywhere — in the auth dependency, on the key row, in a
    module-level dict — would put a window between paying and being served, and
    a longer one between cancelling and being cut off.
    """

    async def test_a_scan_uses_the_tier_as_it_is_right_now(self, db, user):
        """Not the tier when the key was issued, or when the project was
        created."""
        target = await a_scanned_project(db, user)

        free = await build_policy(db, target, user)
        user.tier = Tier.PRO
        await db.flush()
        pro = await build_policy(db, target, user)

        assert free.policy.max_depth == scan_depth_for(Tier.FREE)
        assert pro.policy.max_depth is None

    async def test_a_downgrade_takes_effect_just_as_fast(self, db, pro_user):
        """The direction that matters more. A scanner still applying rules the
        account no longer has is reporting on rules nobody is enforcing."""
        from app.core.types import Severity

        target = await a_scanned_project(db, pro_user)
        target.direct_threshold = Severity.LOW
        await db.flush()

        assert (await build_policy(db, target, pro_user)).policy.direct_threshold is Severity.LOW

        pro_user.tier = Tier.FREE
        await db.flush()

        assert (
            await build_policy(db, target, pro_user)
        ).policy.direct_threshold is not Severity.LOW

    async def test_the_key_carries_no_copy_of_the_plan(self, db, user):
        """A key row that remembered the tier would be a cache with no
        invalidation, and keys outlive plan changes by design."""
        from app.models import ApiKey

        columns = {column.name for column in ApiKey.__table__.columns}

        assert "tier" not in columns
        assert not columns & {"plan", "scan_depth", "custom_rules"}

    async def test_the_api_reports_the_new_plan_on_the_next_request(self, client, db, user):
        """End to end, over the wire, with no restart and nothing cleared."""
        target = await a_scanned_project(db, user)
        key = await api_key_for(db, target, scope="read")
        await db.commit()

        before = await client.get("/api/v1/project", headers={"Authorization": f"Bearer {key}"})

        user.tier = Tier.PRO
        await db.commit()

        after = await client.get("/api/v1/project", headers={"Authorization": f"Bearer {key}"})

        assert before.status_code == 200
        assert after.status_code == 200
        assert before.json()["plan"]["tier"] == "free"
        assert after.json()["plan"]["tier"] == "pro"


class TestTheScheduleIsNotLeftStale:
    """The half that was broken.

    `next_scan_at` is written at the end of a scan from the tier in force at
    that moment. Upgrade a Free account and the four-hourly cadence it is now
    paying for does not start until the next daily scan happens to run — up to
    a full day of having bought something and not received it.
    """

    async def test_an_upgrade_brings_the_next_scan_forward(self, db, user):
        from app.services.plan_service import apply_tier_change

        target = await a_scanned_project(db, user)
        was = target.next_scan_at
        assert was is not None

        await apply_tier_change(db, user, Tier.PRO)
        await db.refresh(target)

        assert target.next_scan_at < was
        # Within the Pro cadence, give or take the second this test took.
        assert target.next_scan_at <= utcnow() + scan_interval_for(Tier.PRO) + timedelta(minutes=1)

    async def test_a_downgrade_pushes_it_back(self, db, pro_user):
        """The other direction, and it must not be forgotten: a cancelled
        account left on the four-hourly cadence is work nobody is paying
        for."""
        from app.services.plan_service import apply_tier_change

        target = await a_scanned_project(db, pro_user)

        await apply_tier_change(db, pro_user, Tier.FREE)
        await db.refresh(target)

        assert target.next_scan_at > utcnow() + scan_interval_for(Tier.PRO)

    async def test_a_project_that_has_never_scanned_is_left_alone(self, db, user):
        """Null means "scan on the next tick", which is sooner than any
        cadence. Rescheduling it would push a brand-new project backwards."""
        from app.services.plan_service import apply_tier_change
        from tests.test_scan_pipeline import make_target

        target = await make_target(db, user)
        target.next_scan_at = None
        await db.flush()

        await apply_tier_change(db, user, Tier.PRO)
        await db.refresh(target)

        assert target.next_scan_at is None

    async def test_an_inactive_project_is_left_alone(self, db, user):
        from app.services.plan_service import apply_tier_change

        target = await a_scanned_project(db, user)
        target.is_active = False
        was = target.next_scan_at
        await db.flush()

        await apply_tier_change(db, user, Tier.PRO)
        await db.refresh(target)

        assert target.next_scan_at == was

    async def test_changing_to_the_same_tier_does_nothing(self, db, user):
        """A webhook that repeats itself must not keep shifting the schedule,
        or a chatty provider becomes a way to scan continuously."""
        from app.services.plan_service import apply_tier_change

        target = await a_scanned_project(db, user)
        was = target.next_scan_at

        changed = await apply_tier_change(db, user, Tier.FREE)
        await db.refresh(target)

        assert changed is False
        assert target.next_scan_at == was

    async def test_somebody_elses_projects_are_untouched(self, db, user, pro_user):
        from app.services.plan_service import apply_tier_change

        mine = await a_scanned_project(db, user)
        theirs = await a_scanned_project(db, pro_user)
        theirs_was = theirs.next_scan_at

        await apply_tier_change(db, user, Tier.PRO)
        await db.refresh(mine)
        await db.refresh(theirs)

        assert mine.next_scan_at != theirs_was
        assert theirs.next_scan_at == theirs_was


class TestEveryPlaceThePlanChangesGoesThroughIt:
    """Three write sites, and a rescheduling that only some of them do is worse
    than none — it would work when an admin changed a plan and not when a
    customer paid, which is the case nobody tests by hand."""

    def test_nothing_assigns_a_tier_outside_the_service(self):
        import ast
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        allowed = {
            # The service itself.
            "app/services/plan_service.py",
            # Seeds and fixtures construct users with a tier; that is not a
            # change to an existing account.
            "app/manage.py",
        }

        offenders = []
        for path in sorted((root / "app").rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            if rel in allowed:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                for goal in node.targets:
                    if (
                        isinstance(goal, ast.Attribute)
                        and goal.attr == "tier"
                        and isinstance(goal.value, ast.Name)
                        and goal.value.id[:1].islower()
                    ):
                        offenders.append(f"{rel}:{node.lineno}")

        assert offenders == [], (
            f"tier assigned directly at {offenders}. Use "
            f"`plan_service.apply_tier_change`, or the schedule is left on the "
            f"cadence of the plan the account no longer has."
        )

    async def test_the_admin_panel_reschedules(self, admin_client, db, user):
        target = await a_scanned_project(db, user)
        was = target.next_scan_at
        await db.commit()

        response = await admin_client.post(
            f"/api/internal/admin/users/{user.id}/tier",
            json={"tier": "pro"},
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )

        assert response.status_code == 200, response.text
        await db.refresh(target)
        assert target.next_scan_at < was

    async def test_the_billing_webhook_reschedules(self, db, user):
        """The one that actually happens when somebody pays."""
        from app.routes.billing import _handle_subscription_event

        target = await a_scanned_project(db, user)
        was = target.next_scan_at
        user.dodo_customer_id = "cus_123"
        await db.flush()

        await _handle_subscription_event(
            db,
            "subscription.active",
            {
                "status": "active",
                "subscription_id": "sub_123",
                "customer": {"customer_id": "cus_123"},
            },
        )
        await db.refresh(target)

        assert user.tier is Tier.PRO
        assert target.next_scan_at < was

    async def test_the_expiry_job_reschedules(self, db, pro_user, monkeypatch):
        """A downgrade nobody clicked. The job that applies a cancellation once
        the paid period ends.

        The job opens its own session, so it is pointed at the test's one --
        the same shape `test_billing.py` uses, because a second connection
        cannot see writes this transaction has not committed.
        """
        from contextlib import asynccontextmanager

        from app.jobs import tasks

        target = await a_scanned_project(db, pro_user)
        pro_user.subscription_ends_at = utcnow() - timedelta(days=1)
        pro_user.subscription_status = "cancelled"
        await db.flush()

        @asynccontextmanager
        async def fake_scope():
            yield db

        monkeypatch.setattr(tasks, "session_scope", fake_scope)

        assert await tasks.expire_subscriptions_task() == 1

        assert pro_user.tier is Tier.FREE
        assert target.next_scan_at > utcnow() + scan_interval_for(Tier.PRO)


class TestTheCliIsToldTheStateChanged:
    """A CLI cannot be pushed to, so the best it can do is notice at the first
    command afterwards and say so. That needs the plan on the wire."""

    async def test_a_scan_reports_the_plan_it_ran_under(self, client, db, user):
        from tests.test_scan_pipeline import seed_mirror

        await seed_mirror(db)
        target = await a_scanned_project(db, user)
        key = await api_key_for(db, target, scope="scan")
        await db.commit()

        response = await client.post(
            "/api/v1/scan",
            headers={"Authorization": f"Bearer {key}"},
            files={"manifest": ("package.json", '{"dependencies":{"lodash":"4.17.15"}}')},
        )

        assert response.status_code == 200, response.text
        plan = response.json()["plan"]
        assert plan["tier"] == "free"
        assert plan["name"] == "Free"

    async def test_the_plan_block_says_what_the_account_can_do(self, client, db, pro_user):
        """Not just a label. The CLI has to be able to say what changed, and
        "you are on Pro" means nothing without "so scans now reach the whole
        tree"."""
        target = await a_scanned_project(db, pro_user)
        key = await api_key_for(db, target, scope="read")
        await db.commit()

        plan = (
            await client.get("/api/v1/project", headers={"Authorization": f"Bearer {key}"})
        ).json()["plan"]

        assert plan["tier"] == "pro"
        assert plan["scan_depth"] is None
        assert plan["custom_rules"] is True
        assert plan["scan_interval_hours"] == 4

    async def test_the_free_plan_block_is_honest_about_the_limits(self, client, db, user):
        target = await a_scanned_project(db, user)
        key = await api_key_for(db, target, scope="read")
        await db.commit()

        plan = (
            await client.get("/api/v1/project", headers={"Authorization": f"Bearer {key}"})
        ).json()["plan"]

        assert plan["scan_depth"] == scan_depth_for(Tier.FREE)
        assert plan["custom_rules"] is False

    async def test_the_rules_listing_carries_it_too(self, db, client, user):
        """Here more than anywhere else.

        A Free account with rules configured gets a tidy list of things that
        are not doing anything. Without the plan on the response there is
        nothing for the CLI to say so with, and a list of configuration that
        looks in force and is not is the exact failure this product exists to
        avoid.
        """
        from app.core.types import Severity

        target = await a_scanned_project(db, user)
        target.direct_threshold = Severity.LOW
        key = await api_key_for(db, target, scope="manage")
        await db.commit()

        body = (
            await client.get("/api/v1/rules", headers={"Authorization": f"Bearer {key}"})
        ).json()

        assert body["plan"]["custom_rules"] is False
        # And the rule is still listed, because a downgrade keeps it.
        assert body["thresholds"]["direct"] == "low"

    @pytest.mark.parametrize("path", ["/api/v1/project", "/api/v1/findings"])
    async def test_the_read_endpoints_carry_it_too(self, client, db, user, path):
        """So any command the CLI runs can notice, not only a scan."""
        target = await a_scanned_project(db, user)
        key = await api_key_for(db, target, scope="read")
        await db.commit()

        response = await client.get(path, headers={"Authorization": f"Bearer {key}"})

        assert response.json()["plan"]["tier"] == "free"
