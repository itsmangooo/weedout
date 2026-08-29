"""Administrative actions: suspension, audit trail and metrics.

Suspension is the action with the widest blast radius — it touches login,
session validation and the scan queue — so each of those consequences is
asserted separately rather than inferred from the flag being set.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.types import ManifestKind, Tier
from app.models import AdminAuditLog, TrackedTarget, User, utcnow
from app.security import hash_password
from app.services.admin_service import (
    AdminActionError,
    feed_health,
    list_users,
    platform_metrics,
    revenue_snapshot,
    signups_over_time,
    suspend_user,
    unsuspend_user,
)
from app.services.auth_service import InvalidCredentials, authenticate, create_session, session_user
from tests.factories import attach_manifest


@pytest.fixture
async def admin(db) -> User:
    record = User(
        email="admin@example.com",
        password_hash=hash_password("correct-horse-battery"),
        is_admin=True,
    )
    db.add(record)
    await db.flush()
    return record


async def make_target(db, user, name="proj") -> TrackedTarget:
    target = TrackedTarget(
        user_id=user.id,
        name=name,
        manifest_kind=ManifestKind.PACKAGE_JSON,
        ecosystem="npm",
        manifest_content="{}",
        content_hash=name.ljust(64, "0"),
        next_scan_at=utcnow() - timedelta(hours=1),
    )
    db.add(target)
    await db.flush()
    await attach_manifest(db, target)
    return target


class TestSuspension:
    async def test_sets_the_flag_with_a_timestamp_and_reason(self, db, admin, user):
        await suspend_user(db, admin, user, reason="abuse report #12")
        assert user.is_suspended is True
        assert user.suspended_at is not None
        assert user.suspension_reason == "abuse report #12"

    async def test_blocks_password_login(self, db, admin, user):
        await suspend_user(db, admin, user)
        await db.flush()

        with pytest.raises(InvalidCredentials):
            await authenticate(db, user.email, "correct-horse-battery")

    async def test_login_failure_is_indistinguishable_from_a_wrong_password(self, db, admin, user):
        # Telling a suspended user that they are suspended confirms the action
        # landed, which is information the account holder should get by email
        # from a human rather than from a login form.
        await suspend_user(db, admin, user)
        await db.flush()

        with pytest.raises(InvalidCredentials) as exc:
            await authenticate(db, user.email, "correct-horse-battery")
        assert str(exc.value) == "Incorrect email or password."

    async def test_kills_sessions_that_are_already_open(self, db, admin, user):
        token = await create_session(db, user)
        assert await session_user(db, token) is not None

        await suspend_user(db, admin, user)
        await db.flush()

        assert await session_user(db, token) is None, "suspension must log them out now"

    async def test_removes_their_targets_from_the_scan_queue(self, db, admin, user):
        from app.services.scan_service import due_targets

        await make_target(db, user)
        assert len(await due_targets(db)) == 1

        await suspend_user(db, admin, user)
        await db.flush()

        assert await due_targets(db) == [], "a suspended account's scans must stop"

    async def test_other_users_keep_scanning(self, db, admin, user, pro_user):
        from app.services.scan_service import due_targets

        await make_target(db, user, "theirs")
        await make_target(db, pro_user, "mine")

        await suspend_user(db, admin, user)
        await db.flush()

        remaining = await due_targets(db)
        assert [t.user_id for t in remaining] == [pro_user.id]

    async def test_deletes_nothing(self, db, admin, user):
        target = await make_target(db, user)
        await suspend_user(db, admin, user)
        await db.flush()

        assert await db.get(TrackedTarget, target.id) is not None
        assert await db.get(User, user.id) is not None

    async def test_writes_an_audit_entry(self, db, admin, user):
        await suspend_user(db, admin, user, reason="spam")
        await db.flush()

        entry = await db.scalar(
            select(AdminAuditLog).where(AdminAuditLog.action == "user.suspended")
        )
        assert entry is not None
        assert entry.details["reason"] == "spam"

    async def test_cannot_suspend_yourself(self, db, admin):
        # Otherwise the only administrator can lock themselves out of the panel
        # that would let them undo it.
        with pytest.raises(AdminActionError, match="your own account"):
            await suspend_user(db, admin, admin)

    async def test_cannot_suspend_another_admin(self, db, admin):
        other = User(email="other-admin@example.com", is_admin=True)
        db.add(other)
        await db.flush()

        with pytest.raises(AdminActionError, match="Administrator accounts"):
            await suspend_user(db, admin, other)

    async def test_double_suspension_is_rejected(self, db, admin, user):
        await suspend_user(db, admin, user)
        with pytest.raises(AdminActionError, match="already suspended"):
            await suspend_user(db, admin, user)


class TestUnsuspension:
    async def test_restores_access_and_scanning(self, db, admin, user):
        from app.services.scan_service import due_targets

        await make_target(db, user)
        await suspend_user(db, admin, user, reason="mistake")
        await db.flush()

        await unsuspend_user(db, admin, user)
        await db.flush()

        assert user.is_suspended is False
        assert user.suspended_at is None
        assert user.suspension_reason is None
        assert (await authenticate(db, user.email, "correct-horse-battery")).id == user.id
        assert len(await due_targets(db)) == 1

    async def test_records_the_previous_reason(self, db, admin, user):
        await suspend_user(db, admin, user, reason="abuse report #12")
        await unsuspend_user(db, admin, user)
        await db.flush()

        entry = await db.scalar(
            select(AdminAuditLog).where(AdminAuditLog.action == "user.unsuspended")
        )
        assert entry.details["previous_reason"] == "abuse report #12"

    async def test_unsuspending_an_active_user_is_rejected(self, db, admin, user):
        with pytest.raises(AdminActionError, match="not suspended"):
            await unsuspend_user(db, admin, user)


class TestUserListing:
    async def test_paginates(self, db):
        for i in range(7):
            db.add(User(email=f"u{i}@example.com"))
        await db.flush()

        first = await list_users(db, page=1, per_page=3)
        assert len(first.rows) == 3
        assert first.total == 7
        assert first.pages == 3
        assert first.has_next is True
        assert first.has_prev is False

        last = await list_users(db, page=3, per_page=3)
        assert len(last.rows) == 1
        assert last.has_next is False

    async def test_search_matches_partial_addresses(self, db, user, pro_user):
        result = await list_users(db, search="pro@")
        assert [r.user.email for r in result.rows] == [pro_user.email]

    async def test_search_is_case_insensitive(self, db, user):
        result = await list_users(db, search="DEV@EXAMPLE")
        assert len(result.rows) == 1

    async def test_search_wildcards_are_escaped(self, db):
        # Without escaping, "%" would match every address.
        db.add(User(email="literal%match@example.com"))
        db.add(User(email="other@example.com"))
        await db.flush()

        result = await list_users(db, search="%")
        assert [r.user.email for r in result.rows] == ["literal%match@example.com"]

    async def test_total_respects_the_same_filters_as_the_rows(self, db, user, pro_user):
        # A count computed over different predicates gives a page count that
        # does not match the data.
        result = await list_users(db, search="pro@", per_page=1)
        assert result.total == 1
        assert result.pages == 1

    async def test_filters_by_status(self, db, admin, user, pro_user):
        await suspend_user(db, admin, user)
        await db.flush()

        suspended = await list_users(db, status="suspended")
        assert [r.user.email for r in suspended.rows] == [user.email]

        admins = await list_users(db, status="admin")
        assert [r.user.email for r in admins.rows] == [admin.email]

    async def test_counts_targets_and_open_alerts_per_user(self, db, user):
        await make_target(db, user, "a")
        await make_target(db, user, "b")

        result = await list_users(db)
        row = next(r for r in result.rows if r.user.id == user.id)
        assert row.target_count == 2
        assert row.open_alert_count == 0

    async def test_empty_result_is_not_an_error(self, db):
        result = await list_users(db, search="nobody-here")
        assert result.rows == []
        assert result.total == 0
        assert result.pages == 1


class TestMetrics:
    async def test_counts_users_without_exposing_legacy_tiers(self, db, user, pro_user):
        metrics = await platform_metrics(db)
        assert metrics.total_users == 2
        assert not hasattr(metrics, "free_users")
        assert not hasattr(metrics, "paid_users")

    async def test_handles_an_empty_platform_without_dividing_by_zero(self, db):
        metrics = await platform_metrics(db)
        assert metrics.total_users == 0
        assert metrics.noise_filtered_share == 0

    async def test_counts_targets_and_dependencies(self, db, user):
        target = await make_target(db, user)
        target.dependency_count = 42
        await db.flush()

        metrics = await platform_metrics(db)
        assert metrics.total_targets == 1
        assert metrics.total_dependencies == 42

    async def test_signup_series_fills_empty_days(self, db, user):
        points = await signups_over_time(db, days=14)
        assert len(points) == 14
        assert points[-1].cumulative == 1
        # Days with no signups are present with a zero, not omitted.
        assert all(p.count >= 0 for p in points)

    async def test_signup_series_is_cumulative_and_monotonic(self, db, user, pro_user):
        points = await signups_over_time(db, days=7)
        cumulative = [p.cumulative for p in points]
        assert cumulative == sorted(cumulative)
        assert cumulative[-1] == 2

    async def test_signups_before_the_window_still_count_toward_the_total(self, db, user):
        user.created_at = utcnow() - timedelta(days=90)
        await db.flush()

        points = await signups_over_time(db, days=7)
        # Otherwise the chart would appear to reset to zero.
        assert points[0].cumulative == 1
        assert points[-1].cumulative == 1


class TestFeedHealth:
    async def test_every_mirrored_ecosystem_is_listed_separately(self, db):
        # One rolled-up "OSV" row could read green while the Go export had been
        # failing for a week, and every Go user would be told they are clean.
        from app.services.mirror_service import MIRRORED_ECOSYSTEMS, mirror_feed_name

        feeds = {f.name: f for f in await feed_health(db)}
        # Derived, so adding an ecosystem cannot leave its feed unlisted — the
        # failure this test exists to prevent.
        assert set(feeds) == {"cisa_kev"} | {
            mirror_feed_name(ecosystem) for ecosystem in MIRRORED_ECOSYSTEMS
        }
        assert feeds["cisa_kev"].status == "never synced"
        assert feeds["cisa_kev"].is_healthy is False

    async def test_a_recent_sync_is_healthy(self, db):
        from app.models import FeedSync

        db.add(FeedSync(name="cisa_kev", last_success_at=utcnow(), record_count=1665))
        await db.flush()

        feeds = {f.name: f for f in await feed_health(db)}
        assert feeds["cisa_kev"].status == "ok"
        assert feeds["cisa_kev"].is_healthy is True

    async def test_an_old_sync_is_stale(self, db):
        from app.models import FeedSync

        db.add(FeedSync(name="cisa_kev", last_success_at=utcnow() - timedelta(days=3)))
        await db.flush()

        feeds = {f.name: f for f in await feed_health(db)}
        assert feeds["cisa_kev"].status == "stale"
        assert feeds["cisa_kev"].is_healthy is False

    async def test_a_recorded_error_reports_failing(self, db):
        from app.models import FeedSync

        db.add(
            FeedSync(
                name="osv_mirror_npm",
                last_success_at=utcnow(),
                last_error="503 from the npm export",
            )
        )
        await db.flush()

        feeds = {f.name: f for f in await feed_health(db)}
        assert feeds["osv_mirror_npm"].status == "failing"
        assert feeds["osv_mirror_npm"].is_healthy is False

    async def test_one_failing_ecosystem_does_not_hide_behind_the_others(self, db):
        from app.models import FeedSync

        for name in ("osv_mirror_npm", "osv_mirror_pypi"):
            db.add(FeedSync(name=name, last_success_at=utcnow(), record_count=5000))
        db.add(
            FeedSync(
                name="osv_mirror_go",
                last_success_at=utcnow() - timedelta(days=9),
                last_error="timeout fetching the Go export",
            )
        )
        await db.flush()

        feeds = {f.name: f for f in await feed_health(db)}
        assert feeds["osv_mirror_npm"].is_healthy is True
        assert feeds["osv_mirror_pypi"].is_healthy is True
        assert feeds["osv_mirror_go"].status == "failing"

    async def test_a_sync_that_stored_almost_nothing_is_visible(self, db):
        """A feed can succeed and still be broken.

        If an export starts returning a handful of records instead of tens of
        thousands, every status field says "ok" — the row count is the only
        thing that gives it away, so it has to be carried through to the admin
        view rather than only logged.
        """
        from app.models import FeedSync

        db.add(FeedSync(name="osv_mirror_npm", last_success_at=utcnow(), record_count=3))
        await db.flush()

        feeds = {f.name: f for f in await feed_health(db)}
        assert feeds["osv_mirror_npm"].status == "ok"
        assert feeds["osv_mirror_npm"].record_count == 3


class TestRevenue:
    async def _subscriber(self, db, email, status, cents, interval="month"):
        record = User(
            email=email,
            tier=Tier.PRO,
            dodo_subscription_id=f"sub_{email}",
            subscription_status=status,
            subscription_amount_cents=cents,
            subscription_currency="USD",
            subscription_interval=interval,
        )
        db.add(record)
        await db.flush()
        return record

    async def test_sums_mrr_over_paying_subscriptions(self, db):
        await self._subscriber(db, "a@example.com", "active", 1200)
        await self._subscriber(db, "b@example.com", "active", 1200)

        snapshot = await revenue_snapshot(db)
        assert snapshot.active_count == 2
        assert snapshot.mrr_cents == 2400
        assert snapshot.mrr == 24.0
        assert snapshot.arr == 288.0

    async def test_canceled_subscriptions_do_not_count_toward_mrr(self, db):
        await self._subscriber(db, "a@example.com", "active", 1200)
        await self._subscriber(db, "b@example.com", "canceled", 1200)

        snapshot = await revenue_snapshot(db)
        assert snapshot.mrr_cents == 1200
        assert snapshot.canceled_count == 1

    async def test_on_hold_still_counts_while_retrying(self, db):
        await self._subscriber(db, "a@example.com", "on_hold", 1200)
        snapshot = await revenue_snapshot(db)
        # `past_due_count` is the dunning bucket; Dodo names that state on_hold.
        assert snapshot.past_due_count == 1
        assert snapshot.mrr_cents == 1200

    async def test_annual_plans_are_normalised_to_a_month(self, db):
        # A yearly subscriber must not read as twelve months of revenue.
        await self._subscriber(db, "a@example.com", "active", 12000, interval="year")
        snapshot = await revenue_snapshot(db)
        assert snapshot.mrr_cents == 1000

    async def test_comped_accounts_are_surfaced_not_silently_dropped(self, db, admin):
        comped = User(email="comped@example.com", tier=Tier.PRO)
        db.add(comped)
        await db.flush()

        snapshot = await revenue_snapshot(db)
        assert snapshot.mrr_cents == 0
        assert snapshot.untracked_paid_count == 1

    async def test_empty_platform_reports_zero(self, db):
        snapshot = await revenue_snapshot(db)
        assert snapshot.mrr_cents == 0
        assert snapshot.active_count == 0
