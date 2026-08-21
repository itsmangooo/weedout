"""Permanent account deletion from the admin panel.

Three things have to hold and each fails differently:

* **The cascade is complete.** Orphaned findings pointing at a deleted account
  are worse than no deletion at all — they are undeletable and unattributable.
* **The last administrator survives.** Losing it locks everyone out of the
  panel that would undo the mistake, permanently.
* **The audit trail outlives the account.** The deletion record is the only
  remaining evidence that the account ever existed, so it must keep the email.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.core.types import (
    AlertStatus,
    Ecosystem,
    ManifestKind,
    Reachability,
    Severity,
    Tier,
    Verdict,
)
from app.models import (
    AdminAuditLog,
    Alert,
    CVEMatch,
    DependencyRecord,
    PasswordResetToken,
    ScanRun,
    Session,
    TrackedTarget,
    User,
    VulnerabilityRecord,
    utcnow,
)
from app.security import hash_password, hash_reset_token
from app.services.admin_service import AdminActionError, delete_user, is_last_admin
from app.services.auth_service import create_session
from tests.conftest import set_csrf, sign_in


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


async def populate(db, owner: User) -> dict[str, int]:
    """Give an account one of everything that should disappear with it."""
    # The advisory cache is global, so it is created once and shared — exactly
    # as it is in production, which is what makes the "not touched" test real.
    if await db.get(VulnerabilityRecord, "GHSA-del-1") is None:
        db.add(VulnerabilityRecord(id="GHSA-del-1", summary="test advisory"))
        await db.flush()

    target = TrackedTarget(
        user_id=owner.id,
        name="doomed-project",
        manifest_kind=ManifestKind.PACKAGE_JSON,
        ecosystem=Ecosystem.NPM,
        manifest_content="{}",
        content_hash="d" * 64,
    )
    db.add(target)
    await db.flush()

    db.add(
        DependencyRecord(
            target_id=target.id,
            ecosystem=Ecosystem.NPM,
            name="lodash",
            version="4.17.15",
            version_spec="4.17.15",
            reachability=Reachability.RUNTIME_DIRECT,
        )
    )
    db.add(ScanRun(target_id=target.id, status="success"))

    match = CVEMatch(
        target_id=target.id,
        vulnerability_id="GHSA-del-1",
        ecosystem=Ecosystem.NPM,
        package_name="lodash",
        package_version="4.17.15",
        reachability=Reachability.RUNTIME_DIRECT,
        verdict=Verdict.ACTIONABLE,
        severity=Severity.HIGH,
        actionable_reason="high_severity_direct",
        status=AlertStatus.OPEN,
    )
    db.add(match)
    await db.flush()

    db.add(
        Alert(
            user_id=owner.id,
            match_id=match.id,
            channel="email",
            destination=owner.email,
            subject="test alert",
            status="sent",
        )
    )
    db.add(
        PasswordResetToken(
            user_id=owner.id,
            # Per-owner so populating two accounts doesn't collide on the
            # unique token-hash index.
            token_hash=hash_reset_token(f"doomed-token-{owner.id}"),
            expires_at=utcnow(),
        )
    )
    await create_session(db, owner)
    await db.flush()

    return {"target_id": target.id, "match_id": match.id}


async def count(db, model, **filters) -> int:
    query = select(func.count()).select_from(model)
    for column, value in filters.items():
        query = query.where(getattr(model, column) == value)
    return (await db.scalar(query)) or 0


class TestCascade:
    async def test_everything_belonging_to_the_account_is_removed(self, db, admin, user):
        ids = await populate(db, user)
        user_id = user.id

        # Sanity: the fixture actually created data to delete.
        assert await count(db, TrackedTarget, user_id=user_id) == 1
        assert await count(db, Alert, user_id=user_id) == 1

        await delete_user(db, admin, user)
        await db.flush()

        assert await count(db, User, id=user_id) == 0
        assert await count(db, TrackedTarget, user_id=user_id) == 0
        assert await count(db, Session, user_id=user_id) == 0
        assert await count(db, Alert, user_id=user_id) == 0
        assert await count(db, PasswordResetToken, user_id=user_id) == 0
        # Reached through tracked_targets, two levels down.
        assert await count(db, DependencyRecord, target_id=ids["target_id"]) == 0
        assert await count(db, ScanRun, target_id=ids["target_id"]) == 0
        assert await count(db, CVEMatch, target_id=ids["target_id"]) == 0

    async def test_shared_advisory_cache_is_not_touched(self, db, admin, user):
        # Vulnerability records are global, not per-account. Cascading into them
        # would delete other users' data.
        await populate(db, user)
        await delete_user(db, admin, user)
        await db.flush()

        assert await count(db, VulnerabilityRecord, id="GHSA-del-1") == 1

    async def test_other_accounts_are_untouched(self, db, admin, user, pro_user):
        await populate(db, user)
        await populate(db, pro_user)

        await delete_user(db, admin, user)
        await db.flush()

        assert await count(db, User, id=pro_user.id) == 1
        assert await count(db, TrackedTarget, user_id=pro_user.id) == 1
        assert await count(db, Alert, user_id=pro_user.id) == 1

    async def test_returns_what_it_removed(self, db, admin, user):
        await populate(db, user)
        removed = await delete_user(db, admin, user)
        assert removed == {"targets": 1, "matches": 1, "alerts": 1}

    async def test_deleting_an_account_with_no_data_works(self, db, admin, user):
        removed = await delete_user(db, admin, user)
        await db.flush()
        assert removed == {"targets": 0, "matches": 0, "alerts": 0}
        assert await count(db, User, id=user.id) == 0


class TestAuditTrail:
    async def test_the_entry_survives_the_deletion_with_the_email(self, db, admin, user):
        email = user.email
        await populate(db, user)
        await delete_user(db, admin, user)
        await db.flush()

        entry = await db.scalar(select(AdminAuditLog).where(AdminAuditLog.action == "user.deleted"))
        assert entry is not None
        # The user row is gone, so the FK is nulled — but the address remains,
        # which is the whole point of denormalising it.
        assert entry.target_user_id is None
        assert entry.target_email == email
        assert entry.details["email"] == email
        assert entry.actor_email == admin.email

    async def test_the_entry_records_what_was_destroyed(self, db, admin, user):
        await populate(db, user)
        await delete_user(db, admin, user)
        await db.flush()

        entry = await db.scalar(select(AdminAuditLog).where(AdminAuditLog.action == "user.deleted"))
        assert entry.details["removed"] == {"targets": 1, "matches": 1, "alerts": 1}
        assert entry.details["tier"] == "free"

    async def test_earlier_entries_about_the_account_also_survive(self, db, admin, user):
        from app.services.admin_service import change_user_tier

        await change_user_tier(db, admin, user, Tier.PRO, note="comped")
        await db.flush()

        await delete_user(db, admin, user)
        await db.flush()

        entries = (await db.scalars(select(AdminAuditLog))).all()
        assert {e.action for e in entries} == {"user.tier_changed", "user.deleted"}
        assert all(e.target_email == user.email for e in entries)


class TestLastAdminProtection:
    async def test_is_last_admin_identifies_the_sole_admin(self, db, admin, user):
        assert await is_last_admin(db, admin) is True
        assert await is_last_admin(db, user) is False

    async def test_is_last_admin_is_false_when_another_exists(self, db, admin):
        second = User(email="second-admin@example.com", is_admin=True)
        db.add(second)
        await db.flush()

        assert await is_last_admin(db, admin) is False
        assert await is_last_admin(db, second) is False

    async def test_deleting_the_final_admin_is_refused(self, db, admin):
        # Construct the real situation: one admin, and someone else acting.
        actor = User(email="actor@example.com", is_admin=True)
        db.add(actor)
        await db.flush()
        # Demote the actor so `admin` is genuinely the only one left.
        actor.is_admin = False
        await db.flush()

        with pytest.raises(AdminActionError, match="only administrator"):
            await delete_user(db, actor, admin)

        assert await count(db, User, id=admin.id) == 1

    async def test_an_admin_cannot_delete_themselves(self, db, admin):
        with pytest.raises(AdminActionError, match="your own account"):
            await delete_user(db, admin, admin)
        assert await count(db, User, id=admin.id) == 1

    async def test_a_non_last_admin_can_be_deleted(self, db, admin):
        spare = User(email="spare-admin@example.com", is_admin=True)
        db.add(spare)
        await db.flush()

        await delete_user(db, admin, spare)
        await db.flush()

        assert await count(db, User, id=spare.id) == 0
        assert await count(db, User, id=admin.id) == 1


class TestDeleteRoute:
    @pytest.fixture
    async def admin_client(self, client, admin):
        response = await sign_in(client, admin.email)
        assert response.status_code == 200
        return client

    async def test_deletes_when_the_email_is_confirmed(self, admin_client, db, user):
        user_id = user.id
        await populate(db, user)

        csrf = set_csrf(admin_client)
        response = await admin_client.post(
            f"/admin/users/{user_id}/delete",
            data={"confirm_email": user.email, "csrf_token": csrf},
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/admin/users"
        assert await count(db, User, id=user_id) == 0

    async def test_confirmation_is_case_insensitive(self, admin_client, db, user):
        user_id = user.id
        csrf = set_csrf(admin_client)
        response = await admin_client.post(
            f"/admin/users/{user_id}/delete",
            data={"confirm_email": user.email.upper(), "csrf_token": csrf},
        )
        assert response.status_code == 303
        assert await count(db, User, id=user_id) == 0

    async def test_a_wrong_confirmation_deletes_nothing(self, admin_client, db, user):
        # The modal is a courtesy; this check is the one that still applies to a
        # hand-crafted POST.
        csrf = set_csrf(admin_client)
        response = await admin_client.post(
            f"/admin/users/{user.id}/delete",
            data={"confirm_email": "someone-else@example.com", "csrf_token": csrf},
        )
        assert response.status_code == 400
        # Jinja escapes the apostrophe in "doesn't".
        assert "match this account" in response.text

        assert await count(db, User, id=user.id) == 1

    async def test_a_missing_confirmation_deletes_nothing(self, admin_client, db, user):
        csrf = set_csrf(admin_client)
        response = await admin_client.post(
            f"/admin/users/{user.id}/delete", data={"csrf_token": csrf}
        )
        assert response.status_code == 400
        assert await count(db, User, id=user.id) == 1

    async def test_delete_requires_csrf(self, admin_client, db, user):
        response = await admin_client.post(
            f"/admin/users/{user.id}/delete", data={"confirm_email": user.email}
        )
        assert response.status_code == 403
        assert await count(db, User, id=user.id) == 1

    async def test_a_non_admin_cannot_delete_anyone(self, auth_client, db, pro_user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/admin/users/{pro_user.id}/delete",
            data={"confirm_email": pro_user.email, "csrf_token": csrf},
        )
        assert response.status_code == 403
        assert await count(db, User, id=pro_user.id) == 1

    async def test_deleting_a_missing_user_is_a_404(self, admin_client):
        csrf = set_csrf(admin_client)
        response = await admin_client.post(
            "/admin/users/999999/delete",
            data={"confirm_email": "ghost@example.com", "csrf_token": csrf},
        )
        assert response.status_code == 404

    async def test_self_deletion_is_refused_at_the_route(self, admin_client, db, admin):
        csrf = set_csrf(admin_client)
        response = await admin_client.post(
            f"/admin/users/{admin.id}/delete",
            data={"confirm_email": admin.email, "csrf_token": csrf},
        )
        assert response.status_code == 400
        assert await count(db, User, id=admin.id) == 1

    async def test_the_user_page_offers_deletion(self, admin_client, user):
        response = await admin_client.get(f"/admin/users/{user.id}")
        assert response.status_code == 200
        assert "Delete this account" in response.text
        assert f'action="/admin/users/{user.id}/delete"' in response.text
