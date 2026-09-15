"""Admin compose access, confirmation, audiences, rendering, and audit tests."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.types import Ecosystem, EmailStatus, EmailTrigger, Tier
from app.models import AdminAuditLog, EmailCampaign, EmailLog, TrackedTarget, User
from app.security import hash_password
from tests.conftest import set_csrf, sign_in

COMPOSER = "/api/internal/admin/email"
DRAFT = {
    "subject": "A message",
    "body": "Hello there, this is the body.",
    "audience": "all",
    "audience_email": "",
}


@pytest.fixture
async def admin_user(db) -> User:
    record = User(
        email="sender@example.com",
        password_hash=hash_password("correct-horse-battery"),
        tier=Tier.FREE,
        is_admin=True,
    )
    db.add(record)
    await db.flush()
    return record


@pytest.fixture
async def admin_client(client, admin_user):
    response = await sign_in(client, admin_user.email)
    assert response.status_code == 200
    return client


async def make_users(db, *, count: int, suspended: int = 0, prefix: str = "user"):
    for index in range(count):
        db.add(User(email=f"{prefix}{index}@example.com", tier=Tier.FREE))
    for index in range(suspended):
        db.add(
            User(
                email=f"suspended{index}@example.com",
                tier=Tier.FREE,
                is_suspended=True,
            )
        )
    await db.flush()


async def preview(client, **overrides):
    return await client.post(
        f"{COMPOSER}/preview",
        json={**DRAFT, **overrides},
        headers={"X-CSRF-Token": set_csrf(client)},
    )


async def send(client, *, confirmed_count, **overrides):
    return await client.post(
        f"{COMPOSER}/send",
        json={**DRAFT, "confirmed_count": confirmed_count, **overrides},
        headers={"X-CSRF-Token": set_csrf(client)},
    )


async def logs(db) -> list[EmailLog]:
    return list((await db.scalars(select(EmailLog).order_by(EmailLog.id))).all())


class TestAccessControl:
    async def test_non_admin_cannot_read_preview_or_send(self, auth_client, db):
        await make_users(db, count=2)
        assert (await auth_client.get(COMPOSER)).status_code == 403
        assert (await preview(auth_client)).status_code == 403
        assert (await send(auth_client, confirmed_count=2)).status_code == 403
        assert await logs(db) == []

    async def test_logged_out_caller_gets_no_recipient_information(self, client, db):
        await make_users(db, count=2)
        response = await preview(client)
        assert response.status_code == 401
        assert "user0@example.com" not in response.text

    async def test_mutations_require_csrf(self, admin_client, db):
        await make_users(db, count=1)
        response = await admin_client.post(
            f"{COMPOSER}/send",
            json={**DRAFT, "confirmed_count": 2},
        )
        assert response.status_code == 403
        assert await logs(db) == []


class TestAudienceAndConfirmation:
    async def test_all_means_every_active_account_and_excludes_suspended(
        self, admin_client, db, admin_user
    ):
        await make_users(db, count=2, suspended=2)
        await db.commit()

        shown = await preview(admin_client)
        assert shown.status_code == 200
        assert shown.json()["data"]["count"] == 3

        delivered = await send(admin_client, confirmed_count=3)
        assert delivered.status_code == 200
        assert {row.recipient for row in await logs(db)} == {
            admin_user.email,
            "user0@example.com",
            "user1@example.com",
        }

    async def test_one_address_reaches_exactly_one(self, admin_client, db):
        await make_users(db, count=3)
        await db.commit()
        options = {"audience": "one", "audience_email": "user1@example.com"}
        assert (await preview(admin_client, **options)).json()["data"]["count"] == 1
        assert (await send(admin_client, confirmed_count=1, **options)).status_code == 200
        assert [row.recipient for row in await logs(db)] == ["user1@example.com"]

    @pytest.mark.parametrize("audience", ["pro", "free"])
    async def test_retired_tier_audiences_are_rejected(self, admin_client, audience):
        response = await preview(admin_client, audience=audience)
        assert response.status_code == 400

    async def test_send_is_refused_when_audience_grows(self, admin_client, db):
        await make_users(db, count=1)
        await db.commit()
        assert (await preview(admin_client)).json()["data"]["count"] == 2
        await make_users(db, count=1, prefix="late")
        await db.commit()

        response = await send(admin_client, confirmed_count=2)
        assert response.status_code == 409
        assert "Nothing was sent" in response.text
        assert await logs(db) == []

    async def test_unpreviewed_send_is_refused(self, admin_client, db):
        response = await send(admin_client, confirmed_count=None)
        assert response.status_code == 400
        assert "Preview" in response.text
        assert await logs(db) == []


class TestVariablesAndLogging:
    async def test_variables_are_resolved_per_recipient(self, admin_client, db):
        user = User(email="owner@example.com", tier=Tier.FREE)
        db.add(user)
        await db.flush()
        db.add(TrackedTarget(user_id=user.id, name="checkout-api", ecosystem=Ecosystem.NPM))
        await db.commit()

        options = {
            "audience": "one",
            "audience_email": user.email,
            "subject": "{{project_name}} for {{user_email}}",
        }
        shown = await preview(admin_client, **options)
        assert shown.json()["data"]["subject"] == "checkout-api for owner@example.com"
        assert (await send(admin_client, confirmed_count=1, **options)).status_code == 200
        entry = (await logs(db))[0]
        assert entry.subject == "checkout-api for owner@example.com"
        assert entry.trigger is EmailTrigger.ADMIN_MANUAL
        assert entry.status is EmailStatus.SENT
        assert entry.actor_email == "sender@example.com"

    async def test_missing_project_uses_a_readable_phrase(self, admin_client, db):
        options = {
            "audience": "one",
            "audience_email": "outside@example.com",
            "subject": "About {{project_name}}",
        }
        shown = await preview(admin_client, **options)
        assert shown.json()["data"]["subject"] == "About your project"

    async def test_composed_text_is_not_evaluated_as_a_template(self, admin_client, db):
        body = "Value: {{ settings.secret_key }} and {{ 7 * 6 }}"
        options = {
            "audience": "one",
            "audience_email": "outside@example.com",
            "body": body,
        }
        await preview(admin_client, **options)
        await send(admin_client, confirmed_count=1, **options)
        campaign = await db.scalar(select(EmailCampaign))
        assert campaign.body == body
        assert "42" not in campaign.body

    async def test_delivery_failure_is_recorded_and_audited(self, admin_client, db, monkeypatch):
        from app.mail import EmailError

        async def explode(*args, **kwargs):
            raise EmailError("relay unavailable")

        monkeypatch.setattr("app.services.email_service.send_email", explode)
        options = {"audience": "one", "audience_email": "outside@example.com"}
        await preview(admin_client, **options)
        response = await send(admin_client, confirmed_count=1, **options)

        assert response.status_code == 200
        assert response.json()["data"]["failed"] == 1
        entry = (await logs(db))[0]
        assert entry.status is EmailStatus.FAILED
        assert "relay unavailable" in entry.error
        audit = await db.scalar(
            select(AdminAuditLog).where(AdminAuditLog.action == "email.campaign_sent")
        )
        assert audit.details["recipients"] == 1
        assert audit.details["audience"] == "one"
