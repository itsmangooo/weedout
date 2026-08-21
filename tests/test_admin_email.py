"""The admin compose-and-send tool.

Three properties, and all three are the kind that look obviously true when you
read the handler and are wrong the moment somebody refactors it:

* A non-admin cannot reach any of it.
* The recipient count on the confirmation screen is the number that actually
  gets mailed. Not approximately -- exactly, or the send is refused.
* Variables resolve per recipient, so two people get two different emails.

The second is the reason this file exists. Composing is a textarea; sending to
every account is irreversible, and "we showed a number that was roughly right"
is not a guardrail.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.types import EmailStatus, EmailTrigger, Tier
from app.models import AdminAuditLog, EmailCampaign, EmailLog, TrackedTarget, User
from app.security import hash_password
from tests.conftest import set_csrf, sign_in


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
    assert response.status_code == 200, response.text
    return client


async def make_users(
    db, *, pro: int = 0, free: int = 0, suspended: int = 0, prefix: str = ""
) -> None:
    """`prefix` keeps a second batch from colliding with the first."""
    for index in range(pro):
        db.add(User(email=f"{prefix}pro{index}@example.com", tier=Tier.PRO))
    for index in range(free):
        db.add(User(email=f"{prefix}free{index}@example.com", tier=Tier.FREE))
    for index in range(suspended):
        db.add(User(email=f"{prefix}gone{index}@example.com", tier=Tier.PRO, is_suspended=True))
    await db.flush()


async def preview(client, **overrides) -> object:
    data = {
        "csrf_token": set_csrf(client),
        "subject": "A message",
        "body": "Hello there, this is the body.",
        "audience": "all",
        "audience_email": "",
    }
    data.update(overrides)
    return await client.post("/admin/email/preview", data=data)


async def send(client, *, confirmed_count, **overrides) -> object:
    data = {
        "csrf_token": set_csrf(client),
        "subject": "A message",
        "body": "Hello there, this is the body.",
        "audience": "all",
        "audience_email": "",
        "confirmed_count": str(confirmed_count),
    }
    data.update(overrides)
    return await client.post("/admin/email/send", data=data)


async def logs(db) -> list[EmailLog]:
    return list((await db.execute(select(EmailLog))).scalars().all())


class TestAccessControl:
    async def test_a_normal_user_cannot_open_the_composer(self, auth_client):
        response = await auth_client.get("/admin/email", follow_redirects=False)
        assert response.status_code in (303, 403, 404)

    async def test_a_normal_user_cannot_send(self, auth_client, db, user):
        await make_users(db, free=3)
        response = await auth_client.post(
            "/admin/email/send",
            data={
                "csrf_token": set_csrf(auth_client),
                "subject": "hi",
                "body": "hi",
                "audience": "all",
                "confirmed_count": "4",
            },
            follow_redirects=False,
        )
        assert response.status_code in (303, 403, 404)
        assert await logs(db) == []

    async def test_a_normal_user_cannot_preview_the_user_list(self, auth_client, db):
        """The preview leaks who is on the platform, so it is not a read-only
        page that happens to live under /admin."""
        await make_users(db, pro=2)
        response = await auth_client.post(
            "/admin/email/preview",
            data={
                "csrf_token": set_csrf(auth_client),
                "subject": "hi",
                "body": "hi",
                "audience": "pro",
            },
            follow_redirects=False,
        )
        assert response.status_code in (303, 403, 404)
        assert "pro0@example.com" not in response.text

    async def test_a_logged_out_visitor_cannot_send(self, client, db):
        await make_users(db, free=2)
        response = await client.post(
            "/admin/email/send",
            data={
                "csrf_token": set_csrf(client),
                "subject": "hi",
                "body": "hi",
                "audience": "all",
                "confirmed_count": "2",
            },
            follow_redirects=False,
        )
        assert response.status_code in (303, 403, 404)
        assert await logs(db) == []


class TestTheCountIsAPromise:
    async def test_the_previewed_count_is_what_gets_sent(self, admin_client, db, admin_user):
        await make_users(db, pro=3, free=2)
        await db.commit()

        response = await preview(admin_client)
        assert response.status_code == 200
        # 3 pro + 2 free + the admin themselves.
        assert "This will send to 6 people" in response.text

        assert (await send(admin_client, confirmed_count=6)).status_code == 200

        delivered = sorted(entry.recipient for entry in await logs(db))
        assert len(delivered) == 6
        assert "sender@example.com" in delivered

    async def test_a_send_is_refused_if_the_audience_grew(self, admin_client, db):
        """Somebody signs up between the confirmation and the send.

        Without this the count on the screen is decorative: the admin agreed to
        47 and 48 people were mailed.
        """
        await make_users(db, free=2)
        await db.commit()

        await preview(admin_client)  # 3 including the admin

        # Somebody signs up while the confirmation screen is on the admin's
        # monitor.
        await make_users(db, free=1, prefix="late-")
        await db.commit()

        response = await send(admin_client, confirmed_count=3)
        assert response.status_code == 409
        assert "audience changed" in response.text
        assert "Nothing was sent" in response.text
        assert await logs(db) == []

    async def test_a_send_is_refused_if_the_audience_shrank(self, admin_client, db):
        await make_users(db, free=3)
        await db.commit()
        await preview(admin_client)

        gone = (
            await db.execute(select(User).where(User.email == "free0@example.com"))
        ).scalar_one()
        gone.is_suspended = True
        await db.commit()

        response = await send(admin_client, confirmed_count=4)
        assert response.status_code == 409
        assert await logs(db) == []

    async def test_sending_without_confirming_is_refused(self, admin_client, db):
        """Reaching /send without the preview step -- a replayed form, a
        bookmarked URL, a script. The confirmation is the only thing between a
        textarea and every account on the platform."""
        await make_users(db, free=5)
        await db.commit()

        response = await send(admin_client, confirmed_count="")
        assert response.status_code == 400
        assert "Preview the message" in response.text
        assert await logs(db) == []

    async def test_suspended_accounts_are_never_included(self, admin_client, db):
        await make_users(db, free=2, suspended=3)
        await db.commit()

        response = await preview(admin_client)
        assert "This will send to 3 people" in response.text

        await send(admin_client, confirmed_count=3)
        delivered = {entry.recipient for entry in await logs(db)}
        assert not any(address.startswith("gone") for address in delivered)


class TestAudiences:
    async def test_pro_only_reaches_pro(self, admin_client, db):
        await make_users(db, pro=2, free=3)
        await db.commit()

        await preview(admin_client, audience="pro")
        await send(admin_client, audience="pro", confirmed_count=2)

        delivered = {entry.recipient for entry in await logs(db)}
        assert delivered == {"pro0@example.com", "pro1@example.com"}

    async def test_free_only_reaches_free(self, admin_client, db, admin_user):
        await make_users(db, pro=2, free=2)
        await db.commit()

        await preview(admin_client, audience="free")
        # The admin is on the free tier, so they are in this audience too.
        await send(admin_client, audience="free", confirmed_count=3)

        delivered = {entry.recipient for entry in await logs(db)}
        assert delivered == {"free0@example.com", "free1@example.com", "sender@example.com"}

    async def test_one_address_reaches_exactly_one(self, admin_client, db):
        await make_users(db, free=5)
        await db.commit()

        await preview(admin_client, audience="one", audience_email="free2@example.com")
        await send(
            admin_client, audience="one", audience_email="free2@example.com", confirmed_count=1
        )

        delivered = [entry.recipient for entry in await logs(db)]
        assert delivered == ["free2@example.com"]

    async def test_an_empty_audience_is_refused_before_the_confirmation(self, admin_client, db):
        response = await preview(admin_client, audience="pro")
        assert response.status_code == 400
        assert "nobody in it" in response.text


class TestVariables:
    async def test_each_recipient_gets_their_own_address(self, admin_client, db):
        await make_users(db, pro=2)
        await db.commit()

        body = "Hello {{user_email}}, this concerns your account."
        await preview(admin_client, audience="pro", body=body)
        await send(admin_client, audience="pro", body=body, confirmed_count=2)

        subjects = {entry.recipient: entry.subject for entry in await logs(db)}
        assert set(subjects) == {"pro0@example.com", "pro1@example.com"}

    async def test_the_project_name_resolves_per_recipient(self, admin_client, db):
        from app.core.types import Ecosystem

        one = User(email="one@example.com", tier=Tier.PRO)
        two = User(email="two@example.com", tier=Tier.PRO)
        db.add_all([one, two])
        await db.flush()
        db.add(TrackedTarget(user_id=one.id, name="acme-store", ecosystem=Ecosystem.NPM))
        db.add(TrackedTarget(user_id=two.id, name="beta-api", ecosystem=Ecosystem.NPM))
        await db.commit()

        subject = "{{project_name}} needs attention"
        await preview(admin_client, audience="pro", subject=subject)
        await send(admin_client, audience="pro", subject=subject, confirmed_count=2)

        by_recipient = {entry.recipient: entry.subject for entry in await logs(db)}
        assert by_recipient["one@example.com"] == "acme-store needs attention"
        assert by_recipient["two@example.com"] == "beta-api needs attention"

    async def test_somebody_with_no_project_gets_a_sentence_not_a_gap(self, admin_client, db):
        """ "Your project  has a finding" is how a product looks broken."""
        db.add(User(email="empty@example.com", tier=Tier.PRO))
        await db.commit()

        subject = "About {{project_name}}"
        await preview(admin_client, audience="pro", subject=subject)
        await send(admin_client, audience="pro", subject=subject, confirmed_count=1)

        entry = (await logs(db))[0]
        assert entry.subject == "About your project"

    async def test_the_preview_shows_resolved_variables(self, admin_client, db):
        db.add(User(email="shown@example.com", tier=Tier.PRO))
        await db.commit()

        response = await preview(admin_client, audience="pro", body="Dear {{user_email}}, hello.")
        assert "Dear shown@example.com, hello." in response.text
        # And the raw variable is not what is shown as the sample.
        assert "Dear {{user_email}}" not in response.text.split("mail-preview__body")[1][:200]

    async def test_the_body_is_not_evaluated_as_a_template(self, admin_client, db):
        """The body is typed into a browser by a human. Handing it to Jinja
        would make `{{ settings.secret_key }}` a working expression."""
        db.add(User(email="curious@example.com", tier=Tier.PRO))
        await db.commit()

        body = "Value: {{ settings.secret_key }} and {{ 7 * 6 }}"
        await preview(admin_client, audience="pro", body=body)
        await send(admin_client, audience="pro", body=body, confirmed_count=1)

        # Nothing was evaluated: the log records the subject, and the campaign
        # keeps the body exactly as typed.
        campaign = (await db.execute(select(EmailCampaign))).scalar_one()
        assert campaign.body == body
        assert "42" not in campaign.body


class TestTheSendLog:
    async def test_every_send_is_recorded_with_who_sent_it(self, admin_client, db):
        await make_users(db, pro=2)
        await db.commit()

        await preview(admin_client, audience="pro")
        await send(admin_client, audience="pro", confirmed_count=2)

        entries = await logs(db)
        assert len(entries) == 2
        for entry in entries:
            assert entry.trigger is EmailTrigger.ADMIN_MANUAL
            assert entry.actor_email == "sender@example.com"
            assert entry.status is EmailStatus.SENT
            assert entry.batch_id

        # One batch id, so six hundred rows still read as one event.
        assert len({entry.batch_id for entry in entries}) == 1

    async def test_the_campaign_row_matches_what_was_sent(self, admin_client, db):
        await make_users(db, pro=3)
        await db.commit()

        await preview(admin_client, audience="pro")
        await send(admin_client, audience="pro", confirmed_count=3)

        campaign = (await db.execute(select(EmailCampaign))).scalar_one()
        assert campaign.recipient_count == 3
        assert campaign.sent_count == 3
        assert campaign.failed_count == 0
        assert campaign.actor_email == "sender@example.com"

    async def test_a_failure_is_recorded_rather_than_lost(self, admin_client, db, monkeypatch):
        from app.mail import EmailError

        async def explode(*args, **kwargs):
            raise EmailError("the relay said no")

        monkeypatch.setattr("app.services.email_service.send_email", explode)

        await make_users(db, pro=2)
        await db.commit()
        await preview(admin_client, audience="pro")
        response = await send(admin_client, audience="pro", confirmed_count=2)

        assert response.status_code == 200
        assert "2 failed" in response.text

        entries = await logs(db)
        assert all(entry.status is EmailStatus.FAILED for entry in entries)
        assert all("relay said no" in (entry.error or "") for entry in entries)

    async def test_the_send_is_audited(self, admin_client, db):
        await make_users(db, pro=2)
        await db.commit()
        await preview(admin_client, audience="pro")
        await send(admin_client, audience="pro", confirmed_count=2)

        entry = (
            await db.execute(
                select(AdminAuditLog).where(AdminAuditLog.action == "email.campaign_sent")
            )
        ).scalar_one()
        assert entry.actor_email == "sender@example.com"
        assert entry.details["recipients"] == 2
        assert entry.details["sent"] == 2
        assert entry.details["audience"] == "pro"

    async def test_the_log_is_shown_on_the_page(self, admin_client, db):
        await make_users(db, pro=1)
        await db.commit()
        await preview(admin_client, audience="pro")
        await send(admin_client, audience="pro", confirmed_count=1)

        response = await admin_client.get("/admin/email")
        assert "pro0@example.com" in response.text
        assert "sender@example.com" in response.text
