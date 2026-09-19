"""The contact form and the admin inbox.

Two properties matter here and neither is obvious from reading the handler:

* An anonymous visitor can send a message. This is the whole point -- "I cannot
  sign up" and "I cannot log in" are reports that by definition come from
  somebody without a session -- and it is the property most easily broken by a
  later refactor that adds `CurrentUser` to the route.
* An authenticated sender's address comes from their session and not from the
  form, so the form cannot be used to put words in an account's mouth.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.core.types import ContactCategory, EmailStatus, MessageStatus, Tier
from app.models import ContactMessage, EmailLog, User
from app.security import hash_password
from tests.conftest import set_csrf, sign_in


@pytest.fixture
async def admin_user(db) -> User:
    record = User(
        email="inbox-admin@example.com",
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


class TestAnyoneCanSend:
    async def test_the_form_is_reachable_logged_out(self, client):
        """The page is the React shell now — its copy is covered by the
        frontend suite. What has to hold here is that a stranger who has never
        signed in can reach it at all."""
        assert (await client.get("/contact")).status_code == 200

    async def test_an_anonymous_visitor_can_send_a_message(self, client, db):
        csrf = set_csrf(client)
        response = await client.post(
            "/api/internal/contact",
            json={
                "email": "stranger@example.com",
                "category": "bug",
                "message": "The signup page returns a 500 when the email has a plus sign.",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200
        assert response.json()["data"]["sent"] is True

        row = (await db.execute(select(ContactMessage))).scalars().one()
        assert row.email == "stranger@example.com"
        assert row.user_id is None
        assert row.category is ContactCategory.BUG
        assert row.status is MessageStatus.NEW

    async def test_an_authenticated_sender_needs_no_address(self, auth_client, db, user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/api/internal/contact",
            json={
                "category": "feedback",
                "message": "The filtered tab is the best part and I would like it first.",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200

        row = (await db.execute(select(ContactMessage))).scalars().one()
        assert row.email == user.email
        assert row.user_id == user.id

    async def test_the_form_cannot_speak_for_an_account(self, auth_client, db, user):
        """A signed-in sender's address comes from the session, not the form."""
        csrf = set_csrf(auth_client)
        await auth_client.post(
            "/api/internal/contact",
            json={
                "email": "someone-else@example.com",
                "category": "billing",
                "message": "Please refund the subscription on this account, thanks.",
            },
            headers={"X-CSRF-Token": csrf},
        )
        row = (await db.execute(select(ContactMessage))).scalars().one()
        assert row.email == user.email
        assert row.email != "someone-else@example.com"

    async def test_a_blank_category_is_not_an_error(self, client, db):
        csrf = set_csrf(client)
        response = await client.post(
            "/api/internal/contact",
            json={
                "email": "stranger@example.com",
                "category": "",
                "message": "Nothing is broken, I just wanted to say the CLI is nice.",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200
        row = (await db.execute(select(ContactMessage))).scalars().one()
        assert row.category is ContactCategory.OTHER

    async def test_a_one_word_message_is_refused_in_plain_english(self, client, db):
        csrf = set_csrf(client)
        response = await client.post(
            "/api/internal/contact",
            json={"email": "a@example.com", "message": "broken"},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 400
        assert "at least a sentence" in response.text
        # And nothing was stored.
        assert (await db.execute(select(ContactMessage))).scalars().first() is None

    async def test_an_anonymous_sender_must_leave_an_address(self, client, db):
        csrf = set_csrf(client)
        response = await client.post(
            "/api/internal/contact",
            json={
                "email": "not-an-address",
                "message": "This is a long enough message to pass the length check.",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 400
        assert "address to reply to" in response.text
        assert (await db.execute(select(ContactMessage))).scalars().first() is None

    async def test_the_message_survives_a_mail_failure(self, client, db, monkeypatch):
        """A broken mail provider must not cost us the report.

        The row is committed before the notification is attempted, so the only
        thing a failure changes is that `notified_at` stays null -- which is
        what the inbox shows as "not emailed".
        """
        from app.mail import EmailError

        async def explode(*args, **kwargs):
            raise EmailError("smtp is having an afternoon")

        monkeypatch.setattr("app.services.email_service.send_email", explode)
        settings = get_settings().model_copy(update={"admin_email": "admin@example.com"})
        monkeypatch.setattr("app.services.contact_service.get_settings", lambda: settings)

        csrf = set_csrf(client)
        response = await client.post(
            "/api/internal/contact",
            json={
                "email": "stranger@example.com",
                "message": "Something went wrong on the dashboard and I cannot tell what.",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200
        assert response.json()["data"]["sent"] is True

        row = (await db.execute(select(ContactMessage))).scalars().one()
        assert row.notified_at is None

        # And the failure is in the send log rather than only in stderr.
        logged = (await db.execute(select(EmailLog))).scalars().all()
        assert [entry.status for entry in logged] == [EmailStatus.FAILED]


class TestTheInbox:
    """The admin queue, now served from /api/internal/admin/inbox.

    /admin/inbox is the React shell and holds nothing, so the access-control
    assertions are against the endpoint that holds the messages.
    """

    async def test_a_non_admin_cannot_reach_the_inbox(self, auth_client):
        response = await auth_client.get("/api/internal/admin/inbox")
        assert response.status_code == 403

    async def test_a_logged_out_visitor_cannot_reach_the_inbox(self, client):
        response = await client.get("/api/internal/admin/inbox")
        assert response.status_code == 401

    async def test_the_admin_sees_a_message(self, admin_client, db):
        db.add(
            ContactMessage(
                email="stranger@example.com",
                message="The alerts page shows a finding twice.",
                category=ContactCategory.BUG,
            )
        )
        await db.commit()

        response = await admin_client.get("/api/internal/admin/inbox")
        assert response.status_code == 200

        messages = response.json()["data"]["messages"]
        assert [row["email"] for row in messages] == ["stranger@example.com"]
        assert "shows a finding twice" in messages[0]["preview"]

    async def test_opening_a_message_marks_it_read(self, admin_client, db):
        row = ContactMessage(
            email="stranger@example.com", message="Something to read.", category=ContactCategory.BUG
        )
        db.add(row)
        await db.commit()
        assert row.status is MessageStatus.NEW

        response = await admin_client.get(f"/api/internal/admin/inbox/{row.id}")
        assert response.status_code == 200

        await db.refresh(row)
        assert row.status is MessageStatus.READ

    async def test_resolving_records_who_and_writes_an_audit_entry(self, admin_client, db):
        from app.models import AdminAuditLog

        row = ContactMessage(email="stranger@example.com", message="Please look at this.")
        db.add(row)
        await db.commit()

        response = await admin_client.post(
            f"/api/internal/admin/inbox/{row.id}/status",
            json={"status": "resolved", "note": "Fixed in 08a2671."},
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        assert response.status_code == 200

        await db.refresh(row)
        assert row.status is MessageStatus.RESOLVED
        assert row.handled_by_email == "inbox-admin@example.com"
        assert row.handled_at is not None
        assert row.admin_note == "Fixed in 08a2671."

        entries = (
            (
                await db.execute(
                    select(AdminAuditLog).where(AdminAuditLog.action == "contact.status_changed")
                )
            )
            .scalars()
            .all()
        )
        assert len(entries) == 1
        assert entries[0].details["message_id"] == row.id

    async def test_reopening_clears_the_handled_marks(self, admin_client, db):
        """Otherwise the page keeps claiming somebody dealt with it."""
        row = ContactMessage(email="stranger@example.com", message="Please look at this again.")
        db.add(row)
        await db.commit()

        for status in ("resolved", "new"):
            await admin_client.post(
                f"/api/internal/admin/inbox/{row.id}/status",
                json={"status": status},
                headers={"X-CSRF-Token": set_csrf(admin_client)},
            )

        await db.refresh(row)
        assert row.status is MessageStatus.NEW
        assert row.handled_at is None
        assert row.handled_by_email is None

    async def test_a_missing_message_is_a_404_not_a_500(self, admin_client):
        response = await admin_client.get("/api/internal/admin/inbox/999999")
        assert response.status_code == 404


class TestTheFormOffersOnlyRealCategories:
    """The select in the React page must not offer a value the API rejects.

    This drifted once already: the page listed "question", "false_positive" and
    "missed", none of which are `ContactCategory` members, so three of its six
    options produced "invalid request" for somebody who picked exactly what
    they were offered. Reading the options out of the source is ugly, but it is
    the only thing that fails when the two lists diverge again.
    """

    OPTIONS = re.compile(r'\{\s*value:\s*"([a-z_]+)"\s*,\s*label:', re.MULTILINE)

    def _page(self) -> str:
        path = (
            Path(__file__).resolve().parents[1] / "frontend" / "src" / "pages" / "ContactPage.jsx"
        )
        return path.read_text(encoding="utf-8")

    def test_the_options_were_found_at_all(self):
        """If the regex stops matching, the assertion below passes vacuously."""
        assert self.OPTIONS.findall(self._page())

    def test_every_offered_category_is_one_the_api_accepts(self):
        offered = set(self.OPTIONS.findall(self._page()))
        known = {member.value for member in ContactCategory}
        assert offered <= known, f"the form offers categories the API rejects: {offered - known}"

    async def test_each_offered_category_is_actually_accepted(self, client, db):
        """End to end, not just against the enum — the schema could narrow it."""
        for value in self.OPTIONS.findall(self._page()):
            csrf = set_csrf(client)
            response = await client.post(
                "/api/internal/contact",
                json={
                    "message": f"Testing the {value} category end to end.",
                    "category": value,
                    "email": f"{value}@example.com",
                },
                headers={"X-CSRF-Token": csrf},
            )
            assert response.status_code == 200, f"{value} was rejected: {response.text}"
