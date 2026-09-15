"""The admin panel's endpoints, for the React application.

Access control is swept in `test_admin_access.py`; this file is about what the
endpoints actually do once an admin is through the door. The two behaviours
worth the most attention are the ones standing in front of something
irreversible, and both are asserted against the request rather than against the
dialog that normally precedes it:

* deleting an account requires the address typed back, server-side;
* sending a campaign requires the recipient count the admin agreed to, and is
  refused with a 409 if the audience moved underneath them.

A bookmarked URL, a replayed request or a script skips the dialog entirely.
These tests are the version of the guard that still applies when it does.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.types import ContactCategory, MessageStatus, Tier
from app.models import AdminAuditLog, ContactMessage, DocPage, User
from app.security import hash_password
from tests.conftest import set_csrf, sign_in
from tests.factories import attach_manifest

API = "/api/internal/admin"


@pytest.fixture
async def admin_user(db) -> User:
    record = User(
        email="root@example.com",
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


async def post(client, path: str, payload: dict | None = None):
    return await client.post(
        f"{API}{path}",
        json=payload or {},
        headers={"X-CSRF-Token": set_csrf(client)},
    )


class TestOverview:
    async def test_reports_the_platform_metrics(self, admin_client, user, pro_user):
        response = await admin_client.get(f"{API}/overview")
        assert response.status_code == 200

        metrics = response.json()["data"]["metrics"]
        assert metrics["total_users"] >= 3
        assert "paid_users" not in metrics
        assert "paid_share" not in metrics
        assert "noise_filtered_share" in metrics

    async def test_reports_feed_health_with_the_service_s_own_verdict(self, admin_client):
        feeds = (await admin_client.get(f"{API}/overview")).json()["data"]["feeds"]
        assert feeds, "feed health must not be empty — a broken feed is silent otherwise"
        for feed in feeds:
            assert feed["status"] in {"ok", "stale", "failing", "never synced"}

    async def test_the_signup_series_covers_the_requested_range(self, admin_client):
        payload = (await admin_client.get(f"{API}/overview?days=14")).json()["data"]
        assert payload["chart_days"] == 14
        assert len(payload["signups"]) == 14

    async def test_a_nonsense_range_falls_back_rather_than_erroring(self, admin_client):
        """A hand-edited URL should show the default range, not a 422."""
        response = await admin_client.get(f"{API}/overview?days=abc")
        assert response.status_code == 200
        assert response.json()["data"]["chart_days"] == 30

    async def test_an_out_of_bounds_range_is_clamped_by_falling_back(self, admin_client):
        response = await admin_client.get(f"{API}/overview?days=99999")
        assert response.status_code == 200
        assert response.json()["data"]["chart_days"] == 30

    async def test_the_response_is_never_cached(self, admin_client):
        response = await admin_client.get(f"{API}/overview")
        assert "no-store" in response.headers["cache-control"]


class TestUserList:
    async def test_lists_accounts_with_their_counts(self, admin_client, user, pro_user):
        payload = (await admin_client.get(f"{API}/users")).json()["data"]
        emails = {row["user"]["email"] for row in payload["rows"]}
        assert user.email in emails
        assert pro_user.email in emails
        assert payload["total"] >= 2
        assert all("target_count" in row for row in payload["rows"])

    async def test_search_narrows_the_list(self, admin_client, user, pro_user):
        payload = (await admin_client.get(f"{API}/users?search={pro_user.email}")).json()["data"]
        emails = {row["user"]["email"] for row in payload["rows"]}
        assert emails == {pro_user.email}

    async def test_retired_tier_filter_is_ignored(self, admin_client, user, pro_user):
        """Same reason as the chart range: a bad URL shows the list, not a 422."""
        response = await admin_client.get(f"{API}/users?tier=platinum")
        assert response.status_code == 200
        rows = response.json()["data"]["rows"]
        assert {row["user"]["tier"] for row in rows} == {"free"}

    async def test_no_password_hash_reaches_the_browser(self, admin_client, user):
        body = (await admin_client.get(f"{API}/users")).text
        assert "password_hash" not in body
        assert "$argon2" not in body


class TestUserDetail:
    async def test_returns_the_account_and_its_projects(self, admin_client, pro_user):
        response = await admin_client.get(f"{API}/users/{pro_user.id}")
        assert response.status_code == 200

        payload = response.json()["data"]
        assert payload["user"]["email"] == pro_user.email
        assert isinstance(payload["targets"], list)
        assert isinstance(payload["audit_entries"], list)

    async def test_an_account_with_history_serialises(self, admin_client, db, pro_user):
        """An account with an alert against it, which the bare fixture has not.

        Worth its own case: the first version of this endpoint called `.value`
        on the alert's channel and status, which are plain strings on that
        model, and every test passed because no fixture had ever sent one.
        """
        from app.core.types import AlertStatus, Ecosystem, Reachability, Severity, Verdict
        from app.models import Alert, CVEMatch, TrackedTarget, VulnerabilityRecord

        target = TrackedTarget(
            user_id=pro_user.id,
            name="acme-store",
            ecosystem=Ecosystem.NPM,
            manifest_content="{}",
            content_hash="e" * 64,
        )
        db.add(target)
        db.add(VulnerabilityRecord(id="GHSA-api-1", summary="test advisory"))
        await db.flush()
        manifest = await attach_manifest(db, target)

        match = CVEMatch(
            target_id=target.id,
            manifest_id=manifest.id,
            vulnerability_id="GHSA-api-1",
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
                user_id=pro_user.id,
                match_id=match.id,
                channel="email",
                destination=pro_user.email,
                subject="A finding in acme-store",
                status="sent",
            )
        )
        await db.flush()

        payload = (await admin_client.get(f"{API}/users/{pro_user.id}")).json()["data"]

        assert [row["name"] for row in payload["targets"]] == ["acme-store"]
        assert payload["recent_alerts"][0]["status"] == "sent"
        assert payload["recent_alerts"][0]["channel"] == "email"

    async def test_an_unknown_account_is_404(self, admin_client):
        response = await admin_client.get(f"{API}/users/999999")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"


class TestRetiredTierChange:
    async def test_the_mutation_endpoint_no_longer_exists(self, admin_client, db, user):
        response = await post(admin_client, f"/users/{user.id}/tier", {"tier": "pro"})
        assert response.status_code == 404
        await db.refresh(user)
        assert user.tier is Tier.FREE


class TestSuspension:
    async def test_suspends_and_unsuspends(self, admin_client, db, user):
        response = await post(admin_client, f"/users/{user.id}/suspend", {"reason": "abuse"})
        assert response.status_code == 200
        assert response.json()["data"]["user"]["is_suspended"] is True

        await db.refresh(user)
        assert user.is_suspended is True
        assert user.suspension_reason == "abuse"

        response = await post(admin_client, f"/users/{user.id}/unsuspend")
        assert response.status_code == 200

        await db.refresh(user)
        assert user.is_suspended is False

    async def test_an_admin_cannot_suspend_themselves(self, admin_client, db, admin_user):
        """The service refuses it. Asserted here because locking the only
        administrator out is unrecoverable from inside the product."""
        response = await post(admin_client, f"/users/{admin_user.id}/suspend", {"reason": "oops"})
        assert response.status_code == 400

        await db.refresh(admin_user)
        assert admin_user.is_suspended is False


class TestDeletion:
    async def test_deletes_when_the_address_is_typed_back(self, admin_client, db, user):
        user_id = user.id
        response = await post(
            admin_client, f"/users/{user_id}/delete", {"confirm_email": user.email}
        )
        assert response.status_code == 200
        assert response.json()["data"]["deleted"] is True

        assert await db.get(User, user_id) is None

    async def test_a_mismatched_address_deletes_nothing(self, admin_client, db, user):
        response = await post(
            admin_client, f"/users/{user.id}/delete", {"confirm_email": "someone@else.test"}
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "CONFIRMATION_MISMATCH"

        assert await db.get(User, user.id) is not None

    async def test_a_missing_confirmation_deletes_nothing(self, admin_client, db, user):
        """The dialog is a courtesy. This is the check, and it is the one that
        still applies to a hand-crafted request."""
        response = await post(admin_client, f"/users/{user.id}/delete", {})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "CONFIRMATION_REQUIRED"

        assert await db.get(User, user.id) is not None

    async def test_the_confirmation_is_case_insensitive(self, admin_client, db, user):
        user_id = user.id
        response = await post(
            admin_client, f"/users/{user_id}/delete", {"confirm_email": user.email.upper()}
        )
        assert response.status_code == 200
        assert await db.get(User, user_id) is None


class TestBilling:
    async def test_reports_the_revenue_snapshot(self, admin_client, pro_user):
        response = await admin_client.get(f"{API}/billing")
        assert response.status_code == 200

        payload = response.json()["data"]
        assert "mrr" in payload["snapshot"]
        assert "arr" in payload["snapshot"]
        assert isinstance(payload["subscribers"], list)


class TestDocs:
    async def test_creates_lists_updates_and_deletes_a_page(self, admin_client, db):
        created = await post(
            admin_client,
            "/docs",
            {"title": "Getting started", "content": "# Hi", "published": True},
        )
        assert created.status_code == 200
        page = created.json()["data"]["page"]
        assert page["slug"] == "getting-started", "the slug is derived from the title"

        listing = (await admin_client.get(f"{API}/docs")).json()["data"]["pages"]
        assert page["id"] in {row["id"] for row in listing}

        updated = await post(
            admin_client,
            f"/docs/{page['id']}",
            {"title": "Getting started", "slug": page["slug"], "content": "# Changed"},
        )
        assert updated.status_code == 200
        assert updated.json()["data"]["page"]["content"] == "# Changed"

        removed = await post(admin_client, f"/docs/{page['id']}/delete")
        assert removed.status_code == 200
        assert await db.get(DocPage, page["id"]) is None

    async def test_a_duplicate_slug_is_refused(self, admin_client, db):
        db.add(DocPage(slug="taken", title="Taken", content=""))
        await db.flush()

        response = await post(admin_client, "/docs", {"title": "Taken", "slug": "taken"})
        assert response.status_code == 400

    async def test_a_page_with_no_title_is_refused(self, admin_client):
        response = await post(admin_client, "/docs", {"title": "", "content": "orphan"})
        assert response.status_code == 400

    async def test_an_unknown_page_is_404(self, admin_client):
        assert (await admin_client.get(f"{API}/docs/999999")).status_code == 404

    async def test_edits_are_recorded_in_the_audit_trail(self, admin_client, db):
        await post(admin_client, "/docs", {"title": "Audited", "content": "x"})

        entry = await db.scalar(select(AdminAuditLog).where(AdminAuditLog.action == "docs.created"))
        assert entry is not None
        assert entry.details["slug"] == "audited"


class TestInbox:
    @pytest.fixture
    async def message(self, db) -> ContactMessage:
        record = ContactMessage(
            email="reporter@example.com",
            message="A finding that should not be a finding.",
            category=ContactCategory.BUG,
        )
        db.add(record)
        await db.flush()
        return record

    async def test_defaults_to_unread(self, admin_client, db, message):
        db.add(
            ContactMessage(
                email="done@example.com", message="Handled.", status=MessageStatus.RESOLVED
            )
        )
        await db.flush()

        payload = (await admin_client.get(f"{API}/inbox")).json()["data"]
        assert payload["show"] == "new"
        assert {row["email"] for row in payload["messages"]} == {message.email}

    async def test_show_all_returns_everything(self, admin_client, db, message):
        db.add(
            ContactMessage(
                email="done@example.com", message="Handled.", status=MessageStatus.RESOLVED
            )
        )
        await db.flush()

        payload = (await admin_client.get(f"{API}/inbox?show=all")).json()["data"]
        assert len(payload["messages"]) >= 2

    async def test_the_list_carries_a_preview_not_the_whole_body(self, admin_client, message):
        payload = (await admin_client.get(f"{API}/inbox")).json()["data"]
        row = payload["messages"][0]
        assert "preview" in row
        assert "ip_address" not in row, "the sender's IP is detail-view only"

    async def test_opening_a_message_marks_it_read(self, admin_client, db, message):
        response = await admin_client.get(f"{API}/inbox/{message.id}")
        assert response.status_code == 200
        assert response.json()["data"]["message"]["message"] == message.message

        await db.refresh(message)
        assert message.status is MessageStatus.READ

    async def test_the_unread_count_follows(self, admin_client, db, message):
        before = (await admin_client.get(f"{API}/inbox")).json()["data"]["unread"]
        assert before >= 1

        after = (await admin_client.get(f"{API}/inbox/{message.id}")).json()["data"]["unread"]
        assert after == before - 1

    async def test_status_changes_are_recorded(self, admin_client, db, message):
        response = await post(
            admin_client,
            f"/inbox/{message.id}/status",
            {"status": "resolved", "note": "Fixed in the reachability pass."},
        )
        assert response.status_code == 200

        await db.refresh(message)
        assert message.status is MessageStatus.RESOLVED
        assert message.admin_note == "Fixed in the reachability pass."

        entry = await db.scalar(
            select(AdminAuditLog).where(AdminAuditLog.action == "contact.status_changed")
        )
        assert entry is not None

    async def test_an_unknown_status_is_refused(self, admin_client, db, message):
        response = await post(admin_client, f"/inbox/{message.id}/status", {"status": "banana"})
        assert response.status_code == 400

        await db.refresh(message)
        assert message.status is MessageStatus.NEW

    async def test_an_unknown_message_is_404(self, admin_client):
        assert (await admin_client.get(f"{API}/inbox/999999")).status_code == 404


class TestCompose:
    async def test_returns_what_the_composer_needs(self, admin_client):
        payload = (await admin_client.get(f"{API}/email")).json()["data"]
        assert "{{user_email}}" in payload["variables"]
        assert payload["confirm_threshold"] >= 1
        assert {option["value"] for option in payload["audiences"]} == {
            "one",
            "all",
        }
        # Least dangerous first: the composer starts on whatever leads, and
        # "every account" should never be the option you get by not choosing.
        assert payload["audiences"][0]["value"] == "one"

    async def test_the_preview_resolves_variables_against_a_real_recipient(
        self, admin_client, user
    ):
        response = await post(
            admin_client,
            "/email/preview",
            {
                "subject": "Hello {{user_email}}",
                "body": "About {{project_name}}.",
                "audience": "all",
            },
        )
        assert response.status_code == 200

        payload = response.json()["data"]
        assert "{{" not in payload["subject"], "variables must be resolved, not echoed"
        assert payload["sample_email"] in payload["subject"]
        assert payload["count"] >= 2

    async def test_the_preview_sends_nothing(self, admin_client, db, user):
        from app.models import EmailLog

        await post(
            admin_client,
            "/email/preview",
            {"subject": "Draft", "body": "Body text.", "audience": "all"},
        )
        assert (await db.scalars(select(EmailLog))).all() == []

    async def test_a_one_off_address_with_no_account_still_resolves(self, admin_client):
        """Sending to somebody who has not signed up is a legitimate thing to
        do — a reply to a report from a logged-out visitor is exactly that."""
        response = await post(
            admin_client,
            "/email/preview",
            {
                "subject": "Hello",
                "body": "Body text.",
                "audience": "one",
                "audience_email": "nobody@nowhere.test",
            },
        )
        assert response.status_code == 200
        assert response.json()["data"]["count"] == 1

    async def test_an_audience_that_resolves_to_nobody_is_refused(self, admin_client):
        response = await post(
            admin_client,
            "/email/preview",
            {
                "subject": "Hello",
                "body": "Body text.",
                "audience": "one",
                "audience_email": "not-an-address",
            },
        )
        assert response.status_code == 400

    async def test_a_message_with_no_subject_is_refused(self, admin_client):
        response = await post(
            admin_client, "/email/preview", {"subject": "", "body": "Body.", "audience": "all"}
        )
        assert response.status_code == 400


class TestSendGuard:
    """The confirmed count is the whole guardrail. Each way around it is closed."""

    async def test_a_confirmed_send_goes_out(self, admin_client, db, user):
        preview = await post(
            admin_client,
            "/email/preview",
            {"subject": "Notice", "body": "Body text.", "audience": "all"},
        )
        count = preview.json()["data"]["count"]

        response = await post(
            admin_client,
            "/email/send",
            {
                "subject": "Notice",
                "body": "Body text.",
                "audience": "all",
                "confirmed_count": count,
            },
        )
        assert response.status_code == 200
        assert response.json()["data"]["sent"] == count

    async def test_sending_without_a_confirmation_is_refused(self, admin_client, db, user):
        from app.models import EmailLog

        response = await post(
            admin_client,
            "/email/send",
            {"subject": "Notice", "body": "Body text.", "audience": "all"},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "NOT_PREVIEWED"

        assert (await db.scalars(select(EmailLog))).all() == [], "nothing may have been sent"

    async def test_a_stale_count_is_refused_with_409(self, admin_client, db, user):
        """Somebody signed up between the preview and the send.

        A screen that said 47 while the send reached 48 would make the count
        decorative, so the mismatch stops the send rather than rounding it off.
        """
        from app.models import EmailLog

        response = await post(
            admin_client,
            "/email/send",
            {
                "subject": "Notice",
                "body": "Body text.",
                "audience": "all",
                "confirmed_count": 1,
            },
        )
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "AUDIENCE_CHANGED"

        assert (await db.scalars(select(EmailLog))).all() == []

    async def test_a_completed_send_is_audited(self, admin_client, db, user):
        preview = await post(
            admin_client,
            "/email/preview",
            {"subject": "Notice", "body": "Body text.", "audience": "all"},
        )
        await post(
            admin_client,
            "/email/send",
            {
                "subject": "Notice",
                "body": "Body text.",
                "audience": "all",
                "confirmed_count": preview.json()["data"]["count"],
            },
        )

        entry = await db.scalar(
            select(AdminAuditLog).where(AdminAuditLog.action == "email.campaign_sent")
        )
        assert entry is not None
        assert entry.details["subject"] == "Notice"


class TestAudit:
    async def test_lists_recent_entries(self, admin_client, db, user):
        await post(admin_client, f"/users/{user.id}/suspend", {"reason": "test"})

        payload = (await admin_client.get(f"{API}/audit")).json()["data"]
        actions = {entry["action"] for entry in payload["entries"]}
        assert "user.suspended" in actions
