"""Route-level behaviour: tier gating, ownership scoping, and triage actions."""

from __future__ import annotations

import json

from sqlalchemy import select

from app.core.types import AlertStatus, ManifestKind, Verdict
from app.models import CVEMatch, TrackedTarget
from tests.conftest import set_csrf
from tests.test_scan_pipeline import LODASH_ADVISORY, MANIFEST, seed_mirror


class TestPublicPages:
    async def test_landing_page_renders_for_anonymous_visitors(self, client):
        response = await client.get("/")
        assert response.status_code == 200
        assert "Weed out the CVE alerts" in response.text

    async def test_landing_page_redirects_signed_in_users(self, auth_client):
        response = await auth_client.get("/")
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

    async def test_pricing_page_lists_both_plans(self, client):
        response = await client.get("/pricing")
        assert response.status_code == 200
        assert "Free" in response.text
        assert "Pro" in response.text

    async def test_healthz_is_public(self, client):
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_readyz_reports_database_and_feed_state(self, client):
        response = await client.get("/readyz")
        assert response.status_code == 200
        body = response.json()
        assert body["checks"]["database"] == "ok"
        assert body["checks"]["kev_feed"] == "never synced"

    async def test_unknown_page_renders_a_404(self, client):
        response = await client.get("/no-such-page", headers={"accept": "text/html"})
        assert response.status_code == 404
        assert "Page not found" in response.text

    async def test_security_headers_are_present(self, client):
        response = await client.get("/")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


class TestTargetRoutes:
    async def test_uploading_a_manifest_creates_a_target(self, auth_client, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        csrf = set_csrf(auth_client)

        response = await auth_client.post(
            "/targets",
            data={"name": "My App", "csrf_token": csrf},
            files={"manifest": ("package.json", MANIFEST, "application/json")},
        )
        assert response.status_code == 303

        target = await db.scalar(select(TrackedTarget).where(TrackedTarget.user_id == user.id))
        assert target is not None
        assert target.name == "My App"
        assert target.manifest_kind is ManifestKind.PACKAGE_JSON
        assert target.dependency_count == 3

    async def test_initial_scan_findings_are_not_also_emailed_later(self, auth_client, db, user):
        # The user is reading these on screen right now. If they were left
        # un-notified, the next scheduled scan would mail the whole list back —
        # precisely the noise this product exists to remove.
        await seed_mirror(db, LODASH_ADVISORY)
        csrf = set_csrf(auth_client)
        await auth_client.post(
            "/targets", data={"filename": "package.json", "content": MANIFEST, "csrf_token": csrf}
        )

        match = await db.scalar(select(CVEMatch).where(CVEMatch.verdict == Verdict.ACTIONABLE))
        assert match is not None
        assert match.notified_at is not None, "initial findings must count as delivered"

    async def test_pasted_manifest_works_the_same_as_an_upload(self, auth_client, db, user):
        await seed_mirror(db)
        csrf = set_csrf(auth_client)

        response = await auth_client.post(
            "/targets",
            data={"filename": "package.json", "content": MANIFEST, "csrf_token": csrf},
        )
        assert response.status_code == 303
        assert await db.scalar(select(TrackedTarget).where(TrackedTarget.user_id == user.id))

    async def test_free_tier_is_capped_at_one_project(self, auth_client, db, user):
        await seed_mirror(db)
        csrf = set_csrf(auth_client)
        first = await auth_client.post(
            "/targets",
            data={"filename": "package.json", "content": MANIFEST, "csrf_token": csrf},
        )
        assert first.status_code == 303

        csrf = set_csrf(auth_client)
        second = await auth_client.post(
            "/targets",
            data={"filename": "package.json", "content": MANIFEST, "csrf_token": csrf},
        )

        assert second.status_code == 402
        assert "Upgrade to Pro" in second.text
        count = len((await db.scalars(select(TrackedTarget))).all())
        assert count == 1

    async def test_unrecognisable_file_is_rejected_with_an_explanation(self, auth_client):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/targets",
            data={"filename": "mystery.bin", "content": "just some prose", "csrf_token": csrf},
        )
        assert response.status_code == 400
        assert "Could not recognise" in response.text

    async def test_manifest_with_no_checkable_versions_is_rejected(self, auth_client):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/targets",
            data={
                "filename": "package.json",
                "content": json.dumps({"dependencies": {"a": "*"}}),
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 400
        assert "No dependencies" in response.text

    async def test_empty_submission_is_rejected(self, auth_client):
        csrf = set_csrf(auth_client)
        response = await auth_client.post("/targets", data={"csrf_token": csrf})
        assert response.status_code == 400
        assert "Choose a file or paste" in response.text

    async def test_creating_a_target_requires_authentication(self, client):
        csrf = set_csrf(client)
        response = await client.post("/targets", data={"content": MANIFEST, "csrf_token": csrf})
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    async def test_target_detail_shows_the_findings(self, auth_client, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        csrf = set_csrf(auth_client)
        await auth_client.post(
            "/targets", data={"filename": "package.json", "content": MANIFEST, "csrf_token": csrf}
        )
        target = await db.scalar(select(TrackedTarget))

        response = await auth_client.get(f"/targets/{target.id}")
        assert response.status_code == 200
        assert "lodash" in response.text

    async def test_cannot_view_another_users_target(self, auth_client, db, pro_user):
        other = TrackedTarget(
            user_id=pro_user.id,
            name="not yours",
            manifest_kind=ManifestKind.PACKAGE_JSON,
            ecosystem="npm",
            manifest_content="{}",
            content_hash="x" * 64,
        )
        db.add(other)
        await db.flush()

        response = await auth_client.get(f"/targets/{other.id}")
        assert response.status_code == 404

    async def test_cannot_delete_another_users_target(self, auth_client, db, pro_user):
        other = TrackedTarget(
            user_id=pro_user.id,
            name="not yours",
            manifest_kind=ManifestKind.PACKAGE_JSON,
            ecosystem="npm",
            manifest_content="{}",
            content_hash="y" * 64,
        )
        db.add(other)
        await db.flush()

        csrf = set_csrf(auth_client)
        response = await auth_client.post(f"/targets/{other.id}/delete", data={"csrf_token": csrf})
        assert response.status_code == 404
        assert await db.get(TrackedTarget, other.id) is not None


class TestAlertRoutes:
    async def _seed(self, auth_client, db):
        await seed_mirror(db, LODASH_ADVISORY)
        csrf = set_csrf(auth_client)
        await auth_client.post(
            "/targets", data={"filename": "package.json", "content": MANIFEST, "csrf_token": csrf}
        )
        return await db.scalar(select(CVEMatch))

    async def test_alert_detail_explains_in_plain_language(self, auth_client, db):
        match = await self._seed(auth_client, db)
        response = await auth_client.get(f"/alerts/{match.id}")
        assert response.status_code == 200
        assert "Why you're seeing this" in response.text
        assert "What to do" in response.text
        # The fix is a command you can paste, not just a version number.
        assert "npm install lodash@4.17.21" in response.text

    async def test_dismissing_a_finding_updates_its_status(self, auth_client, db):
        match = await self._seed(auth_client, db)
        csrf = set_csrf(auth_client)

        response = await auth_client.post(
            f"/alerts/{match.id}/status",
            data={"status": "dismissed", "note": "accepted risk", "csrf_token": csrf},
        )
        assert response.status_code == 303

        await db.refresh(match)
        assert match.status is AlertStatus.DISMISSED
        assert match.dismiss_note == "accepted risk"
        assert match.dismissed_at is not None

    async def test_reopening_clears_the_dismissal(self, auth_client, db):
        match = await self._seed(auth_client, db)
        match.status = AlertStatus.DISMISSED
        await db.flush()

        csrf = set_csrf(auth_client)
        await auth_client.post(
            f"/alerts/{match.id}/status", data={"status": "open", "csrf_token": csrf}
        )
        await db.refresh(match)
        assert match.status is AlertStatus.OPEN
        assert match.dismissed_at is None

    async def test_resolved_cannot_be_set_by_hand(self, auth_client, db):
        # Resolution is a fact a scan establishes. Letting a user assert it
        # would be contradicted by the next scan.
        match = await self._seed(auth_client, db)
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/alerts/{match.id}/status", data={"status": "resolved", "csrf_token": csrf}
        )
        assert response.status_code == 400

    async def test_invalid_status_is_rejected(self, auth_client, db):
        match = await self._seed(auth_client, db)
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/alerts/{match.id}/status", data={"status": "banana", "csrf_token": csrf}
        )
        assert response.status_code == 400

    async def test_status_change_requires_csrf(self, auth_client, db):
        match = await self._seed(auth_client, db)
        response = await auth_client.post(
            f"/alerts/{match.id}/status", data={"status": "dismissed"}
        )
        assert response.status_code == 403

    async def test_cannot_touch_another_users_alert(self, client, db, user, pro_user):
        from app.core.types import Ecosystem, Reachability, Severity, Verdict
        from app.models import VulnerabilityRecord

        db.add(VulnerabilityRecord(id="GHSA-other", summary="x"))
        target = TrackedTarget(
            user_id=pro_user.id,
            name="theirs",
            manifest_kind=ManifestKind.PACKAGE_JSON,
            ecosystem="npm",
            manifest_content="{}",
            content_hash="z" * 64,
        )
        db.add(target)
        await db.flush()

        match = CVEMatch(
            target_id=target.id,
            vulnerability_id="GHSA-other",
            ecosystem=Ecosystem.NPM,
            package_name="x",
            package_version="1.0.0",
            reachability=Reachability.RUNTIME_DIRECT,
            verdict=Verdict.ACTIONABLE,
            severity=Severity.HIGH,
            actionable_reason="high_severity_direct",
        )
        db.add(match)
        await db.flush()

        csrf = set_csrf(client)
        await client.post(
            "/login",
            data={"email": user.email, "password": "correct-horse-battery", "csrf_token": csrf},
        )

        assert (await client.get(f"/alerts/{match.id}")).status_code == 404

        csrf = set_csrf(client)
        response = await client.post(
            f"/alerts/{match.id}/status", data={"status": "dismissed", "csrf_token": csrf}
        )
        assert response.status_code == 404


class TestSettingsRoutes:
    async def test_toggling_email_alerts_persists(self, auth_client, db, user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post("/settings/alerts", data={"csrf_token": csrf})
        assert response.status_code == 200

        await db.refresh(user)
        assert user.email_alerts_enabled is False

    async def test_changing_password_requires_the_current_one(self, auth_client):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/settings/password",
            data={
                "current_password": "wrong",
                "new_password": "a-brand-new-password",
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 400
        assert "current password is incorrect" in response.text.lower()

    async def test_changing_password_keeps_the_current_session_alive(self, auth_client, db, user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/settings/password",
            data={
                "current_password": "correct-horse-battery",
                "new_password": "a-brand-new-password",
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 303
        # Every other session was revoked, but this one was reissued.
        assert (await auth_client.get("/settings")).status_code == 200

    async def test_weak_new_password_is_rejected(self, auth_client):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/settings/password",
            data={
                "current_password": "correct-horse-battery",
                "new_password": "short",
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 400
