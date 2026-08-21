"""Route-level behaviour: tier gating, ownership scoping, and triage actions."""

from __future__ import annotations

import json

from sqlalchemy import select

from app.core.types import AlertStatus, Ecosystem, KeyScope, ManifestKind, Verdict
from app.models import ApiKey, CVEMatch, DependencyRecord, ScanRun, TrackedTarget
from tests.conftest import create_project, set_csrf, sign_in
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

        response = await create_project(
            auth_client,
            name="My App",
            files={"manifest": ("package.json", MANIFEST, "application/json")},
        )
        assert response.status_code == 201

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
        await create_project(auth_client, filename="package.json", content=MANIFEST)

        match = await db.scalar(select(CVEMatch).where(CVEMatch.verdict == Verdict.ACTIONABLE))
        assert match is not None
        assert match.notified_at is not None, "initial findings must count as delivered"

    async def test_pasted_manifest_works_the_same_as_an_upload(self, auth_client, db, user):
        await seed_mirror(db)

        response = await create_project(auth_client, filename="package.json", content=MANIFEST)
        assert response.status_code == 201
        assert await db.scalar(select(TrackedTarget).where(TrackedTarget.user_id == user.id))

    async def test_free_tier_is_capped_at_one_project(self, auth_client, db, user):
        await seed_mirror(db)
        first = await create_project(auth_client, filename="package.json", content=MANIFEST)
        assert first.status_code == 201

        second = await create_project(auth_client, filename="package.json", content=MANIFEST)

        assert second.status_code == 402
        assert "pro" in second.json()["error"]["message"].lower()
        count = len((await db.scalars(select(TrackedTarget))).all())
        assert count == 1

    async def test_unrecognisable_file_is_rejected_with_an_explanation(self, auth_client):
        response = await create_project(
            auth_client, filename="mystery.bin", content="just some prose"
        )
        assert response.status_code == 400
        assert "Could not recognise" in response.text

    async def test_manifest_with_no_checkable_versions_is_rejected(self, auth_client):
        response = await create_project(
            auth_client,
            filename="package.json",
            content=json.dumps({"dependencies": {"a": "*"}}),
        )
        assert response.status_code == 400
        assert "No dependencies" in response.text

    async def test_empty_submission_is_rejected(self, auth_client):
        # With no file and no name, this is now read as an attempt to create a
        # project without a manifest, so the error names the missing field
        # rather than demanding a file the flow no longer requires.
        response = await create_project(
            auth_client,
        )
        assert response.status_code == 400
        assert "Give the project a name." in response.text
        assert "Value error" not in response.text

    async def test_creating_a_target_requires_authentication(self, client):
        response = await create_project(client, content=MANIFEST)

        # 401 rather than a redirect. This is a JSON endpoint, and a client
        # that followed a redirect here would try to parse a sign-in page as a
        # response body. The React boundary reads the 401 and shows the
        # signed-out state itself.
        assert response.status_code == 401

    async def test_target_detail_shows_the_findings(self, auth_client, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        await create_project(auth_client, filename="package.json", content=MANIFEST)
        target = await db.scalar(select(TrackedTarget))

        response = await auth_client.get(f"/api/internal/projects/{target.id}")
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

        response = await auth_client.get(f"/api/internal/projects/{other.id}")
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
        response = await auth_client.post(
            f"/api/internal/projects/{other.id}/delete", data={"csrf_token": csrf}
        )
        assert response.status_code == 404
        assert await db.get(TrackedTarget, other.id) is not None


class TestProjectLifecycle:
    """Creating a project before there is anything to scan, and managing it after.

    The distinction these tests defend is between "checked, nothing found" and
    "never checked". Collapsing the two would tell somebody they are safe on the
    strength of no evidence at all.
    """

    async def test_project_can_be_created_without_a_manifest(self, auth_client, db, user):

        response = await create_project(auth_client, name="checkout-api", ecosystem="npm")
        assert response.status_code == 201

        target = await db.scalar(select(TrackedTarget).where(TrackedTarget.user_id == user.id))
        assert target is not None
        assert target.name == "checkout-api"
        assert target.ecosystem is Ecosystem.NPM
        assert target.manifest_kind is None
        assert target.manifest_content is None
        assert target.content_hash is None
        assert target.has_manifest is False
        assert target.has_been_scanned is False
        # Nothing is scheduled: a sweep that picked this up would have no
        # manifest to compare and would only record a spurious failure.
        assert target.next_scan_at is None

    async def test_creating_without_a_manifest_needs_a_name_and_an_ecosystem(self, auth_client):
        no_ecosystem = await create_project(auth_client, name="checkout-api")
        assert no_ecosystem.status_code == 400
        assert "Choose which ecosystem this project uses." in no_ecosystem.text

        no_name = await create_project(auth_client, ecosystem="npm")
        assert no_name.status_code == 400
        assert "Give the project a name." in no_name.text

        # Neither message should arrive wearing pydantic's own wording.
        assert "Value error" not in no_ecosystem.text + no_name.text

    async def test_unscanned_project_never_claims_to_be_clean(self, auth_client, db, user):
        await create_project(auth_client, name="empty", ecosystem="npm")
        target = await db.scalar(select(TrackedTarget))

        # The page decides what to say; what the API owes it is the two facts
        # that make "no findings" and "never looked" distinguishable. A
        # response that reported zero findings without also saying there is no
        # manifest would leave the page no way to tell them apart.
        response = await auth_client.get(f"/api/internal/projects/{target.id}")

        assert response.status_code == 200
        body = response.json()
        assert body["data"]["has_manifest"] is False
        assert body["data"]["last_scanned_at"] is None
        assert body["findings"] == []

    async def test_attaching_a_manifest_scans_and_flips_the_state(self, auth_client, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        await create_project(auth_client, name="empty", ecosystem="npm")
        target = await db.scalar(select(TrackedTarget))
        assert target.has_been_scanned is False

        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/api/internal/projects/{target.id}/manifest",
            data={"filename": "package.json", "content": MANIFEST},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200

        await db.refresh(target)
        assert target.manifest_kind is ManifestKind.PACKAGE_JSON
        assert target.dependency_count == 3
        assert target.has_been_scanned is True
        assert target.next_scan_at is not None

    async def test_a_manifest_from_another_ecosystem_is_refused(self, auth_client, db):
        await seed_mirror(db)
        await create_project(auth_client, name="py-thing", ecosystem="PyPI")
        target = await db.scalar(select(TrackedTarget))

        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/api/internal/projects/{target.id}/manifest",
            data={"filename": "package.json", "content": MANIFEST},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 400
        await db.refresh(target)
        assert target.has_manifest is False

    async def test_renaming_leaves_the_findings_alone(self, auth_client, db):
        await seed_mirror(db, LODASH_ADVISORY)
        await create_project(auth_client, filename="package.json", content=MANIFEST)
        target = await db.scalar(select(TrackedTarget))
        before = len((await db.scalars(select(CVEMatch))).all())
        assert before > 0

        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/api/internal/projects/{target.id}/rename",
            json={"name": "renamed"},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200

        await db.refresh(target)
        assert target.name == "renamed"
        assert len((await db.scalars(select(CVEMatch))).all()) == before

    async def test_settings_shows_the_findings_count_from_the_other_tab(self, auth_client, db):
        # The number on the Findings tab is a fact about the project. Rendering
        # a zero there while standing on Settings would be the exact kind of
        # false all-clear this product exists to prevent.
        await seed_mirror(db, LODASH_ADVISORY)
        await create_project(auth_client, filename="package.json", content=MANIFEST)
        target = await db.scalar(select(TrackedTarget))

        counts = await db.scalars(
            select(CVEMatch).where(
                CVEMatch.target_id == target.id,
                CVEMatch.verdict == Verdict.ACTIONABLE,
                CVEMatch.status == AlertStatus.OPEN,
            )
        )
        expected = len(list(counts))
        assert expected > 0

        # Returned whichever view the page is on. The number on the Findings
        # tab is a fact about the project, and rendering a zero there because
        # the reader happened to be on Settings would be the same lie this
        # product exists to stop telling.
        response = await auth_client.get(f"/api/internal/projects/{target.id}?show=dismissed")

        assert response.status_code == 200
        assert response.json()["data"]["tab_counts"]["open"] == expected

    async def test_the_form_issues_the_scope_that_was_chosen(self, auth_client, db):
        """The selector has to actually reach the key, or the whole mechanism
        is a dropdown that changes nothing."""
        await create_project(auth_client, name="scoped", ecosystem="npm")
        target = await db.scalar(select(TrackedTarget))

        csrf = set_csrf(auth_client)
        await auth_client.post(
            f"/api/internal/projects/{target.id}/keys",
            json={"name": "laptop", "scope": "manage"},
            headers={"X-CSRF-Token": csrf},
        )

        key = await db.scalar(select(ApiKey).where(ApiKey.target_id == target.id))
        assert key.scope is KeyScope.MANAGE

    async def test_a_tampered_scope_falls_back_to_the_narrowest(self, auth_client, db):
        """Failing closed matters more here than a validation message: the
        only ways to send an unknown scope are a stale template or somebody
        editing the form, and neither should be able to widen a key."""
        await create_project(auth_client, name="tampered", ecosystem="npm")
        target = await db.scalar(select(TrackedTarget))

        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/api/internal/projects/{target.id}/keys",
            json={"name": "x", "scope": "admin"},
            headers={"X-CSRF-Token": csrf},
        )

        assert response.status_code == 200
        key = await db.scalar(select(ApiKey).where(ApiKey.target_id == target.id))
        assert key.scope is KeyScope.SCAN

    async def test_project_api_key_can_be_created_and_revoked(self, auth_client, db):
        await create_project(auth_client, name="ci-only", ecosystem="npm")
        target = await db.scalar(select(TrackedTarget))

        csrf = set_csrf(auth_client)
        created = await auth_client.post(
            f"/api/internal/projects/{target.id}/keys",
            json={"name": "github-actions"},
            headers={"X-CSRF-Token": csrf},
        )
        assert created.status_code == 200

        key = await db.scalar(select(ApiKey).where(ApiKey.target_id == target.id))
        assert key is not None
        assert key.is_active

        # The plaintext is shown in the response body and stored nowhere.
        assert key.token_hash not in created.text

        csrf = set_csrf(auth_client)
        revoked = await auth_client.post(
            f"/api/internal/projects/{target.id}/keys/{key.id}/revoke",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        assert revoked.status_code == 200

        await db.refresh(key)
        assert key.is_active is False
        assert key.revoked_at is not None

    async def test_deleting_a_project_takes_everything_with_it(self, auth_client, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        await create_project(auth_client, filename="package.json", content=MANIFEST)
        target = await db.scalar(select(TrackedTarget))
        target_id = target.id

        csrf = set_csrf(auth_client)
        await auth_client.post(
            f"/api/internal/projects/{target_id}/keys",
            json={"name": "ci"},
            headers={"X-CSRF-Token": csrf},
        )

        # Everything that hangs off the project must exist first, or "it's all
        # gone afterwards" proves nothing.
        assert len((await db.scalars(select(CVEMatch))).all()) > 0
        assert len((await db.scalars(select(DependencyRecord))).all()) > 0
        assert len((await db.scalars(select(ScanRun))).all()) > 0
        assert len((await db.scalars(select(ApiKey))).all()) > 0

        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/api/internal/projects/{target_id}/delete",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        # A JSON endpoint reports what happened; the client decides where to
        # go next. There is no page here to redirect to.
        assert response.status_code == 200
        assert response.json()["data"]["deleted"] is True

        assert await db.get(TrackedTarget, target_id) is None
        for model in (CVEMatch, DependencyRecord, ScanRun, ApiKey):
            rows = (await db.scalars(select(model))).all()
            assert rows == [], f"{model.__name__} rows survived the project delete"

        # The account itself is untouched.
        assert await db.get(type(user), user.id) is not None

    async def test_non_owner_cannot_reach_another_users_project_settings(
        self, auth_client, db, pro_user
    ):
        other = TrackedTarget(
            user_id=pro_user.id,
            name="not yours",
            ecosystem="npm",
            manifest_kind=ManifestKind.PACKAGE_JSON,
            manifest_content="{}",
            content_hash="z" * 64,
        )
        db.add(other)
        await db.flush()

        key = ApiKey(
            user_id=pro_user.id,
            target_id=other.id,
            name="theirs",
            prefix="wo_theirs",
            token_hash="h" * 64,
        )
        db.add(key)
        await db.flush()

        # The page itself is the React shell and is served for any id, which is
        # deliberate: it holds no project data, so there is nothing to leak and
        # nothing to decide before it loads. What refuses is the API behind it.
        shell = await auth_client.get(f"/targets/{other.id}?view=settings")
        assert shell.status_code == 200
        assert "not yours" not in shell.text

        data_request = await auth_client.get(f"/api/internal/projects/{other.id}")
        assert data_request.status_code == 404
        assert "not yours" not in data_request.text

        # Every mutating route, not only the one that reads.
        for path, body in (
            (f"/api/internal/projects/{other.id}/rename", {"name": "hijacked"}),
            (f"/api/internal/projects/{other.id}/keys", {"name": "theirs"}),
            (f"/api/internal/projects/{other.id}/keys/{key.id}/revoke", {}),
            (f"/api/internal/projects/{other.id}/delete", {}),
        ):
            csrf = set_csrf(auth_client)
            response = await auth_client.post(path, json=body, headers={"X-CSRF-Token": csrf})
            assert response.status_code == 404, path

        await db.refresh(other)
        await db.refresh(key)
        assert other.name == "not yours"
        assert key.is_active is True
        assert await db.get(TrackedTarget, other.id) is not None


class TestAlertRoutes:
    async def _seed(self, auth_client, db):
        await seed_mirror(db, LODASH_ADVISORY)
        await create_project(auth_client, filename="package.json", content=MANIFEST)
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

        await sign_in(client, user.email)

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
