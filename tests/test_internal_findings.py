"""Read-only internal finding contract, ownership, and input bounds."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.types import (
    ActionableReason,
    AlertStatus,
    Ecosystem,
    ManifestKind,
    Reachability,
    Severity,
    SuppressionReason,
    Verdict,
)
from app.models import CVEMatch, TrackedTarget, VulnerabilityRecord
from app.security import content_hash
from app.services.finding_service import MAX_FINDING_LIMIT
from tests.factories import attach_manifest


def project_for(owner, name: str) -> TrackedTarget:
    return TrackedTarget(
        user_id=owner.id,
        name=name,
        ecosystem=Ecosystem.NPM,
        manifest_kind=ManifestKind.PACKAGE_LOCK_JSON,
        manifest_content='{"lockfileVersion": 3}',
        content_hash=content_hash(name),
    )


async def add_finding(
    db,
    target: TrackedTarget,
    identifier: str,
    *,
    package_name: str = "lodash",
    version: str = "4.17.15",
    severity: Severity = Severity.HIGH,
    is_exploited: bool = False,
    reachability: Reachability = Reachability.RUNTIME_DIRECT,
    verdict: Verdict = Verdict.ACTIONABLE,
    status: AlertStatus | None = None,
    detected_at: datetime | None = None,
) -> CVEMatch:
    vulnerability_id = f"OSV-{identifier}"
    vulnerability = VulnerabilityRecord(
        id=vulnerability_id,
        cve_ids=[identifier] if identifier.startswith("CVE-") else [],
        summary=f"Finding for {package_name}",
    )
    db.add(vulnerability)
    await db.flush()

    # `project_for` builds the target synchronously, so the manifest it needs
    # is attached here — idempotently, since several findings share a project.
    manifest = await attach_manifest(db, target)

    match = CVEMatch(
        target_id=target.id,
        manifest_id=manifest.id,
        vulnerability_id=vulnerability_id,
        ecosystem=Ecosystem.NPM,
        package_name=package_name,
        package_version=version,
        reachability=reachability,
        verdict=verdict,
        severity=severity,
        is_kev=is_exploited,
        actionable_reason=(
            ActionableReason.EXPLOITED_IN_WILD if verdict is Verdict.ACTIONABLE else None
        ),
        suppression_reason=(
            SuppressionReason.BELOW_SEVERITY_THRESHOLD if verdict is Verdict.SUPPRESSED else None
        ),
        status=status
        or (AlertStatus.FILTERED if verdict is Verdict.SUPPRESSED else AlertStatus.OPEN),
        first_seen_at=detected_at or datetime(2026, 8, 20, 18, 30, tzinfo=UTC),
    )
    db.add(match)
    await db.flush()
    return match


class TestInternalFindingsAuthentication:
    async def test_anonymous_request_is_a_json_401(self, client):
        response = await client.get(
            "/api/internal/findings",
            headers={"Accept": "text/html"},
        )

        assert response.status_code == 401
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["cache-control"] == "private, no-store"
        assert response.headers["vary"] == "Cookie"
        assert response.json() == {
            "error": {
                "code": "UNAUTHENTICATED",
                "message": "Sign in to continue.",
            }
        }
        assert "location" not in response.headers

    async def test_stale_session_is_reported_without_a_redirect(self, client):
        client.cookies.set("weedout_session", "stale-session-token")

        response = await client.get("/api/internal/findings")

        assert response.status_code == 401
        assert response.json() == {
            "error": {
                "code": "SESSION_EXPIRED",
                "message": "Your session has expired. Sign in again.",
            }
        }
        assert "location" not in response.headers


class TestInternalFindingReads:
    async def test_empty_state_has_stable_metadata(self, auth_client):
        response = await auth_client.get("/api/internal/findings")

        assert response.status_code == 200
        assert response.headers["cache-control"] == "private, no-store"
        assert response.headers["vary"] == "Cookie"
        assert response.json() == {
            "data": [],
            "meta": {"show": "open", "limit": 25, "count": 0, "history_days": None},
        }

    async def test_authenticated_results_are_scoped_to_the_owner(
        self, auth_client, db, user, pro_user
    ):
        mine = project_for(user, "mine")
        theirs = project_for(pro_user, "theirs")
        db.add_all([mine, theirs])
        await db.flush()
        own_match = await add_finding(db, mine, "CVE-2026-1001")
        await add_finding(db, theirs, "CVE-2026-9001", package_name="secret-package")

        body = (await auth_client.get("/api/internal/findings")).json()

        assert [finding["id"] for finding in body["data"]] == [own_match.id]
        assert body["meta"]["count"] == 1
        assert "theirs" not in str(body)
        assert "secret-package" not in str(body)

    async def test_user_cannot_see_another_users_findings(self, auth_client, db, pro_user):
        theirs = project_for(pro_user, "private-project")
        db.add(theirs)
        await db.flush()
        await add_finding(db, theirs, "CVE-2026-9002")

        response = await auth_client.get("/api/internal/findings?show=open&limit=25")

        assert response.json()["data"] == []
        assert response.json()["meta"]["count"] == 0

    async def test_show_open_excludes_filtered_dismissed_and_resolved(self, auth_client, db, user):
        project = project_for(user, "filters")
        db.add(project)
        await db.flush()
        open_match = await add_finding(db, project, "CVE-2026-2001")
        await add_finding(
            db,
            project,
            "CVE-2026-2002",
            verdict=Verdict.SUPPRESSED,
        )
        await add_finding(
            db,
            project,
            "CVE-2026-2003",
            status=AlertStatus.DISMISSED,
        )
        await add_finding(
            db,
            project,
            "CVE-2026-2004",
            status=AlertStatus.RESOLVED,
        )

        body = (await auth_client.get("/api/internal/findings?show=open")).json()

        assert [finding["id"] for finding in body["data"]] == [open_match.id]
        assert body["meta"] == {"show": "open", "limit": 25, "count": 1, "history_days": None}

    async def test_supported_filtered_view_reuses_the_same_read_contract(
        self, auth_client, db, user
    ):
        project = project_for(user, "filtered")
        db.add(project)
        await db.flush()
        filtered = await add_finding(
            db,
            project,
            "CVE-2026-3001",
            verdict=Verdict.SUPPRESSED,
        )

        body = (await auth_client.get("/api/internal/findings?show=filtered")).json()

        assert [finding["id"] for finding in body["data"]] == [filtered.id]
        assert body["meta"]["show"] == "filtered"

    async def test_limit_is_validated_and_capped(self, auth_client, db, user):
        project = project_for(user, "limits")
        db.add(project)
        await db.flush()
        for number in range(3):
            await add_finding(
                db,
                project,
                f"CVE-2026-40{number:02d}",
                detected_at=datetime(2026, 8, 20, tzinfo=UTC) + timedelta(minutes=number),
            )

        limited = (await auth_client.get("/api/internal/findings?limit=2")).json()
        capped = (await auth_client.get("/api/internal/findings?limit=9999")).json()
        invalid = await auth_client.get("/api/internal/findings?limit=0")

        assert limited["meta"] == {"show": "open", "limit": 2, "count": 2, "history_days": None}
        assert len(limited["data"]) == 2
        assert capped["meta"] == {
            "show": "open",
            "limit": MAX_FINDING_LIMIT,
            "count": 3,
            "history_days": None,
        }
        assert invalid.status_code == 422
        assert invalid.headers["cache-control"] == "private, no-store"
        assert invalid.json()["error"]["code"] == "VALIDATION_ERROR"

    async def test_unsupported_show_is_rejected(self, auth_client):
        response = await auth_client.get("/api/internal/findings?show=everything")

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"

    async def test_response_is_an_explicit_safe_read_model(self, auth_client, db, user):
        project = project_for(user, "checkout-api")
        project.repo_url = "https://example.com/private/repository"
        project.policy_file = "secret policy content"
        db.add(project)
        await db.flush()
        match = await add_finding(
            db,
            project,
            "CVE-2026-5001",
            package_name="minimist",
            version="1.2.5",
            severity=Severity.CRITICAL,
            is_exploited=True,
            reachability=Reachability.RUNTIME_TRANSITIVE,
        )

        response = await auth_client.get("/api/internal/findings")

        assert response.status_code == 200
        finding = response.json()["data"][0]
        assert finding == {
            "id": match.id,
            "project": {"id": project.id, "name": "checkout-api"},
            "identifier": "CVE-2026-5001",
            "package_name": "minimist",
            "installed_version": "1.2.5",
            "severity": "critical",
            "is_exploited": True,
            "dependency_relationship": "runtime_transitive",
            "reachability": "unknown",
            "reachability_evidence": [],
            "status": "open",
            "detected_at": "2026-08-20T18:30:00Z",
        }
        assert set(finding) == {
            "id",
            "project",
            "identifier",
            "package_name",
            "installed_version",
            "severity",
            "is_exploited",
            "dependency_relationship",
            "reachability",
            "reachability_evidence",
            "status",
            "detected_at",
        }
        serialized = str(response.json())
        for forbidden in (
            "user_id",
            "target_id",
            "manifest_content",
            "content_hash",
            "repo_url",
            "policy_file",
            "vulnerability_id",
            "affected",
            "secret policy content",
        ):
            assert forbidden not in serialized


class TestTheRetentionWindow:
    """Archived findings use the single Free plan's 365-day window."""

    async def _archive(self, db, owner, *, age_days: int, status: AlertStatus):
        from app.models import utcnow

        target = project_for(owner, f"archive-{age_days}-{status}")
        db.add(target)
        await db.flush()

        match = await add_finding(
            db,
            target,
            f"CVE-2026-{age_days:04d}",
            status=status,
            verdict=Verdict.ACTIONABLE,
        )
        stamped = utcnow() - timedelta(days=age_days)
        if status is AlertStatus.RESOLVED:
            match.resolved_at = stamped
        else:
            match.dismissed_at = stamped
        await db.flush()
        return match

    async def _ids(self, client, show: str) -> list[int]:
        response = await client.get(f"/api/internal/findings?show={show}")
        assert response.status_code == 200
        return [finding["id"] for finding in response.json()["data"]]

    async def test_a_free_account_sees_the_full_year(self, auth_client, db, user):
        recent = await self._archive(db, user, age_days=3, status=AlertStatus.RESOLVED)
        older = await self._archive(db, user, age_days=90, status=AlertStatus.RESOLVED)
        await db.commit()

        assert sorted(await self._ids(auth_client, "resolved")) == sorted([recent.id, older.id])

    async def test_a_pro_account_sees_the_same_finding(self, pro_client, db, pro_user):
        """The negative above is only a plan limit if Pro reaches further."""
        recent = await self._archive(db, pro_user, age_days=3, status=AlertStatus.RESOLVED)
        older = await self._archive(db, pro_user, age_days=90, status=AlertStatus.RESOLVED)
        await db.commit()

        assert sorted(await self._ids(pro_client, "resolved")) == sorted([recent.id, older.id])

    async def test_pro_still_ends_at_a_year(self, pro_client, db, pro_user):
        """365 is what the plan table says, so 365 is what is enforced. The
        bullet used to say 'full', which was the table and the pricing page
        disagreeing."""
        await self._archive(db, pro_user, age_days=400, status=AlertStatus.RESOLVED)
        await db.commit()

        assert await self._ids(pro_client, "resolved") == []

    async def test_dismissed_findings_share_the_year_window(self, auth_client, db, user):
        recent = await self._archive(db, user, age_days=3, status=AlertStatus.DISMISSED)
        older = await self._archive(db, user, age_days=90, status=AlertStatus.DISMISSED)
        await db.commit()

        assert sorted(await self._ids(auth_client, "dismissed")) == sorted([recent.id, older.id])

    async def test_open_findings_are_never_trimmed_by_plan(self, auth_client, db, user):
        """The line that matters most here. An open finding is a live
        vulnerability, and putting one behind a paywall because it was found a
        year ago would be indefensible for a security product.
        """
        target = project_for(user, "long-standing")
        db.add(target)
        await db.flush()
        ancient = await add_finding(
            db,
            target,
            "CVE-2024-0001",
            detected_at=datetime(2024, 1, 1, tzinfo=UTC),
        )
        await db.commit()

        assert await self._ids(auth_client, "open") == [ancient.id]

    async def test_filtered_findings_are_never_trimmed_either(self, auth_client, db, user):
        """'What am I not being told about?' has to keep having an answer."""
        target = project_for(user, "suppressed-long-ago")
        db.add(target)
        await db.flush()
        old = await add_finding(
            db,
            target,
            "CVE-2024-0002",
            verdict=Verdict.SUPPRESSED,
            detected_at=datetime(2024, 1, 1, tzinfo=UTC),
        )
        await db.commit()

        assert await self._ids(auth_client, "filtered") == [old.id]

    async def test_free_reports_its_window(self, auth_client):
        """An archive that stops 30 days back reads as lost data unless the
        page says otherwise, so the number travels with the response.

        Split from the Pro case below rather than asserted together: both
        clients are built on the same session, so signing in as one replaces
        the other.
        """
        body = (await auth_client.get("/api/internal/findings?show=resolved")).json()

        assert body["meta"]["history_days"] == 365

    async def test_pro_reports_its_own(self, pro_client):
        body = (await pro_client.get("/api/internal/findings?show=resolved")).json()

        assert body["meta"]["history_days"] == 365

    async def test_the_present_tense_tabs_report_no_window(self, auth_client):
        for show in ("open", "filtered"):
            body = (await auth_client.get(f"/api/internal/findings?show={show}")).json()
            assert body["meta"]["history_days"] is None, show

    async def test_an_undated_archived_finding_is_kept(self, auth_client, db, user):
        """Both timestamps are written alongside the status today, so this
        should not arise. If it ever does, the filter must fail towards showing
        history rather than deleting it.
        """
        target = project_for(user, "undated")
        db.add(target)
        await db.flush()
        match = await add_finding(db, target, "CVE-2026-9999", status=AlertStatus.RESOLVED)
        match.resolved_at = None
        await db.commit()

        assert await self._ids(auth_client, "resolved") == [match.id]
