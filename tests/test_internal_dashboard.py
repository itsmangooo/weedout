"""Read-only React dashboard contract and ownership boundary."""

from __future__ import annotations

from datetime import UTC, datetime

from app.core.types import Ecosystem, ManifestKind
from app.models import TrackedTarget
from app.security import content_hash


def target_for(user, name: str, dependencies: int = 0, **values) -> TrackedTarget:
    return TrackedTarget(
        user_id=user.id,
        name=name,
        ecosystem=Ecosystem.NPM,
        manifest_kind=ManifestKind.PACKAGE_JSON,
        manifest_content="{}",
        content_hash=content_hash(name),
        dependency_count=dependencies,
        **values,
    )


class TestInternalDashboard:
    async def test_anonymous_access_is_a_json_401_not_a_login_redirect(self, client):
        response = await client.get(
            "/api/internal/dashboard",
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

    async def test_authenticated_user_receives_the_empty_dashboard(self, auth_client):
        response = await auth_client.get("/api/internal/dashboard")

        assert response.status_code == 200
        assert response.headers["cache-control"] == "private, no-store"
        assert response.headers["vary"] == "Cookie"
        assert response.json() == {
            "data": {
                "summary": {
                    "projects": 0,
                    "dependencies": 0,
                    "open_findings": 0,
                    "exploited_findings": 0,
                    "critical_findings": 0,
                    "filtered_findings": 0,
                    "dismissed_findings": 0,
                    "resolved_findings": 0,
                    "filter_rate_percent": 0,
                },
                "projects": [],
            }
        }

    async def test_dashboard_is_scoped_to_the_authenticated_owner(
        self, auth_client, db, user, pro_user
    ):
        mine = target_for(user, "mine", dependencies=7)
        theirs = target_for(pro_user, "not-mine", dependencies=900)
        db.add_all([mine, theirs])
        await db.flush()

        body = (await auth_client.get("/api/internal/dashboard")).json()["data"]

        assert body["summary"]["projects"] == 1
        assert body["summary"]["dependencies"] == 7
        assert [project["id"] for project in body["projects"]] == [mine.id]
        assert theirs.id not in {project["id"] for project in body["projects"]}
        assert "not-mine" not in str(body)

    async def test_project_response_is_an_explicit_safe_read_model(self, auth_client, db, user):
        checked_at = datetime(2026, 8, 20, 18, 30, tzinfo=UTC)
        project = target_for(
            user,
            "checkout-api",
            dependencies=12,
            is_active=False,
            last_scanned_at=checked_at,
            last_scan_error="provider timeout with internal details",
        )
        db.add(project)
        await db.flush()

        response = await auth_client.get("/api/internal/dashboard")

        assert response.status_code == 200
        body = response.json()["data"]
        assert set(body) == {"summary", "projects"}
        assert set(body["summary"]) == {
            "projects",
            "dependencies",
            "open_findings",
            "exploited_findings",
            "critical_findings",
            "filtered_findings",
            "dismissed_findings",
            "resolved_findings",
            "filter_rate_percent",
        }
        assert body["projects"] == [
            {
                "id": project.id,
                "name": "checkout-api",
                "ecosystem": "npm",
                "manifest_kind": "package.json",
                "dependency_count": 12,
                "is_active": False,
                "has_manifest": True,
                "last_scanned_at": "2026-08-20T18:30:00Z",
                "last_scan_failed": True,
                "findings": {"open": 0, "exploited": 0, "filtered": 0},
            }
        ]
        serialized = str(body)
        assert "provider timeout" not in serialized
        assert "manifest_content" not in serialized
        assert "content_hash" not in serialized
        assert "user_id" not in serialized
