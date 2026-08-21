"""Production React entry, immutable assets, rollback, and parity boundary."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from app.config import get_settings
from app.core.types import (
    ActionableReason,
    Ecosystem,
    ManifestKind,
    Reachability,
    Severity,
    Verdict,
)
from app.db import get_db
from app.main import create_app
from app.models import CVEMatch, TrackedTarget, VulnerabilityRecord
from app.security import content_hash
from app.services.auth_service import create_session


@pytest.fixture
async def production_client(db, tmp_path, monkeypatch) -> AsyncIterator[httpx.AsyncClient]:
    """An app wired to representative immutable Vite output.

    The Python CI job intentionally does not depend on Node output from a
    separate job. Docker and frontend CI build the real bundle; this fixture
    exercises the serving contract with the same filenames and markup shape.
    """
    from app.routes import frontend

    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    index = dist / "index.html"
    index.write_text(
        '<!doctype html><html lang="en"><head>'
        '<link rel="stylesheet" href="/assets/index-a1b2c3.css">'
        '<script type="module" src="/assets/index-d4e5f6.js"></script>'
        '</head><body><div id="root"></div></body></html>',
        encoding="utf-8",
    )
    (assets / "index-a1b2c3.css").write_text("body{background:#08080b}", encoding="utf-8")
    (assets / "index-d4e5f6.js").write_text("import('./DashboardPage-f6e5d4.js')", encoding="utf-8")
    (assets / "DashboardPage-f6e5d4.js").write_text("export const dashboard=true", encoding="utf-8")

    monkeypatch.setattr(frontend, "FRONTEND_DIST_DIR", dist)
    monkeypatch.setattr(frontend, "FRONTEND_INDEX", index)
    monkeypatch.setattr(frontend, "FRONTEND_ASSETS_DIR", assets)

    app = create_app(get_settings())

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        follow_redirects=False,
    ) as client:
        yield client

    app.dependency_overrides.clear()


async def attach_session(client, db, user) -> None:
    token = await create_session(db, user)
    await db.flush()
    client.cookies.set(get_settings().session_cookie_name, token)


class TestProductionFrontendServing:
    def test_source_entry_has_a_static_asset_failure_fallback(self):
        entry = (Path(__file__).parents[1] / "frontend" / "index.html").read_text(encoding="utf-8")

        assert "If this message remains, a frontend asset could not be loaded." in entry
        assert "/dashboard/legacy" not in entry
        assert "<script>" not in entry

    async def test_dashboard_direct_navigation_serves_only_the_react_entry(self, production_client):
        response = await production_client.get("/dashboard")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert response.headers["cache-control"] == "private, no-store"
        assert response.headers["vary"] == "Cookie"
        assert '<div id="root"></div>' in response.text
        assert 'src="/assets/index-d4e5f6.js"' in response.text
        assert "All clear" not in response.text
        assert "dashboard.html" not in response.text

    async def test_anonymous_shell_exposes_no_data_and_internal_reads_stay_protected(
        self, production_client
    ):
        shell = await production_client.get("/dashboard")
        dashboard = await production_client.get("/api/internal/dashboard")
        findings = await production_client.get("/api/internal/findings")

        assert shell.status_code == 200
        assert "example.com" not in shell.text
        assert dashboard.status_code == 401
        assert findings.status_code == 401

    async def test_hashed_assets_and_lazy_chunks_are_public_and_immutable(self, production_client):
        main = await production_client.get("/assets/index-d4e5f6.js")
        lazy = await production_client.get("/assets/DashboardPage-f6e5d4.js")
        css = await production_client.get("/assets/index-a1b2c3.css")

        for response in (main, lazy, css):
            assert response.status_code == 200
            assert response.headers["cache-control"] == ("public, max-age=31536000, immutable")

    async def test_missing_assets_and_unknown_routes_never_receive_the_spa_entry(
        self, production_client
    ):
        missing = await production_client.get("/assets/missing.js")
        old_proof = await production_client.get("/app/dashboard")
        unknown = await production_client.get("/not-a-migrated-route")

        assert missing.status_code == 404
        assert old_proof.status_code == 404
        assert unknown.status_code == 404
        assert '<div id="root"></div>' not in missing.text
        assert '<div id="root"></div>' not in unknown.text

    async def test_built_entry_remains_compatible_with_the_strict_csp(self, production_client):
        response = await production_client.get("/dashboard")

        csp = response.headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "connect-src 'self'" in csp
        assert "font-src 'self'" in csp
        assert "unsafe-eval" not in csp
        assert "blob:" not in csp
        assert "script-src *" not in csp
        assert '<script type="module" src=' in response.text
        assert "<script>" not in response.text

    async def test_stale_session_reaches_the_shell_then_is_cleared_by_auth_bootstrap(
        self, production_client
    ):
        production_client.cookies.set(get_settings().session_cookie_name, "stale-session")

        assert (await production_client.get("/dashboard")).status_code == 200
        auth = await production_client.get("/api/internal/auth/me")

        assert auth.status_code == 401
        assert auth.json()["error"]["code"] == "SESSION_EXPIRED"
        assert "weedout_session=" in auth.headers["set-cookie"]
        assert "Max-Age=0" in auth.headers["set-cookie"]
        assert auth.cookies.get("weedout_csrf")

    async def test_sse_response_is_private_and_explicitly_non_buffered(self, user):
        from app.routes.events import events

        response = await events(request=object(), user=user)  # type: ignore[arg-type]

        assert response.media_type == "text/event-stream"
        assert response.headers["cache-control"] == ("private, no-cache, no-store, no-transform")
        assert response.headers["vary"] == "Cookie"
        assert response.headers["x-accel-buffering"] == "no"
        assert response.headers["connection"] == "keep-alive"

    async def test_authenticated_shell_uses_the_unchanged_cookie_api_boundary(
        self, production_client, db, user
    ):
        await attach_session(production_client, db, user)

        shell = await production_client.get("/dashboard")
        auth = await production_client.get("/api/internal/auth/me")
        dashboard = await production_client.get("/api/internal/dashboard")
        findings = await production_client.get("/api/internal/findings")

        assert shell.status_code == 200
        assert auth.status_code == 200
        assert auth.json()["data"]["user"]["id"] == user.id
        assert dashboard.status_code == 200
        assert findings.status_code == 200
        assert auth.cookies.get("weedout_csrf")


class TestLegacyRollback:
    async def test_legacy_route_remains_server_protected(self, production_client):
        response = await production_client.get("/dashboard/legacy")

        assert response.status_code == 303
        assert response.headers["location"] == "/login?next=/dashboard/legacy"

    async def test_authenticated_operator_can_reach_the_legacy_renderer(
        self, production_client, db, user
    ):
        await attach_session(production_client, db, user)

        response = await production_client.get("/dashboard/legacy")

        assert response.status_code == 200
        assert "All clear" in response.text
        assert 'src="/assets/index-d4e5f6.js"' not in response.text


class TestDashboardParity:
    async def test_react_apis_and_legacy_renderer_share_the_same_account_data(
        self, auth_client, db, user
    ):
        project = TrackedTarget(
            user_id=user.id,
            name="parity-checkout",
            ecosystem=Ecosystem.NPM,
            manifest_kind=ManifestKind.PACKAGE_LOCK_JSON,
            manifest_content='{"lockfileVersion": 3}',
            content_hash=content_hash("parity-checkout"),
            dependency_count=17,
        )
        vulnerability = VulnerabilityRecord(
            id="GHSA-phase5-parity",
            cve_ids=["CVE-2026-5555"],
            summary="Phase 5 parity finding",
        )
        db.add_all([project, vulnerability])
        await db.flush()
        db.add(
            CVEMatch(
                target_id=project.id,
                vulnerability_id=vulnerability.id,
                ecosystem=Ecosystem.NPM,
                package_name="phase5-package",
                package_version="1.2.3",
                reachability=Reachability.RUNTIME_DIRECT,
                verdict=Verdict.ACTIONABLE,
                severity=Severity.CRITICAL,
                is_kev=True,
                actionable_reason=ActionableReason.EXPLOITED_IN_WILD,
            )
        )
        await db.flush()

        dashboard = (await auth_client.get("/api/internal/dashboard")).json()["data"]
        findings = (await auth_client.get("/api/internal/findings")).json()["data"]
        legacy = (await auth_client.get("/dashboard/legacy")).text

        assert dashboard["summary"] == {
            "projects": 1,
            "dependencies": 17,
            "open_findings": 1,
            "exploited_findings": 1,
            "critical_findings": 1,
            "filtered_findings": 0,
            "dismissed_findings": 0,
            "resolved_findings": 0,
            "filter_rate_percent": 0,
        }
        assert dashboard["projects"][0]["name"] == "parity-checkout"
        assert findings[0]["identifier"] == "CVE-2026-5555"
        assert findings[0]["project"]["name"] == "parity-checkout"
        for expected in ("parity-checkout", "CVE-2026-5555", "phase5-package", "1.2.3"):
            assert expected in legacy
