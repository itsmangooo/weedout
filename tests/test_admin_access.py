"""Admin access control.

This is the file that matters most in the admin work. The dependency looks
obviously correct, which is exactly why it gets verified rather than assumed:
the failure mode is silent, and it exposes every account on the platform.

The route list is derived from the application itself, so a new admin endpoint
added later is automatically covered — a hand-maintained list would drift, and
the one route someone forgets to add is the one that leaks.
"""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.core.types import Tier
from app.models import AdminAuditLog, User
from app.security import hash_password
from tests.conftest import set_csrf


def admin_routes(app) -> list[tuple[str, str]]:
    """Every (method, path) under /admin that the app actually serves."""
    found: list[tuple[str, str]] = []

    def walk(routes):
        for route in routes:
            path = getattr(route, "path", None)
            if path and str(path).startswith("/admin"):
                for method in getattr(route, "methods", set()) or set():
                    if method in ("GET", "POST"):
                        found.append((method, str(path)))
            for attr in ("routes", "original_router"):
                nested = getattr(route, attr, None)
                if nested is not None:
                    walk(getattr(nested, "routes", nested))

    walk(app.routes)
    return sorted(set(found))


def concrete(path: str, user_id: int = 1, **params) -> str:
    """Fill path parameters so the route is actually reachable.

    Generic rather than a fixed list: a new admin route with a new parameter
    name should surface here as an unfilled placeholder and fail loudly, not be
    quietly skipped by a substitution that does not match.
    """
    filled = path.replace("{user_id}", str(user_id))
    for name, value in params.items():
        filled = filled.replace("{" + name + "}", str(value))
    # Anything left is a parameter this helper does not know how to fill; use a
    # plausible integer so the route is still exercised.
    return re.sub(r"\{[^}]+\}", "1", filled)


@pytest.fixture
async def admin_user(db) -> User:
    record = User(
        email="admin@example.com",
        password_hash=hash_password("correct-horse-battery"),
        tier=Tier.FREE,
        is_admin=True,
    )
    db.add(record)
    await db.flush()
    return record


@pytest.fixture
async def admin_client(client, admin_user):
    csrf = set_csrf(client)
    response = await client.post(
        "/login",
        data={"email": admin_user.email, "password": "correct-horse-battery", "csrf_token": csrf},
    )
    assert response.status_code == 303
    return client


class TestRouteInventory:
    def test_the_inventory_is_not_silently_empty(self, client):
        # If this ever returns nothing, every parametrised test below would
        # vacuously pass while testing nothing at all.
        routes = admin_routes(client._transport.app)
        assert len(routes) >= 6, f"expected the admin routes to be discovered, got {routes}"
        assert all(path.startswith("/admin") for _, path in routes)


class TestNonAdminIsRefused:
    async def test_every_admin_route_returns_403_for_a_regular_user(self, auth_client, db, user):
        """A signed-in non-admin must be refused everywhere under /admin."""
        routes = admin_routes(auth_client._transport.app)
        csrf = set_csrf(auth_client)

        failures = []
        for method, path in routes:
            url = concrete(path, user_id=user.id)
            if method == "GET":
                response = await auth_client.get(url)
            else:
                response = await auth_client.post(url, data={"csrf_token": csrf})

            if response.status_code != 403:
                failures.append(f"{method} {url} -> {response.status_code}")

        assert not failures, "non-admin reached admin routes: " + "; ".join(failures)

    async def test_the_html_403_page_actually_renders(self, auth_client):
        """A browser sends `Accept: text/html` and gets the rendered page.

        Worth asserting separately: the default test client sends `*/*`, which
        takes the JSON branch, so every other test here would still pass while
        the HTML error page raised a 500 — which is exactly what happened once.
        """
        response = await auth_client.get("/admin", headers={"accept": "text/html"})
        assert response.status_code == 403
        assert "Not allowed" in response.text
        assert "Internal Server Error" not in response.text

    async def test_the_html_403_still_renders_the_signed_in_nav(self, auth_client, user):
        response = await auth_client.get("/admin/users", headers={"accept": "text/html"})
        assert response.status_code == 403
        # Rendering the nav requires user attributes after the request's session
        # has been rolled back and closed.
        assert "Sign out" in response.text
        assert 'href="/admin"' not in response.text

    async def test_refusal_is_403_not_a_redirect(self, auth_client, user):
        # A redirect would be indistinguishable from "not signed in" and would
        # send a legitimate user into a login loop.
        response = await auth_client.get("/admin")
        assert response.status_code == 403
        assert "location" not in response.headers

    async def test_refusal_leaks_no_admin_data(self, auth_client, db, pro_user):
        response = await auth_client.get("/admin/users")
        assert response.status_code == 403
        # The body must not contain another user's address.
        assert pro_user.email not in response.text

    async def test_non_admin_cannot_change_another_users_tier(self, auth_client, db, pro_user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/admin/users/{pro_user.id}/tier",
            data={"tier": "free", "csrf_token": csrf},
        )
        assert response.status_code == 403

        await db.refresh(pro_user)
        assert pro_user.tier is Tier.PRO, "the tier must be untouched"

    async def test_non_admin_cannot_suspend_anyone(self, auth_client, db, pro_user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/admin/users/{pro_user.id}/suspend",
            data={"reason": "because", "csrf_token": csrf},
        )
        assert response.status_code == 403

        await db.refresh(pro_user)
        assert pro_user.is_suspended is False

    async def test_a_refused_attempt_writes_no_audit_entry(self, auth_client, db, pro_user):
        csrf = set_csrf(auth_client)
        await auth_client.post(f"/admin/users/{pro_user.id}/suspend", data={"csrf_token": csrf})
        entries = (await db.scalars(select(AdminAuditLog))).all()
        assert entries == []

    async def test_the_admin_nav_link_is_not_rendered_for_regular_users(self, auth_client):
        response = await auth_client.get("/dashboard")
        assert response.status_code == 200
        assert 'href="/admin"' not in response.text


class TestAnonymousIsRedirected:
    async def test_anonymous_visitors_go_to_login(self, client):
        response = await client.get("/admin")
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    async def test_anonymous_post_does_not_act(self, client, db, pro_user):
        csrf = set_csrf(client)
        response = await client.post(
            f"/admin/users/{pro_user.id}/suspend", data={"csrf_token": csrf}
        )
        assert response.status_code in (303, 403)

        await db.refresh(pro_user)
        assert pro_user.is_suspended is False


class TestAdminIsAllowed:
    async def test_admin_reaches_every_get_route(self, admin_client, db, admin_user):
        from app.models import ContactMessage, DocPage

        # Detail routes need a record to resolve, or they 404 for a reason that
        # has nothing to do with access control.
        page = DocPage(slug="fixture-page", title="Fixture", content="# Hi", published=True)
        db.add(page)
        message = ContactMessage(email="fixture@example.com", message="A fixture message.")
        db.add(message)
        await db.flush()

        routes = [(m, p) for m, p in admin_routes(admin_client._transport.app) if m == "GET"]
        failures = []
        for _, path in routes:
            url = concrete(path, user_id=admin_user.id, page_id=page.id, message_id=message.id)
            response = await admin_client.get(url)
            if response.status_code != 200:
                failures.append(f"GET {url} -> {response.status_code}")

        assert not failures, "admin was blocked from: " + "; ".join(failures)

    async def test_admin_sees_the_nav_link(self, admin_client):
        response = await admin_client.get("/dashboard")
        assert 'href="/admin"' in response.text


class TestAdminPromotion:
    async def test_configured_admin_email_is_promoted_on_login(self, client, db, monkeypatch):
        from app.config import get_settings
        from app.services.auth_service import register_user

        settings = get_settings()
        monkeypatch.setattr(settings, "admin_email", "boss@example.com")

        # Signing up as the configured address is itself a first sign-in, so
        # the promotion happens there rather than requiring a second login.
        created = await register_user(db, "boss@example.com", "a-good-long-password")
        assert created.is_admin is True

        created.is_admin = False  # prove the login path promotes too
        await db.flush()

        csrf = set_csrf(client)
        response = await client.post(
            "/login",
            data={
                "email": "boss@example.com",
                "password": "a-good-long-password",
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 303

        await db.refresh(created)
        assert created.is_admin is True

    async def test_promotion_is_recorded_in_the_audit_log(self, client, db, monkeypatch):
        from app.config import get_settings
        from app.services.auth_service import register_user

        monkeypatch.setattr(get_settings(), "admin_email", "boss@example.com")
        await register_user(db, "boss@example.com", "a-good-long-password")

        csrf = set_csrf(client)
        await client.post(
            "/login",
            data={
                "email": "boss@example.com",
                "password": "a-good-long-password",
                "csrf_token": csrf,
            },
        )

        entry = await db.scalar(
            select(AdminAuditLog).where(AdminAuditLog.action == "admin.self_promoted")
        )
        assert entry is not None
        assert entry.target_email == "boss@example.com"

    async def test_other_addresses_are_never_promoted(self, client, db, user, monkeypatch):
        from app.config import get_settings

        monkeypatch.setattr(get_settings(), "admin_email", "boss@example.com")

        csrf = set_csrf(client)
        await client.post(
            "/login",
            data={
                "email": user.email,
                "password": "correct-horse-battery",
                "csrf_token": csrf,
            },
        )
        await db.refresh(user)
        assert user.is_admin is False

    async def test_no_promotion_when_admin_email_is_unset(self, client, db, user, monkeypatch):
        from app.config import get_settings

        monkeypatch.setattr(get_settings(), "admin_email", None)

        csrf = set_csrf(client)
        await client.post(
            "/login",
            data={
                "email": user.email,
                "password": "correct-horse-battery",
                "csrf_token": csrf,
            },
        )
        await db.refresh(user)
        assert user.is_admin is False
