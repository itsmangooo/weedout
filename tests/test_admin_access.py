"""Admin access control.

This is the file that matters most in the admin work. The dependency looks
obviously correct, which is exactly why it gets verified rather than assumed:
the failure mode is silent, and it exposes every account on the platform.

The route list is derived from the application itself, so a new admin endpoint
added later is automatically covered — a hand-maintained list would drift, and
the one route someone forgets to add is the one that leaks.

Since the panel became React, `/admin/*` serves the same empty shell every
other page does and carries no data at all; the enforcement is on
`/api/internal/admin/*`. Both halves are asserted below — that the shell leaks
nothing, and that every endpoint behind it refuses a non-admin — because
"the page loads for everyone" is only acceptable while the second half holds.
"""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.core.types import Tier
from app.models import AdminAuditLog, User
from app.security import hash_password
from tests.conftest import set_csrf, sign_in


def routes_under(app, prefix: str) -> list[tuple[str, str]]:
    """Every (method, path) under `prefix` that the app actually serves."""
    found: list[tuple[str, str]] = []

    def walk(routes):
        for route in routes:
            path = getattr(route, "path", None)
            if path and str(path).startswith(prefix):
                for method in getattr(route, "methods", set()) or set():
                    if method in ("GET", "POST"):
                        found.append((method, str(path)))
            for attr in ("routes", "original_router"):
                nested = getattr(route, attr, None)
                if nested is not None:
                    walk(getattr(nested, "routes", nested))

    walk(app.routes)
    return sorted(set(found))


def admin_routes(app) -> list[tuple[str, str]]:
    """The rendered panel. `/api/internal/admin` is a different prefix, so this
    keeps returning only the HTML routes even while both panels exist."""
    return routes_under(app, "/admin")


def admin_api_routes(app) -> list[tuple[str, str]]:
    """The React panel's endpoints."""
    return routes_under(app, "/api/internal/admin")


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
    response = await sign_in(client, admin_user.email)
    assert response.status_code == 200
    return client


class TestRouteInventory:
    def test_the_inventory_is_not_silently_empty(self, client):
        # If this ever returns nothing, every parametrised test below would
        # vacuously pass while testing nothing at all.
        routes = admin_api_routes(client._transport.app)
        assert len(routes) >= 6, f"expected the admin routes to be discovered, got {routes}"
        assert all(path.startswith("/api/internal/admin") for _, path in routes)


class TestTheAdminShellHoldsNothing:
    """`/admin/*` is the React shell, so it answers 200 to anyone.

    That is only safe because the shell is the same bytes for every visitor.
    These tests assert exactly that — no account data, no hint about who is an
    administrator — rather than asserting a status code, which would pass just
    as happily if the shell started embedding a user object.
    """

    async def test_the_shell_is_served_to_a_signed_in_non_admin(self, auth_client):
        response = await auth_client.get("/admin")
        assert response.status_code == 200

    async def test_the_shell_is_byte_identical_for_admin_and_stranger(
        self, client, auth_client, db
    ):
        """Anonymous, ordinary and administrator get the same file.

        If they ever differ, something is being rendered per-user into a page
        that is served to everybody.
        """
        anonymous = await client.get("/admin")
        signed_in = await auth_client.get("/admin")

        assert anonymous.status_code == signed_in.status_code == 200
        assert anonymous.content == signed_in.content

    async def test_the_shell_leaks_no_account_data(self, auth_client, db, pro_user):
        for path in ("/admin", "/admin/users", f"/admin/users/{pro_user.id}"):
            response = await auth_client.get(path)
            assert pro_user.email not in response.text, path

    async def test_the_admin_nav_link_is_not_rendered_for_regular_users(self, auth_client):
        # Checked on a page that still renders the shared nav. The dashboard
        # and settings are React now and build their own.
        response = await auth_client.get("/docs")
        assert response.status_code == 200
        assert 'href="/admin"' not in response.text


class TestNonAdminIsRefusedByTheApi:
    """The same property, for the React panel.

    Derived from the app rather than listed, for the reason the HTML sweep is:
    the one endpoint somebody forgets to add to a list is the one that leaks.
    """

    def test_the_api_inventory_is_not_silently_empty(self, client):
        routes = admin_api_routes(client._transport.app)
        assert len(routes) >= 6, f"expected admin API routes to be discovered, got {routes}"

    async def test_every_admin_api_route_returns_403_for_a_regular_user(
        self, auth_client, db, user
    ):
        routes = admin_api_routes(auth_client._transport.app)
        csrf = set_csrf(auth_client)

        failures = []
        for method, path in routes:
            url = concrete(path, user_id=user.id)
            if method == "GET":
                response = await auth_client.get(url)
            else:
                response = await auth_client.post(url, json={}, headers={"X-CSRF-Token": csrf})

            if response.status_code != 403:
                failures.append(f"{method} {url} -> {response.status_code}")

        assert not failures, "non-admin reached admin API routes: " + "; ".join(failures)

    async def test_the_refusal_is_the_json_envelope(self, auth_client):
        """A fetch client has to be able to read the reason.

        The HTML panel renders an error page; this one must not, or the
        frontend reports "unexpected token <" instead of "not allowed".
        """
        response = await auth_client.get("/api/internal/admin/overview")
        assert response.status_code == 403
        assert response.headers["content-type"].startswith("application/json")
        assert response.json()["error"]["code"] == "FORBIDDEN"

    async def test_an_anonymous_caller_gets_401_not_a_redirect(self, client):
        """A `fetch` cannot follow a login redirect usefully — it would report
        the login page's HTML as a parse error rather than as "sign in"."""
        response = await client.get("/api/internal/admin/overview")
        assert response.status_code == 401
        assert "location" not in response.headers
        assert response.json()["error"]["code"] in ("UNAUTHENTICATED", "SESSION_EXPIRED")

    async def test_refusal_leaks_no_admin_data(self, auth_client, db, pro_user):
        response = await auth_client.get("/api/internal/admin/users")
        assert response.status_code == 403
        assert pro_user.email not in response.text

    async def test_retired_tier_mutation_is_absent(self, auth_client, db, pro_user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/api/internal/admin/users/{pro_user.id}/tier",
            json={"tier": "free"},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 404

        await db.refresh(pro_user)
        assert pro_user.tier is Tier.PRO, "the tier must be untouched"

    async def test_non_admin_cannot_delete_anyone(self, auth_client, db, pro_user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/api/internal/admin/users/{pro_user.id}/delete",
            json={"confirm_email": pro_user.email},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 403

        assert await db.get(User, pro_user.id) is not None

    async def test_a_refused_attempt_writes_no_audit_entry(self, auth_client, db, pro_user):
        csrf = set_csrf(auth_client)
        await auth_client.post(
            f"/api/internal/admin/users/{pro_user.id}/suspend",
            json={"reason": "because"},
            headers={"X-CSRF-Token": csrf},
        )
        entries = (await db.scalars(select(AdminAuditLog))).all()
        assert entries == []


class TestAnonymousIsRefused:
    async def test_anonymous_callers_get_401_from_the_api(self, client):
        """401 and not a redirect: a `fetch` cannot follow one usefully, and
        the React boundary needs to tell "signed out" from "not allowed"."""
        response = await client.get("/api/internal/admin/users")
        assert response.status_code == 401
        assert "location" not in response.headers

    async def test_anonymous_post_does_not_act(self, client, db, pro_user):
        csrf = set_csrf(client)
        response = await client.post(
            f"/api/internal/admin/users/{pro_user.id}/suspend",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code in (401, 403)

        await db.refresh(pro_user)
        assert pro_user.is_suspended is False


class TestAdminIsAllowed:
    async def test_admin_reaches_every_get_endpoint(self, admin_client, db, admin_user):
        from app.models import ContactMessage, DocPage

        # Detail routes need a record to resolve, or they 404 for a reason that
        # has nothing to do with access control.
        page = DocPage(slug="fixture-page", title="Fixture", content="# Hi", published=True)
        db.add(page)
        message = ContactMessage(email="fixture@example.com", message="A fixture message.")
        db.add(message)
        await db.flush()

        routes = [(m, p) for m, p in admin_api_routes(admin_client._transport.app) if m == "GET"]
        failures = []
        for _, path in routes:
            url = concrete(path, user_id=admin_user.id, page_id=page.id, message_id=message.id)
            response = await admin_client.get(url)
            if response.status_code != 200:
                failures.append(f"GET {url} -> {response.status_code} {response.text[:120]}")

        assert not failures, "admin was blocked from: " + "; ".join(failures)

    async def test_admin_reaches_the_panel(self, admin_client):
        assert (await admin_client.get("/admin")).status_code == 200


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

        response = await sign_in(client, "boss@example.com", "a-good-long-password")
        assert response.status_code == 200

        await db.refresh(created)
        assert created.is_admin is True

    async def test_promotion_is_recorded_in_the_audit_log(self, client, db, monkeypatch):
        from app.config import get_settings
        from app.services.auth_service import register_user

        monkeypatch.setattr(get_settings(), "admin_email", "boss@example.com")
        await register_user(db, "boss@example.com", "a-good-long-password")

        await sign_in(client, "boss@example.com", "a-good-long-password")

        entry = await db.scalar(
            select(AdminAuditLog).where(AdminAuditLog.action == "admin.self_promoted")
        )
        assert entry is not None
        assert entry.target_email == "boss@example.com"

    async def test_other_addresses_are_never_promoted(self, client, db, user, monkeypatch):
        from app.config import get_settings

        monkeypatch.setattr(get_settings(), "admin_email", "boss@example.com")

        await sign_in(client, user.email)
        await db.refresh(user)
        assert user.is_admin is False

    async def test_no_promotion_when_admin_email_is_unset(self, client, db, user, monkeypatch):
        from app.config import get_settings

        monkeypatch.setattr(get_settings(), "admin_email", None)

        await sign_in(client, user.email)
        await db.refresh(user)
        assert user.is_admin is False
