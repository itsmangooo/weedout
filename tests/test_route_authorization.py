"""Every route is guarded, and the guard is the right one.

Written as an inventory rather than as a list of hand-picked cases, because the
failure this guards against is *a new route added without auth* — and a test
that only checks the routes someone remembered to add it to would never catch
that. A new endpoint that is neither in the public allowlist nor behind a
dependency fails here the moment it is registered.

This is the re-verification the review asked for: the rename, the CLI, the
local CVE mirror and the Dodo migration all added or moved routes, and none of
them should have loosened anything.
"""

from __future__ import annotations

import pytest
from fastapi.routing import APIRoute

from app.main import create_app

#: Routes an anonymous stranger is *supposed* to reach, with why.
#:
#: Anything not listed here must carry an auth dependency. Adding to this list
#: is a deliberate act, which is the point.
PUBLIC_ROUTES: dict[str, str] = {
    "/": "landing page",
    "/pricing": "public pricing",
    "/healthz": "liveness probe",
    "/readyz": "readiness probe",
    "/login": "sign-in form and submission",
    "/login/2fa": (
        "second step of signing in; the caller has no session yet by definition. "
        "Guarded instead by a short-lived signed challenge cookie naming the "
        "account, which is checked before any code is even looked at."
    ),
    "/signup": "sign-up form and submission",
    "/logout": "ends a session; harmless without one",
    "/forgot-password": "reset request; identical response either way",
    "/reset-password": "reset completion; the token is the credential",
    "/docs": "public documentation index",
    "/docs/{slug}": "public documentation page",
    "/webhooks/dodo": "authenticated by HMAC signature, not by session",
}

#: Routes authenticated by bearer key rather than by session cookie. These
#: correctly have no CSRF token — no cookie is read, so no browser can be
#: tricked into making the call.
API_KEY_ROUTES = {"/api/v1/scan"}


def build_app():
    return create_app()


def all_routes(app) -> list[APIRoute]:
    """Every APIRoute the app serves, however deeply nested.

    FastAPI wraps an included router in a `_IncludedRouter` whose children hang
    off `original_router`, so a walk that only follows `.routes` finds nothing
    at all. `test_the_inventory_is_not_silently_empty` exists because that
    failure mode makes every other assertion here pass vacuously.
    """
    found: list[APIRoute] = []
    seen: set[int] = set()

    def walk(routes):
        for route in routes:
            if id(route) in seen:
                continue
            seen.add(id(route))

            if isinstance(route, APIRoute):
                found.append(route)

            for attr in ("routes", "original_router"):
                nested = getattr(route, attr, None)
                if nested is None:
                    continue
                walk(getattr(nested, "routes", nested))

    walk(app.routes)
    return found


def dependency_names(route: APIRoute) -> set[str]:
    """Every dependency callable reachable from this route, at any depth.

    Router-level dependencies (how `/admin` is protected) and nested ones (how
    `CurrentUser` pulls in `get_current_user`) both have to be visible here, or
    the audit would report a guarded route as unguarded.
    """
    names: set[str] = set()

    def walk(dependant):
        for sub in dependant.dependencies:
            if sub.call is not None:
                names.add(getattr(sub.call, "__name__", ""))
            walk(sub)

    walk(route.dependant)
    return names


def classify(route: APIRoute) -> str:
    names = dependency_names(route)
    if "require_admin" in names:
        return "admin"
    if "require_api_key" in names:
        return "api_key"
    if "require_user" in names:
        return "user"
    if "get_current_user" in names:
        return "optional"
    return "none"


@pytest.fixture(scope="module")
def routes():
    return all_routes(build_app())


class TestInventory:
    def test_the_inventory_is_not_silently_empty(self, routes):
        """If route discovery breaks, every assertion below passes vacuously."""
        assert len(routes) > 25

    def test_every_route_is_either_public_by_design_or_guarded(self, routes):
        unguarded = [
            (sorted(r.methods), r.path)
            for r in routes
            if classify(r) == "none" and r.path not in PUBLIC_ROUTES
        ]
        assert unguarded == [], f"routes with no auth dependency: {unguarded}"

    def test_the_public_list_has_no_stale_entries(self, routes):
        """A path left in the allowlist after being removed or renamed is an
        exemption waiting to apply to something it was never reviewed for."""
        served = {r.path for r in routes}
        stale = sorted(set(PUBLIC_ROUTES) - served)
        assert stale == [], f"allowlisted paths that no longer exist: {stale}"


class TestAdminSurface:
    def test_every_admin_route_requires_admin(self, routes):
        wrong = [
            (sorted(r.methods), r.path, classify(r))
            for r in routes
            if r.path.startswith("/admin") and classify(r) != "admin"
        ]
        assert wrong == [], f"admin routes not behind require_admin: {wrong}"

    def test_there_are_admin_routes_to_check(self, routes):
        assert any(r.path.startswith("/admin") for r in routes)


class TestApiSurface:
    def test_every_api_route_requires_a_key(self, routes):
        wrong = [
            (sorted(r.methods), r.path, classify(r))
            for r in routes
            if r.path.startswith("/api/") and classify(r) != "api_key"
        ]
        assert wrong == [], f"API routes not behind require_api_key: {wrong}"

    def test_the_api_surface_is_exactly_what_is_expected(self, routes):
        """The scan API is deliberately one endpoint wide. A second one
        appearing should be a decision, not a surprise."""
        served = {r.path for r in routes if r.path.startswith("/api/")}
        assert served == API_KEY_ROUTES

    def test_api_routes_do_not_use_session_auth(self, routes):
        """Mixing the two would reintroduce exactly the ambient-credential
        problem that lets a logged-in browser be used to make API calls."""
        for route in routes:
            if route.path in API_KEY_ROUTES:
                names = dependency_names(route)
                assert "require_user" not in names
                assert "get_current_user" not in names


class TestCsrfCoverage:
    def test_every_session_authenticated_mutation_has_csrf(self, routes):
        """Cookie-authenticated POSTs are the ones a cross-site form can
        forge. Bearer-authenticated ones cannot be — no cookie is read."""
        missing = []
        for route in routes:
            if "POST" not in route.methods:
                continue
            if route.path in API_KEY_ROUTES or route.path in PUBLIC_ROUTES:
                continue
            if "verify_csrf" not in dependency_names(route):
                missing.append((sorted(route.methods), route.path))

        assert missing == [], f"POST routes without CSRF protection: {missing}"

    def test_the_public_post_routes_still_carry_csrf(self, routes):
        """Login, signup, logout and the reset forms are public but are still
        browser form posts, so they are protected too — being on the public
        allowlist exempts them from *authentication*, not from CSRF."""
        expected = {"/login", "/signup", "/logout", "/forgot-password", "/reset-password"}
        for route in routes:
            if route.path in expected and "POST" in route.methods:
                assert "verify_csrf" in dependency_names(route), route.path

    def test_the_webhook_is_deliberately_exempt(self, routes):
        """Dodo cannot send a CSRF token. Its authenticity comes from the HMAC
        signature over the raw body, which is verified before anything else."""
        webhook = [r for r in routes if r.path == "/webhooks/dodo"]
        assert webhook, "the webhook route should exist"
        assert "verify_csrf" not in dependency_names(webhook[0])
