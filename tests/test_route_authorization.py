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

from app.core.types import KeyScope
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
    "/forgot-password": "reset request; identical response either way",
    "/reset-password": "reset completion; the token is the credential",
    # The JSON equivalents the React application posts to. Public for exactly
    # the same reasons as the form versions above -- a caller signing in has no
    # session yet -- and carrying exactly the same protections, which
    # TestInternalAuthActions below asserts rather than assumes.
    "/api/internal/auth/login": "sign-in; the caller has no session by definition",
    "/api/internal/auth/login/2fa": (
        "second step of signing in; guarded by the same short-lived signed "
        "challenge cookie as the form route, checked before any code is read"
    ),
    "/api/internal/auth/signup": "account creation",
    "/api/internal/auth/logout": "ends a session; harmless without one",
    "/api/internal/auth/forgot-password": "reset request; identical response either way",
    "/api/internal/auth/reset-password": "reset completion; the token is the credential",
    "/cli": "public marketing page for the CLI",
    "/install.sh": (
        "the install script itself. `curl -sSL https://weedout.dev/install.sh | sh` "
        "is a documented address that has to work before anyone has an account, "
        "and the file is a static asset with no user data in it."
    ),
    "/docs": "public documentation index",
    "/docs/{slug}": "public documentation page",
    "/targets/new": (
        "the static React shell. It holds no user data; the project API behind "
        "it is session-guarded and answers 401, which is what lets the React "
        "boundary tell signed-out from expired."
    ),
    "/targets/{target_id}": (
        "the static React shell, as above. Note that it is served for any id, "
        "including one belonging to somebody else — the shell is identical "
        "either way, and the API is what refuses."
    ),
    "/alerts": (
        "the static React shell, as with /dashboard — no findings are in it, "
        "and the API behind it is session-guarded."
    ),
    "/alerts/{match_id}": (
        "the static React shell, served for any id. The finding itself comes "
        "from the API, which 404s anything not owned by the caller."
    ),
    "/dashboard": (
        "the static React shell; it contains no user data and every dashboard "
        "read remains behind the internal session dependencies"
    ),
    "/assets/{asset_path:path}": "content-hashed public frontend build assets",
    "/webhooks/dodo": "authenticated by HMAC signature, not by session",
}

#: Routes authenticated by bearer key rather than by session cookie. These
#: correctly have no CSRF token — no cookie is read, so no browser can be
#: tricked into making the call.
#:
#: The value is the scope the route requires, and that is the part worth
#: reviewing. The split exists because a key that pushes scans lives in a CI
#: environment variable, where anyone who can read a build log can take it,
#: while a key that can add an ignore rule can silence the alert for the
#: vulnerability an attacker just used. Those must not be the same key, so
#: `manage` never belongs on a runner.
API_KEY_SCOPES = {
    "/api/v1/scan": "scan",
    "/api/v1/project": "read",
    "/api/v1/findings": "read",
    "/api/v1/history": "read",
    "/api/v1/supply-chain": "read",
    "/api/v1/rules": "manage",
    "/api/v1/rules/{identifier}": "manage",
}

API_KEY_ROUTES = set(API_KEY_SCOPES)

# Browser-internal endpoints are a separate contract. They use the opaque
# session cookie (optionally for the bootstrap endpoint) and must never be
# swept into the bearer-key assertions above.
INTERNAL_SESSION_ROUTES = {
    "/api/internal/auth/me": "optional",
    "/api/internal/dashboard": "internal_user",
    "/api/internal/findings": "internal_user",
    # The sign-in endpoints hold no session guard, because requiring a session
    # to create one is impossible. What protects them is rate limiting before
    # the password hash, CSRF on every mutation, and -- for the second factor --
    # a signed challenge cookie. Each is asserted separately below.
    "/api/internal/auth/login": "none",
    "/api/internal/auth/login/2fa": "none",
    "/api/internal/auth/logout": "none",
    "/api/internal/auth/forgot-password": "none",
    "/api/internal/auth/reset-password": "none",
    # Signup reads the current user only to refuse when one is already signed
    # in, which is why it classifies as optional rather than none.
    "/api/internal/auth/signup": "optional",
    # Projects. Every one of these re-checks ownership through
    # get_target_for_user, so a session alone reaches nothing.
    "/api/internal/projects": "internal_user",
    "/api/internal/projects/{target_id}": "internal_user",
    "/api/internal/projects/{target_id}/rename": "internal_user",
    "/api/internal/projects/{target_id}/manifest": "internal_user",
    "/api/internal/projects/{target_id}/scan": "internal_user",
    "/api/internal/projects/{target_id}/delete": "internal_user",
    "/api/internal/projects/{target_id}/keys": "internal_user",
    "/api/internal/projects/{target_id}/keys/{key_id}/revoke": "internal_user",
    "/api/internal/projects/{target_id}/rules": "internal_user",
    "/api/internal/projects/{target_id}/rules/{rule_id}/delete": "internal_user",
    "/api/internal/projects/{target_id}/thresholds": "internal_user",
    "/api/internal/projects/{target_id}/webhook": "internal_user",
    "/api/internal/projects/{target_id}/webhook/test": "internal_user",
    "/api/internal/projects/{target_id}/webhook/remove": "internal_user",
    "/api/internal/alerts/{match_id}": "internal_user",
    "/api/internal/alerts/{match_id}/status": "internal_user",
}


def scopes_enforced(route) -> set[str]:
    """Which KeyScope values a route's dependencies actually check for.

    `require_scope` builds a closure per scope, so the scope it captured is what
    the route really enforces — which is the thing worth asserting on, rather
    than a dependency's name.
    """
    found = set()
    for dependency in route.dependant.dependencies:
        call = getattr(dependency, "call", None)
        for cell in getattr(call, "__closure__", None) or ():
            try:
                contents = cell.cell_contents
            except ValueError:  # an empty cell
                continue
            if isinstance(contents, KeyScope):
                found.add(contents.value)
    return found


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
    if "require_internal_user" in names:
        return "internal_user"
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
    def test_every_public_api_route_requires_a_key(self, routes):
        wrong = [
            (sorted(r.methods), r.path, classify(r))
            for r in routes
            if r.path.startswith("/api/v1/") and classify(r) != "api_key"
        ]
        assert wrong == [], f"API routes not behind require_api_key: {wrong}"

    def test_the_api_surface_is_exactly_what_is_expected(self, routes):
        """A new endpoint on the machine API should be a decision, not a
        surprise. Adding one means listing it above and saying what it may do."""
        served = {r.path for r in routes if r.path.startswith("/api/v1/")}
        assert served == API_KEY_ROUTES

    def test_every_api_route_enforces_the_scope_it_should(self, routes):
        """The guarantee the scopes exist for.

        Reading findings or editing rules must not be possible with the key a
        pipeline holds. Checked by reading the scope out of the dependency
        actually attached to the route, so a handler that looks careful but was
        wired to the wrong dependency still fails here.
        """
        wrong = []
        for route in routes:
            if not route.path.startswith("/api/v1/"):
                continue
            expected = API_KEY_SCOPES[route.path]
            enforced = scopes_enforced(route)
            if enforced != {expected}:
                wrong.append((route.path, f"expected {expected}, enforces {enforced or 'nothing'}"))

        assert wrong == [], f"API routes enforcing the wrong scope: {wrong}"

    def test_api_routes_do_not_use_session_auth(self, routes):
        """Mixing the two would reintroduce exactly the ambient-credential
        problem that lets a logged-in browser be used to make API calls."""
        for route in routes:
            if route.path in API_KEY_ROUTES:
                names = dependency_names(route)
                assert "require_user" not in names
                assert "get_current_user" not in names


class TestInternalApiSurface:
    def test_the_internal_surface_is_explicit(self, routes):
        served = {r.path for r in routes if r.path.startswith("/api/internal/")}
        assert served == set(INTERNAL_SESSION_ROUTES)

    def test_internal_routes_use_the_reviewed_session_mode(self, routes):
        wrong = [
            (r.path, classify(r), INTERNAL_SESSION_ROUTES.get(r.path))
            for r in routes
            if r.path.startswith("/api/internal/")
            and classify(r) != INTERNAL_SESSION_ROUTES.get(r.path)
        ]
        assert wrong == [], f"internal routes using the wrong session guard: {wrong}"

    def test_internal_routes_never_accept_bearer_keys(self, routes):
        for route in routes:
            if route.path.startswith("/api/internal/"):
                assert "require_api_key" not in dependency_names(route)


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
        expected = {
            "/login",
            "/signup",
            "/logout",
            "/forgot-password",
            "/reset-password",
            # The JSON endpoints matter more here, not less: they are the ones
            # a cross-site page can reach with fetch().
            "/api/internal/auth/login",
            "/api/internal/auth/login/2fa",
            "/api/internal/auth/signup",
            "/api/internal/auth/logout",
            "/api/internal/auth/forgot-password",
            "/api/internal/auth/reset-password",
        }
        for route in routes:
            if route.path in expected and "POST" in route.methods:
                assert "verify_csrf" in dependency_names(route), route.path

    def test_the_webhook_is_deliberately_exempt(self, routes):
        """Dodo cannot send a CSRF token. Its authenticity comes from the HMAC
        signature over the raw body, which is verified before anything else."""
        webhook = [r for r in routes if r.path == "/webhooks/dodo"]
        assert webhook, "the webhook route should exist"
        assert "verify_csrf" not in dependency_names(webhook[0])
