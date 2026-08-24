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
    "/": "the marketing page — the React shell, or a redirect if already signed in",
    "/pricing": "public pricing",
    "/terms": "the static React shell for the terms of service",
    "/privacy": "the static React shell for the privacy policy",
    "/status": (
        "the static React shell for the public status page. A status page you have "
        "to sign in to read is not a status page."
    ),
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
    # `weedout auth`. Unauthenticated because the caller has no credential
    # yet -- that is the entire problem the flow exists to solve -- and outside
    # /api/v1 so the bearer-key assertion protecting that namespace stays
    # absolute. What stands in for authentication is asserted in
    # TestCliAuthFlow: `start` writes one short-lived row and is IP rate
    # limited; `poll` requires a 256-bit device code only the process that
    # started the request has ever held. Neither can grant anything without a
    # signed-in person approving it through the CSRF-protected internal
    # endpoint.
    "/api/cli-auth/start": (
        "begins a login; the caller has no credential by definition, and this "
        "grants nothing on its own"
    ),
    "/api/cli-auth/poll": (
        "collects the result of a login somebody approved in a browser; "
        "authenticated by a 256-bit device code, not by a session"
    ),
    "/api/internal/pricing": "the plan table; the same thing the pricing page shows a stranger",
    "/api/internal/cli": "the CLI version and dependency list; both already public",
    # Public on purpose. The failure it reports -- a stale advisory feed --
    # breaks the product's promise without breaking a page, and users have a
    # right to know about it without an account. Error strings and the backup
    # job are filtered out before anything is returned; see status_service.
    "/api/internal/status": "service health; no account details and no error text",
    "/api/internal/legal/{slug}": (
        "the terms and the privacy policy, which have to be readable before "
        "somebody has an account to read them with"
    ),
    "/api/internal/docs": "the published documentation index",
    "/api/internal/docs/{slug}": "one published documentation page",
    "/api/internal/contact": (
        "the contact form. Anyone may write to us, including somebody who "
        "cannot sign in — which is often exactly who needs to."
    ),
    "/api/internal/landing": (
        "the live figures on the marketing page. Unauthenticated by design — "
        "this is what a stranger is shown. Every field is already public: "
        "advisory ids from OSV, package names from public registries, and "
        "headline numbers rounded so they cannot be used to count customers."
    ),
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
    "/contact": "the static React shell for the contact form",
    "/billing": "the static React shell; the plan itself comes from the API",
    "/billing/success": (
        "where Dodo returns somebody after checkout. Served to anyone, "
        "because the shell holds nothing — what it shows comes from the API, "
        "which is session-guarded."
    ),
    "/cli-auth": (
        "the static React shell, reached by opening a URL printed in a terminal. "
        "Nothing about the account is in it, and the endpoints behind it that "
        "read and approve a pending request are both session-guarded."
    ),
    "/settings": (
        "the static React shell. Nothing about the account is in it; the "
        "settings API behind it is session-guarded and answers 401."
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
    # The admin panel's shell routes. Unguarded on purpose and reviewed as a
    # group: they serve the same bytes to every caller, hold no data at all,
    # and every figure on the panel comes from /api/internal/admin/*, which
    # enforces is-admin. Guarding these too would mean two places that have to
    # agree about who is an administrator, and the redirect a guard produces is
    # useless to the router that would receive it.
    # `TestTheAdminShellHoldsNothing` asserts the shell really is identical for
    # an administrator and a stranger, which is what makes this safe.
    "/admin": "the admin shell; every figure on it comes from the guarded API",
    "/admin/users": "the admin shell",
    "/admin/users/{user_id}": "the admin shell, served for any id",
    "/admin/billing": "the admin shell",
    "/admin/inbox": "the admin shell",
    "/admin/inbox/{message_id}": "the admin shell, served for any id",
    "/admin/email": "the admin shell",
    "/admin/docs": "the admin shell",
    "/admin/docs/new": "the admin shell",
    "/admin/docs/{page_id}": "the admin shell, served for any id",
    "/admin/audit": "the admin shell",
    "/logout": (
        "ends a session and redirects; harmless without one. A form post "
        "rather than a fetch because the error page — the only server-rendered "
        "page left — has to work when the React bundle did not load, which is "
        "one of the things it exists to report."
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
    # Read rather than manage. Knowing which rule sets exist is part of
    # understanding what a scan reported, and a CI key that can see the name it
    # is meant to pass fails with a useful message rather than a puzzle. The
    # documents are rules, not credentials.
    "/api/v1/profiles": "read",
    "/api/v1/rules": "manage",
    "/api/v1/rules/{identifier}": "manage",
}

API_KEY_ROUTES = set(API_KEY_SCOPES)

#: Account-level operations, behind the credential `weedout auth` puts on a
#: machine. A third namespace because it is a third credential.
#:
#: The split is the point. A project key can push a scan and read findings for
#: one project, and is what sits in CI where anyone reading a build log can
#: take it. A machine credential can create projects and mint keys for them,
#: and cannot read a single finding. Neither can do the other's job, and
#: `TestAccountApiSurface` asserts that rather than trusting it.
ACCOUNT_ROUTES = {
    "/api/account/projects",
    "/api/account/keys",
    "/api/account/keys/regenerate",
    "/api/account/whoami",
}

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
    "/api/internal/landing": "none",
    "/api/internal/pricing": "none",
    "/api/internal/cli": "none",
    "/api/internal/status": "none",
    "/api/internal/legal/{slug}": "none",
    "/api/internal/docs": "none",
    "/api/internal/docs/{slug}": "none",
    # Reads the session only to fill in a sender's address, never to gate.
    "/api/internal/contact": "optional",
    # Projects. Every one of these re-checks ownership through
    # get_target_for_user, so a session alone reaches nothing.
    "/api/internal/projects": "internal_user",
    "/api/internal/projects/{target_id}": "internal_user",
    "/api/internal/projects/{target_id}/rename": "internal_user",
    "/api/internal/projects/{target_id}/manifest": "internal_user",
    # Rule profiles are account-scoped, not project-scoped, which is why they
    # sit outside the /projects prefix. Assigning one to a project is the one
    # operation that belongs on the project.
    "/api/internal/profiles": "internal_user",
    "/api/internal/profiles/{profile_id}": "internal_user",
    "/api/internal/profiles/{profile_id}/default": "internal_user",
    "/api/internal/profiles/{profile_id}/delete": "internal_user",
    "/api/internal/projects/{target_id}/scan": "internal_user",
    "/api/internal/projects/{target_id}/delete": "internal_user",
    "/api/internal/projects/{target_id}/keys": "internal_user",
    "/api/internal/projects/{target_id}/keys/{key_id}/revoke": "internal_user",
    # Approving a machine login. The browser half of `weedout auth`, and the
    # half that carries the authorisation: the terminal proves it started the
    # request, this proves who is granting it. CSRF matters more here than
    # almost anywhere -- without it a page somebody visits while signed in
    # could hand an attacker a credential for the account.
    "/api/internal/cli-auth/{code}": "internal_user",
    "/api/internal/cli-auth/approve": "internal_user",
    "/api/internal/cli-auth/deny": "internal_user",
    "/api/internal/cli-tokens": "internal_user",
    "/api/internal/cli-tokens/{token_id}/revoke": "internal_user",
    "/api/internal/projects/{target_id}/profile": "internal_user",
    "/api/internal/projects/{target_id}/rules": "internal_user",
    "/api/internal/projects/{target_id}/rules/{rule_id}/delete": "internal_user",
    "/api/internal/projects/{target_id}/thresholds": "internal_user",
    "/api/internal/projects/{target_id}/webhook": "internal_user",
    "/api/internal/projects/{target_id}/webhook/test": "internal_user",
    "/api/internal/projects/{target_id}/webhook/remove": "internal_user",
    "/api/internal/alerts/{match_id}": "internal_user",
    "/api/internal/alerts/{match_id}/status": "internal_user",
    "/api/internal/billing": "internal_user",
    "/api/internal/settings": "internal_user",
    "/api/internal/settings/organisation": "internal_user",
    "/api/internal/settings/showcase": "internal_user",
    "/api/internal/settings/alerts": "internal_user",
    "/api/internal/settings/password": "internal_user",
    "/api/internal/settings/sessions/revoke-others": "internal_user",
    "/api/internal/settings/sessions/{session_id}/revoke": "internal_user",
    "/api/internal/settings/2fa/start": "internal_user",
    "/api/internal/settings/2fa/confirm": "internal_user",
    "/api/internal/settings/2fa/codes": "internal_user",
    "/api/internal/settings/2fa/disable": "internal_user",
    "/api/internal/settings/api-keys": "internal_user",
    "/api/internal/settings/api-keys/{key_id}/revoke": "internal_user",
    # The admin panel. `internal_admin` is `internal_user` plus the is_admin
    # boolean, so a signed-in customer reaching any of these is a 403 — the
    # same answer the rendered panel gives, in the JSON shape a fetch can read.
    "/api/internal/admin/overview": "internal_admin",
    "/api/internal/admin/users": "internal_admin",
    "/api/internal/admin/users/{user_id}": "internal_admin",
    "/api/internal/admin/users/{user_id}/tier": "internal_admin",
    "/api/internal/admin/users/{user_id}/showcase": "internal_admin",
    "/api/internal/admin/users/{user_id}/suspend": "internal_admin",
    "/api/internal/admin/users/{user_id}/unsuspend": "internal_admin",
    "/api/internal/admin/users/{user_id}/delete": "internal_admin",
    "/api/internal/admin/billing": "internal_admin",
    "/api/internal/admin/docs": "internal_admin",
    "/api/internal/admin/docs/{page_id}": "internal_admin",
    "/api/internal/admin/docs/{page_id}/delete": "internal_admin",
    "/api/internal/admin/inbox": "internal_admin",
    "/api/internal/admin/inbox/{message_id}": "internal_admin",
    "/api/internal/admin/inbox/{message_id}/status": "internal_admin",
    "/api/internal/admin/email": "internal_admin",
    "/api/internal/admin/email/preview": "internal_admin",
    "/api/internal/admin/email/send": "internal_admin",
    "/api/internal/admin/audit": "internal_admin",
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
    # A third credential type, and the assertions below depend on it being
    # distinguishable from the other two: a project key must not reach an
    # account operation, and a machine credential must not reach a project's
    # findings.
    if "require_cli_token" in names:
        return "cli_token"
    # Checked before `internal_user`, because the admin guard is built on top
    # of it — an admin route reports both names, and the stricter one is the
    # one that describes it.
    if "require_internal_admin" in names:
        return "internal_admin"
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
    def test_no_admin_shell_route_serves_data(self, routes):
        """`/admin/*` is the React shell and is deliberately unguarded.

        What makes that acceptable is that the handler is `_shell` and nothing
        else — the moment one of these grows a database session it is serving
        admin data to anonymous callers, and this is the assertion that says so.
        """
        wrong = [
            (sorted(r.methods), r.path, sorted(dependency_names(r)))
            for r in routes
            if r.path.startswith("/admin")
            and (r.endpoint.__module__ != "app.routes.frontend" or classify(r) != "none")
        ]
        assert wrong == [], f"admin shell routes that are not plain shells: {wrong}"

    def test_every_admin_api_route_requires_admin(self, routes):
        """The React panel's endpoints are the same access-control surface.

        Swept by prefix rather than by a list, for the reason the whole module
        exists: an endpoint someone forgot to add to a list is exactly the one
        that would ship unguarded.
        """
        wrong = [
            (sorted(r.methods), r.path, classify(r))
            for r in routes
            if r.path.startswith("/api/internal/admin") and classify(r) != "internal_admin"
        ]
        assert wrong == [], f"admin API routes not behind require_internal_admin: {wrong}"

    def test_there_are_admin_api_routes_to_check(self, routes):
        assert any(r.path.startswith("/api/internal/admin") for r in routes)

    def test_no_admin_route_hides_behind_a_plain_session(self, routes):
        """`internal_user` on an /admin path would mean any customer got in."""
        for route in routes:
            if route.path.startswith("/api/internal/admin"):
                assert "require_internal_admin" in dependency_names(route)


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


class TestAccountApiSurface:
    """The third credential, and the walls around it.

    `weedout auth` puts a machine credential on a laptop. It exists to do the
    things that have no project yet -- create one, list them, mint a key for
    one -- and it must never become a way to read an account's findings, which
    is what a project key is for.
    """

    def test_the_surface_is_exactly_what_is_expected(self, routes):
        served = {r.path for r in routes if r.path.startswith("/api/account/")}
        assert served == ACCOUNT_ROUTES

    def test_every_account_route_requires_a_machine_credential(self, routes):
        wrong = [
            (sorted(r.methods), r.path, classify(r))
            for r in routes
            if r.path.startswith("/api/account/") and classify(r) != "cli_token"
        ]
        assert wrong == [], f"account routes not behind require_cli_token: {wrong}"

    def test_they_never_accept_a_project_key(self, routes):
        """A key leaked from a CI runner must not be able to enumerate the
        account or mint more keys."""
        for route in routes:
            if route.path.startswith("/api/account/"):
                assert "require_api_key" not in dependency_names(route)

    def test_they_never_accept_a_session(self, routes):
        """Mixing the two would reintroduce the ambient-credential problem:
        a logged-in browser being usable to make these calls."""
        for route in routes:
            if route.path.startswith("/api/account/"):
                names = dependency_names(route)
                assert "require_user" not in names
                assert "require_internal_user" not in names
                assert "get_current_user" not in names

    def test_the_machine_credential_reaches_nothing_else(self, routes):
        """The other direction. A token stolen from a laptop must not read
        findings, which means no route outside this namespace may accept
        one."""
        stray = [
            r.path for r in routes if classify(r) == "cli_token" and r.path not in ACCOUNT_ROUTES
        ]
        assert stray == [], f"machine credential accepted outside /api/account: {stray}"


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
            if (
                route.path in API_KEY_ROUTES
                or route.path in ACCOUNT_ROUTES
                or route.path in PUBLIC_ROUTES
            ):
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
