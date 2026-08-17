"""Request-scoped dependencies: the current user, CSRF, and flash messages."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.core.types import Tier
from app.db import get_db
from app.logging_config import get_logger
from app.models import ApiKey, User
from app.services.auth_service import session_user

log = get_logger(__name__)

__all__ = [
    "CurrentAdmin",
    "CurrentApiKey",
    "CurrentUser",
    "DbSession",
    "OptionalUser",
    "TemplateUser",
    "get_current_user",
    "require_admin",
    "require_api_key",
    "require_user",
    "snapshot_user",
    "verify_csrf",
]

CSRF_COOKIE_NAME = "weedout_csrf"
CSRF_FIELD_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"


@dataclass(frozen=True, slots=True)
class TemplateUser:
    """A detached, read-only view of the signed-in user, for templates.

    Templates must never hold a live ORM instance. Error pages are rendered
    *after* the request's dependencies have been torn down: `get_db` rolls the
    session back and closes it, which expires every attribute on the instance,
    so the next attribute access in a template tries to reload from a session
    that is gone. The failure is a bare 500 replacing whatever error page the
    user should have seen — the worst possible moment for it.

    Copying the handful of fields templates actually use removes the dependency
    on session lifetime entirely, and keeps rendering a pure function of data.
    """

    id: int
    email: str
    tier: Tier
    is_admin: bool
    is_suspended: bool
    is_active: bool
    email_alerts_enabled: bool
    created_at: datetime | None = None
    last_login_at: datetime | None = None
    subscription_status: str | None = None
    subscription_ends_at: datetime | None = None

    @property
    def status_label(self) -> str:
        if self.is_suspended:
            return "Suspended"
        if not self.is_active:
            return "Inactive"
        return "Active"


def snapshot_user(user: User | None) -> TemplateUser | None:
    if user is None:
        return None
    return TemplateUser(
        id=user.id,
        email=user.email,
        tier=user.tier,
        is_admin=user.is_admin,
        is_suspended=user.is_suspended,
        is_active=user.is_active,
        email_alerts_enabled=user.email_alerts_enabled,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        subscription_status=user.subscription_status,
        subscription_ends_at=user.subscription_ends_at,
    )


class RedirectToLogin(HTTPException):
    """Signals that an HTML request needs to authenticate first.

    Raised rather than returned so it can surface from a nested dependency; the
    exception handler in `main` turns it into a 303 to the login page carrying a
    `next` parameter, so the user lands where they were going.
    """

    def __init__(self, next_url: str = "/dashboard") -> None:
        super().__init__(status_code=status.HTTP_303_SEE_OTHER, detail="Authentication required")
        self.next_url = next_url


async def get_current_user(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User | None:
    """Resolve the session cookie to a user, or None for anonymous requests."""
    token = request.cookies.get(settings.session_cookie_name)
    user = await session_user(db, token)
    request.state.user = user
    # A detached copy for rendering. Taken here, while the session is still
    # open, so the error handler can render a nav bar after teardown.
    request.state.template_user = snapshot_user(user)
    return user


async def require_user(
    request: Request,
    user: Annotated[User | None, Depends(get_current_user)],
) -> User:
    """Same, but redirects anonymous visitors to the login page."""
    if user is None:
        raise RedirectToLogin(next_url=request.url.path)
    return user


async def require_admin(
    request: Request,
    user: Annotated[User | None, Depends(get_current_user)],
) -> User:
    """Gate for `/admin/*`. Deliberately separate from `require_user`.

    Two distinct outcomes, and the difference matters:

    * Anonymous visitors are redirected to log in, exactly as elsewhere.
    * A signed-in **non-admin** gets a hard 403. It does not redirect, and it
      does not 404 to hide the route's existence — this is a single-tenant
      admin panel behind a boolean, and pretending the URL is absent buys
      nothing while making a real misconfiguration harder to notice.

    Enforcement lives here rather than in the templates. Hiding the nav link is
    presentation; this is the access control, and it is applied to every route
    in the admin router including the ones that only return data.
    """
    if user is None:
        raise RedirectToLogin(next_url=request.url.path)

    if not user.is_admin:
        log.warning(
            "admin.access_denied",
            user_id=user.id,
            path=request.url.path,
            method=request.method,
        )
        raise HTTPException(status_code=403, detail="You don't have access to that.")

    return user


async def require_api_key(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ApiKey:
    """Authenticate a machine caller from `Authorization: Bearer <key>`.

    Entirely separate from the session dependencies, and deliberately so. The
    two carry different risks and want different behaviour:

    * No cookie is read, so a browser that happens to be logged in cannot
      authenticate an API call it was tricked into making — which is also why
      these routes need no CSRF token. The credential is never sent ambiently.
    * Failure is a 401 with `WWW-Authenticate`, not a redirect to a login page.
      A CI runner cannot follow one, and a 303 to HTML is a confusing way to
      tell a script its key is wrong.
    * Every failure looks the same. Missing, malformed, unknown, revoked and
      suspended are one response, because distinguishing them tells someone
      holding a list of leaked strings which ones were once real.
    """
    from app.services.api_key_service import authenticate_api_key, parse_bearer_token

    token = parse_bearer_token(request.headers.get("authorization"))
    key = await authenticate_api_key(db, token)
    if key is None:
        log.info("api_key.rejected", path=request.url.path, presented=bool(token))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.api_key = key
    return key


DbSession = Annotated[AsyncSession, Depends(get_db)]
CurrentUser = Annotated[User, Depends(require_user)]
CurrentAdmin = Annotated[User, Depends(require_admin)]
CurrentApiKey = Annotated[ApiKey, Depends(require_api_key)]
OptionalUser = Annotated[User | None, Depends(get_current_user)]
AppSettings = Annotated[Settings, Depends(get_settings)]


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


def issue_csrf_token(request: Request) -> str:
    """Return the request's CSRF token, minting one if absent.

    Double-submit cookie pattern: the token lives in a cookie *and* in a hidden
    form field, and a forged cross-site POST cannot read the cookie to populate
    the field. The cookie is deliberately readable by JavaScript so the small
    amount of client-side fetch code can echo it in a header.
    """
    existing = getattr(request.state, "csrf_token", None)
    if existing:
        return existing
    token = request.cookies.get(CSRF_COOKIE_NAME) or secrets.token_urlsafe(32)
    request.state.csrf_token = token
    return token


async def verify_csrf(request: Request) -> None:
    """Reject state-changing requests without a matching CSRF token.

    Applied to every mutating route. Read-only handlers are exempt because they
    change nothing.
    """
    if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not cookie_token:
        raise HTTPException(status_code=403, detail="Missing CSRF cookie. Please reload the page.")

    submitted = request.headers.get(CSRF_HEADER_NAME)
    if not submitted:
        try:
            form = await request.form()
        except Exception:
            form = {}
        value = form.get(CSRF_FIELD_NAME)
        submitted = value if isinstance(value, str) else None

    if not submitted or not hmac.compare_digest(cookie_token, submitted):
        raise HTTPException(status_code=403, detail="Invalid CSRF token. Please reload the page.")


CsrfProtected = Depends(verify_csrf)


def redirect(url: str, status_code: int = status.HTTP_303_SEE_OTHER) -> RedirectResponse:
    """303 by default, so a POST redirects to a GET rather than replaying."""
    return RedirectResponse(url=url, status_code=status_code)
