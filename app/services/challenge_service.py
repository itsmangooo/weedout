"""The short-lived challenge between a password and a second-factor code.

Not a session, and deliberately not shaped like one. A signed value rather than
a database row: there is nothing to revoke, nothing to clean up, and it stops
meaning anything the moment it expires. A stolen one is worth only the
remaining minutes of a code prompt.

This lived in the auth router until sign-in moved to React. Nothing routes here
any more — `app/routes/internal_auth_actions.py` is the only caller — so it
sits with the other services instead of pretending to be a router.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import Request
from fastapi.responses import Response

from app.config import get_settings

#: How long the gap between password and code may be. Long enough to open an
#: authenticator and wait out a rollover, short enough that a challenge left on
#: a shared machine is not useful later.
CHALLENGE_TTL_SECONDS = 300

_CHALLENGE_COOKIE = "weedout_mfa"


def _sign_challenge(user_id: int, expires_at: int) -> str:
    """`{user_id}.{expires}.{hmac}`, keyed on SECRET_KEY.

    A signed value rather than a database row because it is not a session and
    should not look like one: nothing to revoke, nothing to clean up, and it
    stops meaning anything the moment it expires. The signature covers both
    fields, so neither the account nor the expiry can be edited.
    """
    payload = f"{user_id}.{expires_at}"
    digest = hmac.new(
        get_settings().secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{payload}.{digest}"


def read_challenge(request: Request) -> int | None:
    """The user id from a valid, unexpired challenge cookie, or None."""
    raw = request.cookies.get(_CHALLENGE_COOKIE)
    if not raw:
        return None

    parts = raw.split(".")
    if len(parts) != 3:
        return None

    user_id_raw, expires_raw, _ = parts
    try:
        user_id = int(user_id_raw)
        expires_at = int(expires_raw)
    except ValueError:
        return None

    # Constant-time, and recomputed from the claimed fields rather than trusted.
    if not hmac.compare_digest(_sign_challenge(user_id, expires_at), raw):
        return None
    if expires_at < int(time.time()):
        return None
    return user_id


def set_challenge_cookie(response: Response, user) -> None:
    settings = get_settings()
    expires_at = int(time.time()) + CHALLENGE_TTL_SECONDS
    response.set_cookie(
        _CHALLENGE_COOKIE,
        _sign_challenge(user.id, expires_at),
        max_age=CHALLENGE_TTL_SECONDS,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.session_cookie_samesite,
        path="/",
    )


def clear_challenge_cookie(response: Response) -> None:
    response.delete_cookie(_CHALLENGE_COOKIE, path="/")


# ---------------------------------------------------------------------------
# Signup, login and recovery moved to React.
#
# The pages are served from app/routes/frontend.py and the submissions go to
# /api/internal/auth/*. The decision behind signing in did not move with them:
# it lives in app/services/login_flow.py, which is where it went when there
# were two front doors, and is what the JSON endpoint calls now that there is
# one again.
#
# What remains below is account management, which is reached from inside a
# session and has no React screen yet.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Account settings
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Two-factor authentication
#
# Setup is two-phase on purpose: a secret exists from the moment you start, but
# 2FA is only in force once a working code has been produced from it. Someone
# who scans the QR and closes the tab is not locked out of their own account.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# API keys
#
# The generated key is passed straight to the template and never stored, never
# logged, and never put in a redirect target. It exists in this one response
# and nowhere else — which is why creation renders the page directly instead of
# following the POST-redirect-GET pattern used everywhere else here.
# ---------------------------------------------------------------------------
