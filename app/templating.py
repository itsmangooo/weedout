"""Jinja2 environment and template helpers.

Autoescaping is on for every template (Jinja's `select_autoescape` covers .html),
and nothing here ever marks user-supplied text safe.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.core.explain import (
    confidence_note,
    fix_command,
    fix_sentence,
    risk_sentence,
    why_surfaced,
)
from app.core.types import Severity
from app.deps import CSRF_COOKIE_NAME, issue_csrf_token
from app.tiers import PLANS, limits_for

TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def relative_time(value: datetime | None) -> str:
    """Human-friendly age. `None` renders as 'never'."""
    if value is None:
        return "never"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)

    delta = datetime.now(UTC) - value
    seconds = delta.total_seconds()

    if seconds < 0:
        # A future timestamp is a scheduled time, not an age.
        seconds = -seconds
        if seconds < 60:
            return "in under a minute"
        if seconds < 3600:
            return f"in {int(seconds // 60)}m"
        if seconds < 86400:
            return f"in {int(seconds // 3600)}h"
        return f"in {int(seconds // 86400)}d"

    if seconds < 45:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    if seconds < 86400 * 30:
        return f"{int(seconds // 86400)}d ago"
    return value.strftime("%d %b %Y")


def absolute_time(value: datetime | None) -> str:
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.strftime("%d %b %Y, %H:%M UTC")


def severity_class(severity: Severity | str | None) -> str:
    """CSS modifier for a severity badge."""
    if severity is None:
        return "sev-unknown"
    value = severity.value if isinstance(severity, Severity) else str(severity)
    return f"sev-{value}"


def device_name(user_agent: str | None) -> str:
    """A readable name for the thing a session was started from.

    Deliberately coarse. A user agent string cannot identify a device
    reliably, and pretending otherwise ("MacBook Pro, Chrome 139") invites
    people to trust a guess. Browser and platform are enough to answer the only
    question this list exists for: is one of these not me?
    """
    if not user_agent:
        return "Unknown device"

    ua = user_agent
    lowered = ua.lower()

    # Order matters: Edge and Opera both carry "chrome", and Chrome carries
    # "safari", so the more specific names have to be tested first.
    browser = next(
        (
            name
            for token, name in (
                ("edg/", "Edge"),
                ("opr/", "Opera"),
                ("firefox/", "Firefox"),
                ("chrome/", "Chrome"),
                ("safari/", "Safari"),
                ("curl/", "curl"),
                ("python-httpx", "httpx"),
                ("weedout-cli", "Weedout CLI"),
            )
            if token in lowered
        ),
        "Unknown browser",
    )

    platform = next(
        (
            name
            for token, name in (
                ("windows", "Windows"),
                ("android", "Android"),
                ("iphone", "iPhone"),
                ("ipad", "iPad"),
                ("mac os x", "macOS"),
                ("macintosh", "macOS"),
                ("cros", "ChromeOS"),
                ("linux", "Linux"),
            )
            if token in lowered
        ),
        "",
    )

    return f"{browser} on {platform}" if platform else browser


def pluralize(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or f"{singular}s")


templates.env.filters["relative_time"] = relative_time
templates.env.filters["absolute_time"] = absolute_time
templates.env.filters["severity_class"] = severity_class
templates.env.filters["device_name"] = device_name
templates.env.filters["pluralize"] = pluralize

# Explanation helpers, so the alert views call one function instead of
# assembling prose in the template.
templates.env.globals["risk_sentence"] = risk_sentence
templates.env.globals["why_surfaced"] = why_surfaced
templates.env.globals["fix_sentence"] = fix_sentence
templates.env.globals["fix_command"] = fix_command
templates.env.globals["confidence_note"] = confidence_note
templates.env.globals["limits_for"] = limits_for
templates.env.globals["PLANS"] = PLANS


def render(
    request: Request,
    template_name: str,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """Render a template with the shared context every page expects.

    Also (re)issues the CSRF cookie on every HTML response, so a form is never
    served without its matching cookie — the failure mode being a mystifying
    403 on submit.
    """
    settings = get_settings()
    csrf_token = issue_csrf_token(request)

    merged: dict[str, Any] = {
        "request": request,
        # The detached snapshot, never the live ORM instance — see
        # `app.deps.TemplateUser` for why this matters on error pages.
        "user": getattr(request.state, "template_user", None),
        "csrf_token": csrf_token,
        "settings": settings,
        "flash": getattr(request.state, "flash", None),
        "now": datetime.now(UTC),
    }
    merged.update(context or {})

    response = templates.TemplateResponse(
        request=request,
        name=template_name,
        context=merged,
        status_code=status_code,
        headers=headers,
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token,
        max_age=60 * 60 * 12,
        # Readable by JS on purpose: the double-submit pattern needs the client
        # to echo it back in a header for fetch() calls.
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return response
