"""Signup, login, logout, and account settings."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError

from app.config import get_settings
from app.deps import (
    CsrfProtected,
    CurrentUser,
    DbSession,
    OptionalUser,
    redirect,
)
from app.logging_config import get_logger
from app.schemas import (
    AlertPreferencesForm,
    ApiKeyForm,
    ChangePasswordForm,
    ForgotPasswordForm,
    LoginForm,
    ResetPasswordForm,
    SignupForm,
)
from app.services.api_key_service import (
    ApiKeyError,
    issue_api_key,
    keys_for_user,
    revoke_api_key,
)
from app.services.auth_service import (
    AuthError,
    EmailAlreadyRegistered,
    InvalidCredentials,
    WeakPassword,
    authenticate,
    change_password,
    create_session,
    register_user,
    revoke_session,
)
from app.services.password_reset_service import (
    InvalidResetToken,
    complete_password_reset,
    request_password_reset,
    validate_reset_token,
)
from app.services.rate_limit_service import (
    bucket_for,
    check_rate_limit,
    client_ip,
    record_attempt,
)
from app.services.target_service import get_target_for_user, list_targets
from app.templating import render

log = get_logger(__name__)

router = APIRouter(tags=["auth"])


def _set_session_cookie(response: RedirectResponse, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        settings.session_cookie_name,
        token,
        max_age=settings.session_ttl_hours * 3600,
        # HttpOnly: no application JavaScript ever needs to read this, and
        # keeping it out of reach limits what an XSS bug could steal.
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.session_cookie_samesite,
        path="/",
    )


def _clear_session_cookie(response: RedirectResponse) -> None:
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name, path="/")


# ---------------------------------------------------------------------------
# Signup
# ---------------------------------------------------------------------------


@router.get("/signup")
async def signup_page(request: Request, user: OptionalUser):
    if user is not None:
        return redirect("/dashboard")
    return render(request, "auth/signup.html", {"page_title": "Create your account"})


@router.post("/signup", dependencies=[CsrfProtected])
async def signup_submit(
    request: Request,
    db: DbSession,
    email: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    website: Annotated[str, Form()] = "",
):
    settings = get_settings()
    ip_bucket = bucket_for("signup", "ip", client_ip(request, settings))
    decision = await check_rate_limit(
        db, ip_bucket, settings.signup_rate_limit_per_ip, timedelta(hours=1)
    )
    if not decision.allowed:
        log.warning("auth.signup_rate_limited", used=decision.used)
        return _rate_limited(
            request,
            "auth/signup.html",
            {"page_title": "Create your account", "email": email},
            decision,
            "Too many accounts have been created from here recently.",
        )

    # Recorded before validation so that malformed submissions still count —
    # otherwise the limit is trivially bypassed by sending garbage.
    await record_attempt(db, ip_bucket)
    await db.commit()

    try:
        form = SignupForm(email=email, password=password, website=website)
    except ValidationError as exc:
        return render(
            request,
            "auth/signup.html",
            {"page_title": "Create your account", "error": _first_error(exc), "email": email},
            status_code=400,
        )

    if form.website:
        # Honeypot tripped. Behave exactly like success so a bot learns nothing.
        log.info("auth.honeypot_triggered")
        return redirect("/login")

    try:
        user = await register_user(db, form.email, form.password)
    except (EmailAlreadyRegistered, WeakPassword) as exc:
        return render(
            request,
            "auth/signup.html",
            {"page_title": "Create your account", "error": str(exc), "email": form.email},
            status_code=400,
        )

    token = await create_session(db, user, request.headers.get("user-agent"), _client_ip(request))
    await db.commit()

    response = redirect("/dashboard")
    _set_session_cookie(response, token)
    return response


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------


@router.get("/login")
async def login_page(request: Request, user: OptionalUser, next: str = "/dashboard"):
    if user is not None:
        return redirect("/dashboard")
    return render(request, "auth/login.html", {"page_title": "Sign in", "next": next})


@router.post("/login", dependencies=[CsrfProtected])
async def login_submit(
    request: Request,
    db: DbSession,
    email: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    next: Annotated[str, Form()] = "/dashboard",
):
    settings = get_settings()
    page = {"page_title": "Sign in", "email": email, "next": next}

    # Checked before the password is verified, not after. Argon2id is
    # deliberately expensive — 19 MiB and real CPU per call — so an unlimited
    # login endpoint is a memory-exhaustion lever as well as a credential
    # stuffing target. A rejected attempt must cost one indexed count, not one
    # hash.
    window = timedelta(minutes=settings.login_rate_limit_window_minutes)
    ip_bucket = bucket_for("login", "ip", client_ip(request, settings))
    account_bucket = bucket_for("login", "account", email)

    for bucket, limit in (
        (ip_bucket, settings.login_rate_limit_per_ip),
        (account_bucket, settings.login_rate_limit_per_account),
    ):
        decision = await check_rate_limit(db, bucket, limit, window)
        if not decision.allowed:
            log.warning("auth.login_rate_limited", used=decision.used, limit=decision.limit)
            return _rate_limited(
                request,
                "auth/login.html",
                page,
                decision,
                "Too many sign-in attempts.",
            )

    try:
        form = LoginForm(email=email, password=password, next=next)
    except ValidationError as exc:
        return render(
            request,
            "auth/login.html",
            {**page, "error": _first_error(exc)},
            status_code=400,
        )

    try:
        user = await authenticate(db, form.email, form.password)
    except InvalidCredentials as exc:
        # Only failures are recorded, so a legitimate user is never throttled
        # by their own successful sign-ins and a shared office address is not
        # collectively punished for one person's typo.
        await record_attempt(db, ip_bucket)
        await record_attempt(db, account_bucket)
        await db.commit()

        log.info("auth.login_failed", email_domain=form.email.rsplit("@", 1)[-1])
        return render(
            request,
            "auth/login.html",
            {**page, "error": str(exc), "email": form.email, "next": form.next},
            status_code=401,
        )

    token = await create_session(db, user, request.headers.get("user-agent"), _client_ip(request))
    await db.commit()

    response = redirect(form.next)
    _set_session_cookie(response, token)
    return response


@router.post("/logout", dependencies=[CsrfProtected])
async def logout(request: Request, db: DbSession):
    settings = get_settings()
    await revoke_session(db, request.cookies.get(settings.session_cookie_name))
    await db.commit()

    response = redirect("/")
    _clear_session_cookie(response)
    return response


# ---------------------------------------------------------------------------
# Forgotten password
#
# Every response on the request step is identical whether or not the address is
# registered. That is the entire security property of this flow, so the two
# handlers below deliberately have exactly one exit each.
# ---------------------------------------------------------------------------


@router.get("/forgot-password")
async def forgot_password_page(request: Request, user: OptionalUser):
    if user is not None:
        return redirect("/settings")
    return render(request, "auth/forgot_password.html", {"page_title": "Reset your password"})


@router.post("/forgot-password", dependencies=[CsrfProtected])
async def forgot_password_submit(
    request: Request,
    db: DbSession,
    email: Annotated[str, Form()] = "",
):
    """Request a reset link.

    Renders the same confirmation for a valid address, an unregistered one, a
    suspended account and a malformed address alike. A validation error shown
    only for unknown addresses would leak exactly what the identical wording
    is there to hide.

    The rate limit here is keyed on the client address *only*, never on the
    submitted email. Keying it on the address would make the throttle response
    depend on how many times that specific account had been targeted, which is
    precisely the enumeration oracle the identical wording exists to close.
    `password_reset_max_per_hour` separately caps mail sent to any one address;
    this caps the endpoint, which is what a sweep hits.
    """
    settings = get_settings()
    ip_bucket = bucket_for("pwreset", "ip", client_ip(request, settings))
    decision = await check_rate_limit(
        db, ip_bucket, settings.password_reset_rate_limit_per_ip, timedelta(hours=1)
    )
    if not decision.allowed:
        log.warning("password_reset.rate_limited", used=decision.used)
        return _rate_limited(
            request,
            "auth/forgot_password.html",
            {"page_title": "Reset your password"},
            decision,
            "Too many reset requests from here.",
        )

    await record_attempt(db, ip_bucket)
    await db.commit()

    try:
        form = ForgotPasswordForm(email=email)
    except ValidationError:
        # Not even a malformed address gets a different answer.
        log.info("password_reset.malformed_address")
    else:
        await request_password_reset(db, form.email, _client_ip(request))
        await db.commit()

    return render(
        request,
        "auth/forgot_password_sent.html",
        {"page_title": "Check your email", "email": email.strip()},
    )


@router.get("/reset-password")
async def reset_password_page(
    request: Request,
    db: DbSession,
    token: Annotated[str, Query()] = "",
):
    """Show the new-password form, if the link is still good.

    Checked before rendering so a dead link says so immediately, rather than
    after the user has chosen and typed a password twice.
    """
    record = await validate_reset_token(db, token)
    if record is None:
        return render(
            request,
            "auth/reset_password_invalid.html",
            {"page_title": "That link has expired"},
            status_code=400,
        )

    return render(
        request,
        "auth/reset_password.html",
        {"page_title": "Choose a new password", "token": token},
    )


@router.post("/reset-password", dependencies=[CsrfProtected])
async def reset_password_submit(
    request: Request,
    db: DbSession,
    token: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    password_confirm: Annotated[str, Form()] = "",
):
    try:
        form = ResetPasswordForm(token=token, password=password, password_confirm=password_confirm)
    except ValidationError as exc:
        # Re-render with the token intact so a mistyped confirmation does not
        # cost the user their one link.
        return render(
            request,
            "auth/reset_password.html",
            {
                "page_title": "Choose a new password",
                "token": token,
                "error": _first_error(exc),
            },
            status_code=400,
        )

    try:
        await complete_password_reset(db, form.token, form.password)
    except InvalidResetToken as exc:
        await db.rollback()
        return render(
            request,
            "auth/reset_password_invalid.html",
            {"page_title": "That link has expired", "error": str(exc)},
            status_code=400,
        )
    except WeakPassword as exc:
        return render(
            request,
            "auth/reset_password.html",
            {"page_title": "Choose a new password", "token": token, "error": str(exc)},
            status_code=400,
        )

    await db.commit()

    # Deliberately not signed in automatically: the reset revoked every
    # session, and proving the new password works now is better than
    # discovering later that it was not what they thought they typed.
    return render(
        request,
        "auth/login.html",
        {
            "page_title": "Sign in",
            "next": "/dashboard",
            "success": "Your password has been changed. You've been signed out everywhere else.",
        },
    )


# ---------------------------------------------------------------------------
# Account settings
# ---------------------------------------------------------------------------


async def _settings_context(db, user, **extra) -> dict:
    """Everything the settings page needs, in one place.

    Built by a helper because the page is re-rendered from six handlers, and a
    context assembled inline in each of them is a context that ends up
    different in each of them.
    """
    context = {
        "page_title": "Settings",
        "api_keys": await keys_for_user(db, user),
        # `list_targets` returns summaries with finding counts attached; the
        # key form only needs to name a project, so the targets are unwrapped
        # here rather than making the template reach through a wrapper.
        "targets": [summary.target for summary in await list_targets(db, user.id)],
    }
    context.update(extra)
    return context


@router.get("/settings")
async def settings_page(request: Request, db: DbSession, user: CurrentUser):
    return render(request, "settings.html", await _settings_context(db, user))


@router.post("/settings/alerts", dependencies=[CsrfProtected])
async def update_alert_preferences(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    email_alerts_enabled: Annotated[str, Form()] = "",
):
    form = AlertPreferencesForm(email_alerts_enabled=email_alerts_enabled == "on")
    user.email_alerts_enabled = form.email_alerts_enabled
    await db.commit()

    return render(
        request,
        "settings.html",
        await _settings_context(db, user, success="Alert preferences saved."),
    )


# ---------------------------------------------------------------------------
# API keys
#
# The generated key is passed straight to the template and never stored, never
# logged, and never put in a redirect target. It exists in this one response
# and nowhere else — which is why creation renders the page directly instead of
# following the POST-redirect-GET pattern used everywhere else here.
# ---------------------------------------------------------------------------


@router.post("/settings/api-keys", dependencies=[CsrfProtected])
async def create_api_key(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    target_id: Annotated[str, Form()] = "",
    name: Annotated[str, Form()] = "",
):
    try:
        form = ApiKeyForm(target_id=target_id, name=name)
    except ValidationError as exc:
        return render(
            request,
            "settings.html",
            await _settings_context(db, user, error=_first_error(exc)),
            status_code=400,
        )

    target = await get_target_for_user(db, user.id, form.target_id)
    if target is None:
        return render(
            request,
            "settings.html",
            await _settings_context(db, user, error="That project could not be found."),
            status_code=404,
        )

    try:
        issued = await issue_api_key(db, user, target, form.name)
    except ApiKeyError as exc:
        return render(
            request,
            "settings.html",
            await _settings_context(db, user, error=str(exc)),
            status_code=400,
        )

    await db.commit()

    return render(
        request,
        "settings.html",
        await _settings_context(
            db,
            user,
            new_api_key=issued.token,
            new_api_key_target=target.name,
            success="Key created. Copy it now — it will not be shown again.",
        ),
    )


@router.post("/settings/api-keys/{key_id}/revoke", dependencies=[CsrfProtected])
async def revoke_key(request: Request, db: DbSession, user: CurrentUser, key_id: int):
    if not await revoke_api_key(db, user, key_id):
        return render(
            request,
            "settings.html",
            await _settings_context(db, user, error="That key could not be found."),
            status_code=404,
        )
    await db.commit()
    return redirect("/settings")


@router.post("/settings/password", dependencies=[CsrfProtected])
async def update_password(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    current_password: Annotated[str, Form()] = "",
    new_password: Annotated[str, Form()] = "",
):
    try:
        form = ChangePasswordForm(current_password=current_password, new_password=new_password)
    except ValidationError as exc:
        return render(
            request,
            "settings.html",
            {"page_title": "Settings", "error": _first_error(exc)},
            status_code=400,
        )

    try:
        await change_password(db, user, form.current_password, form.new_password)
    except AuthError as exc:
        return render(
            request,
            "settings.html",
            {"page_title": "Settings", "error": str(exc)},
            status_code=400,
        )

    # change_password revoked every session, including this one, so issue a
    # fresh one rather than logging the user out of the page they are on.
    token = await create_session(db, user, request.headers.get("user-agent"), _client_ip(request))
    await db.commit()

    response = redirect("/settings")
    _set_session_cookie(response, token)
    return response


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    message = error["msg"].removeprefix("Value error, ")

    # Model-level errors (a cross-field check like "passwords must match") have
    # no field location. Prefixing those with a made-up field name produces
    # "Input: Those passwords don't match", which is worse than the sentence on
    # its own.
    if not error["loc"]:
        return message

    field = str(error["loc"][0])
    return f"{field.replace('_', ' ').capitalize()}: {message}"


def _rate_limited(request: Request, template: str, context: dict, decision, headline: str):
    """Render a throttled response: 429, with a Retry-After the client can use.

    A page rather than a bare error because a real person who mistyped their
    password five times will see this, and "try again in 4 minutes" is the only
    thing they need. `Retry-After` carries the same fact for anything
    automated.
    """
    minutes = max(1, round(decision.retry_after_seconds / 60))
    unit = "minute" if minutes == 1 else "minutes"
    return render(
        request,
        template,
        {**context, "error": f"{headline} Try again in about {minutes} {unit}."},
        status_code=429,
        headers={"Retry-After": str(decision.retry_after_seconds)},
    )


def _client_ip(request: Request) -> str | None:
    """Best-effort client IP, for the user's own session list.

    Display only — never used for authorisation or rate limiting, which is why
    it can afford to read an untrusted header. Anything that makes a security
    decision must use `rate_limit_service.client_ip`, which consults only the
    header the deployment is configured to trust.
    """
    settings = get_settings()
    if settings.trusted_client_ip_header:
        trusted = request.headers.get(settings.trusted_client_ip_header)
        if trusted:
            return trusted.split(",")[0].strip()

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
