"""Sign-in, sign-out and account recovery for the React application.

Everything here is the JSON face of a flow that already existed as a form post.
None of it reimplements a decision: login goes through `login_flow`, signup and
recovery through the same services the server-rendered routes call. The only
things that live here are the shape of the request, the shape of the reply, and
the cookies.

Two properties carry the weight:

  * A browser calling these is authenticated by cookie, so every mutation is
    CSRF-protected. The React client reads the double-submit cookie and echoes
    it in a header; without that header these refuse, exactly as the forms do.
  * A failure says the same thing here as it does on the rendered page. Two
    front doors giving different answers to the same wrong password is how
    somebody learns which addresses are registered.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ValidationError

from app.core.types import Tier
from app.deps import (
    AppSettings,
    CsrfProtected,
    DbSession,
    OptionalUser,
    redirect,
    set_csrf_cookie,
)
from app.logging_config import get_logger
from app.schemas import (
    CurrentAuthState,
    CurrentUserView,
    ForgotPasswordForm,
    ResetPasswordForm,
    SignupForm,
)
from app.schemas import first_error as _first_error
from app.services.auth_service import (
    AuthError,
    EmailAlreadyRegistered,
    WeakPassword,
    create_session,
    register_user,
    revoke_session,
)
from app.services.login_flow import LoginResult, attempt_login
from app.services.password_reset_service import (
    InvalidResetToken,
    complete_password_reset,
    request_password_reset,
)
from app.services.rate_limit_service import (
    bucket_for,
    check_rate_limit,
    client_ip,
    record_attempt,
)
from app.services.twofactor_service import verify_code as verify_second_factor

log = get_logger(__name__)

router = APIRouter(prefix="/api/internal/auth", tags=["internal-auth"])

#: One form-posting route, unprefixed, for the error page. Kept in this module
#: rather than in a survivor of the old auth router so that ending a session
#: has exactly one implementation.
form_router = APIRouter(tags=["internal-auth"])


# ---------------------------------------------------------------------------
# Request bodies
#
# Declared rather than read loosely from the payload, so a missing field is a
# 422 with a field name instead of a KeyError in a handler.
# ---------------------------------------------------------------------------


class LoginBody(BaseModel):
    email: str = ""
    password: str = ""
    next: str = "/dashboard"


class SecondFactorBody(BaseModel):
    code: str = ""
    next: str = "/dashboard"


class SignupBody(BaseModel):
    email: str = ""
    password: str = ""
    #: The honeypot the rendered form carries. Kept so a bot filling every
    #: field is caught on both doors rather than only the older one.
    website: str = ""


class ForgotPasswordBody(BaseModel):
    email: str = ""


class ResetPasswordBody(BaseModel):
    token: str = ""
    password: str = ""
    #: Confirmed server-side, not only in the browser. This is the one screen
    #: where a typo locks somebody out of the account they are recovering, and
    #: there is no old password left to fall back on -- so the check belongs
    #: somewhere a client cannot skip it.
    password_confirm: str = ""


def _prepare(response: Response, request: Request) -> None:
    """No shared caching, and refresh the CSRF cookie."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"
    set_csrf_cookie(response, request)


def _retry_phrase(decision) -> str:
    """ "Try again in about 4 minutes."

    A real person who mistyped their password five times sees this, and the
    only thing they need is when they can try again. Retry-After carries the
    same fact for anything automated, but a header is not an explanation.
    """
    if decision is None or not decision.retry_after_seconds:
        return "Try again shortly."
    minutes = max(1, round(decision.retry_after_seconds / 60))
    unit = "minute" if minutes == 1 else "minutes"
    return f"Try again in about {minutes} {unit}."


def _rate_limited(request: Request, headline: str, decision) -> JSONResponse:
    """A 429 that says both what happened and when to come back."""
    response = _error(
        status.HTTP_429_TOO_MANY_REQUESTS,
        "RATE_LIMITED",
        f"{headline} {_retry_phrase(decision)}",
    )
    if decision is not None and decision.retry_after_seconds:
        response.headers["Retry-After"] = str(decision.retry_after_seconds)
    _prepare(response, request)
    return response


def _error(status_code: int, code: str, message: str, **extra) -> JSONResponse:
    """The error envelope the React client already parses.

    `{"error": {"code", "message"}}` — matching what `/auth/me` returns for an
    expired session, so the client has one shape to handle rather than two.
    """
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message, **extra}},
    )


def _user_view(user) -> CurrentUserView:
    """The safe projection. The ORM object is never serialised."""
    return CurrentUserView(
        id=user.id,
        email=user.email,
        is_admin=user.is_admin,
        tier=Tier.FREE,
        account_state="active",
    )


def _authenticated(user) -> dict:
    return {
        "data": CurrentAuthState(
            authenticated=True,
            session_state="authenticated",
            user=_user_view(user),
        ).model_dump()
    }


def _set_session_cookie(response: Response, token: str, settings) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        max_age=settings.session_ttl_hours * 3600,
        # HttpOnly: no application JavaScript needs to read this, and keeping
        # it out of reach bounds what an XSS bug could steal. The React client
        # never sees the session token, only the CSRF cookie.
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.session_cookie_samesite,
        path="/",
    )


# ---------------------------------------------------------------------------
# Signing in
# ---------------------------------------------------------------------------


@router.post("/login", dependencies=[CsrfProtected])
async def login(
    request: Request,
    db: DbSession,
    settings: AppSettings,
    body: LoginBody,
) -> JSONResponse:
    """Exchange an email and password for a session cookie.

    The reply for a second-factor account is a 200 carrying
    `two_factor_required`, not an error: nothing went wrong, and the client has
    another step to take. Treating it as a failure would have the React
    boundary show "sign-in failed" to somebody whose password was correct.
    """
    outcome = await attempt_login(
        db,
        settings,
        email=body.email,
        password=body.password,
        next_path=body.next,
        client_ip=client_ip(request, settings),
        user_agent=request.headers.get("user-agent"),
    )

    if outcome.result is LoginResult.RATE_LIMITED:
        return _rate_limited(request, outcome.message, outcome.decision)

    if outcome.result is LoginResult.MALFORMED:
        response = _error(outcome.status_code, "INVALID_REQUEST", outcome.message)
        _prepare(response, request)
        return response

    if outcome.result is LoginResult.INVALID:
        response = _error(outcome.status_code, "INVALID_CREDENTIALS", outcome.message)
        _prepare(response, request)
        return response

    if outcome.result is LoginResult.CHALLENGE:
        from app.services.challenge_service import set_challenge_cookie

        response = JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "data": {
                    "authenticated": False,
                    "two_factor_required": True,
                    "next": outcome.next,
                }
            },
        )
        set_challenge_cookie(response, outcome.user)
        _prepare(response, request)
        return response

    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={**_authenticated(outcome.user), "next": outcome.next},
    )
    _set_session_cookie(response, outcome.token, settings)
    _prepare(response, request)
    log.info("auth.login_succeeded", user_id=outcome.user.id)
    return response


@router.post("/login/2fa", dependencies=[CsrfProtected])
async def second_factor(
    request: Request,
    db: DbSession,
    settings: AppSettings,
    body: SecondFactorBody,
) -> JSONResponse:
    """Complete a sign-in that is waiting on a code."""
    from app.services.challenge_service import clear_challenge_cookie, read_challenge

    user_id = read_challenge(request)
    if user_id is None:
        # Expired or absent. Deliberately not "wrong code" — the user needs to
        # start again, and saying so is the only way they would know to.
        response = _error(
            status.HTTP_401_UNAUTHORIZED,
            "CHALLENGE_EXPIRED",
            "That took too long. Sign in again.",
        )
        _prepare(response, request)
        return response

    from app.models import User

    user = await db.get(User, user_id)
    if user is None or not user.two_factor_enabled:
        response = _error(
            status.HTTP_401_UNAUTHORIZED,
            "CHALLENGE_EXPIRED",
            "That took too long. Sign in again.",
        )
        clear_challenge_cookie(response)
        _prepare(response, request)
        return response

    # The same buckets a password attempt uses, deliberately. Six digits is a
    # small space, so an unlimited prompt is a brute-force target — and a
    # bucket of its own would give an attacker who had spent the password
    # allowance a fresh budget for guessing codes.
    window = timedelta(minutes=settings.login_rate_limit_window_minutes)
    ip_bucket = bucket_for("login", "ip", client_ip(request, settings))
    account_bucket = bucket_for("login", "account", str(user_id))

    for bucket, limit in (
        (ip_bucket, settings.login_rate_limit_per_ip),
        (account_bucket, settings.login_rate_limit_per_account),
    ):
        decision = await check_rate_limit(db, bucket, limit, window)
        if not decision.allowed:
            log.warning("auth.second_factor_rate_limited", used=decision.used)
            return _rate_limited(request, "Too many attempts.", decision)

    # verify_code answers with a bool. It does not raise for a wrong code, and
    # an earlier version of this handler wrapped it in a try/except for an
    # exception that never comes — so every rejected code fell through to
    # creating a session. Read the answer.
    accepted = await verify_second_factor(db, user, body.code)
    if not accepted:
        await record_attempt(db, ip_bucket)
        await record_attempt(db, account_bucket)
        await db.commit()
        response = _error(
            status.HTTP_401_UNAUTHORIZED,
            "INVALID_CODE",
            "That code was not accepted. Check your authenticator and try again.",
        )
        _prepare(response, request)
        return response

    token = await create_session(
        db, user, request.headers.get("user-agent"), client_ip(request, settings)
    )
    await db.commit()

    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={**_authenticated(user), "next": body.next},
    )
    _set_session_cookie(response, token, settings)
    clear_challenge_cookie(response)
    _prepare(response, request)
    log.info("auth.second_factor_succeeded", user_id=user.id)
    return response


@router.post("/logout", dependencies=[CsrfProtected])
async def logout(
    request: Request,
    db: DbSession,
    settings: AppSettings,
) -> JSONResponse:
    """End this session.

    Always 200, even with no session. Signing out is idempotent, and a client
    that has already lost its cookie should still be able to reach a clean
    signed-out state rather than an error it has to special-case.
    """
    await revoke_session(db, request.cookies.get(settings.session_cookie_name))
    await db.commit()

    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "data": CurrentAuthState(
                authenticated=False, session_state="anonymous", user=None
            ).model_dump()
        },
    )
    response.delete_cookie(settings.session_cookie_name, path="/")
    _prepare(response, request)
    return response


@form_router.post("/logout", dependencies=[CsrfProtected])
async def logout_form(
    request: Request,
    db: DbSession,
    settings: AppSettings,
) -> RedirectResponse:
    """Sign out from a page that has no JavaScript.

    `error.html` is the last server-rendered page, and it exists precisely for
    the case where the React bundle did not load — so its sign-out button
    cannot be a fetch. It posts a form here and gets a redirect, which is the
    one thing that works with nothing running in the browser.

    The session-clearing itself is the same call the JSON endpoint makes, so
    there is one way to end a session and not two that can drift.
    """
    await revoke_session(db, request.cookies.get(settings.session_cookie_name))
    await db.commit()

    response = redirect("/login")
    response.delete_cookie(settings.session_cookie_name, path="/")
    _prepare(response, request)
    return response


# ---------------------------------------------------------------------------
# Creating an account
# ---------------------------------------------------------------------------


@router.post("/signup", dependencies=[CsrfProtected])
async def signup(
    request: Request,
    db: DbSession,
    settings: AppSettings,
    body: SignupBody,
    user: OptionalUser,
) -> JSONResponse:
    """Register and sign in, in one step."""
    if user is not None:
        response = _error(
            status.HTTP_409_CONFLICT,
            "ALREADY_SIGNED_IN",
            "You are already signed in.",
        )
        _prepare(response, request)
        return response

    ip_bucket = bucket_for("signup", "ip", client_ip(request, settings))
    decision = await check_rate_limit(
        db, ip_bucket, settings.signup_rate_limit_per_ip, timedelta(hours=1)
    )
    if not decision.allowed:
        log.warning("auth.signup_rate_limited", used=decision.used)
        return _rate_limited(
            request, "Too many accounts have been created from here recently.", decision
        )

    # Recorded before validation, so malformed submissions still count.
    # Otherwise the limit is bypassed by sending garbage.
    await record_attempt(db, ip_bucket)
    await db.commit()

    try:
        form = SignupForm(email=body.email, password=body.password, website=body.website)
    except ValidationError as exc:
        response = _error(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", _first_error(exc))
        _prepare(response, request)
        return response

    if form.website:
        # The honeypot was filled, so this is a bot. Answered as though it
        # worked: telling it which field gave it away only helps the next one.
        log.info("auth.signup_honeypot")
        response = JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"data": {"authenticated": False, "session_state": "anonymous", "user": None}},
        )
        _prepare(response, request)
        return response

    try:
        created = await register_user(db, form.email, form.password)
    except EmailAlreadyRegistered as exc:
        response = _error(status.HTTP_409_CONFLICT, "EMAIL_IN_USE", str(exc))
        _prepare(response, request)
        return response
    except WeakPassword as exc:
        response = _error(status.HTTP_400_BAD_REQUEST, "WEAK_PASSWORD", str(exc))
        _prepare(response, request)
        return response
    except AuthError as exc:
        response = _error(status.HTTP_400_BAD_REQUEST, "SIGNUP_FAILED", str(exc))
        _prepare(response, request)
        return response

    token = await create_session(
        db, created, request.headers.get("user-agent"), client_ip(request, settings)
    )
    await db.commit()

    response = JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={**_authenticated(created), "next": "/dashboard"},
    )
    _set_session_cookie(response, token, settings)
    _prepare(response, request)
    log.info("auth.signup_succeeded", user_id=created.id)
    return response


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------


@router.post("/forgot-password", dependencies=[CsrfProtected])
async def forgot_password(
    request: Request,
    db: DbSession,
    settings: AppSettings,
    body: ForgotPasswordBody,
) -> JSONResponse:
    """Start a password reset.

    The answer is the same whether or not the address is registered. Anything
    else turns this into a way to find out who has an account here.
    """
    ip_bucket = bucket_for("pwreset", "ip", client_ip(request, settings))
    decision = await check_rate_limit(
        db, ip_bucket, settings.password_reset_rate_limit_per_ip, timedelta(hours=1)
    )

    same_answer = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "data": {
                "sent": True,
                "message": "If that address has an account, a reset link is on its way.",
            }
        },
    )

    if not decision.allowed:
        # A 429 here, not the identical answer.
        #
        # The identical-answer rule is about known versus unknown addresses,
        # and this limit is keyed on the caller's IP — so saying "you have
        # asked too often" reveals nothing about whether any address is
        # registered. Swallowing it would hide the throttle from the one person
        # it affects most: somebody waiting for a link that is never coming.
        return _rate_limited(request, "Too many reset requests from here.", decision)

    await record_attempt(db, ip_bucket)
    await db.commit()

    try:
        form = ForgotPasswordForm(email=body.email)
    except ValidationError:
        # Not reported as a validation error, for the same reason as above: a
        # different answer for a malformed address is still a different answer.
        _prepare(same_answer, request)
        return same_answer

    await request_password_reset(db, form.email)
    await db.commit()

    _prepare(same_answer, request)
    return same_answer


@router.post("/reset-password", dependencies=[CsrfProtected])
async def reset_password(
    request: Request,
    db: DbSession,
    body: ResetPasswordBody,
) -> JSONResponse:
    """Finish a password reset."""
    try:
        form = ResetPasswordForm(
            token=body.token,
            password=body.password,
            password_confirm=body.password_confirm,
        )
    except ValidationError as exc:
        response = _error(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", _first_error(exc))
        _prepare(response, request)
        return response

    try:
        await complete_password_reset(db, form.token, form.password)
    except InvalidResetToken as exc:
        response = _error(status.HTTP_400_BAD_REQUEST, "INVALID_TOKEN", str(exc))
        _prepare(response, request)
        return response
    except WeakPassword as exc:
        response = _error(status.HTTP_400_BAD_REQUEST, "WEAK_PASSWORD", str(exc))
        _prepare(response, request)
        return response

    await db.commit()

    # Deliberately not signed in afterwards. Completing a reset proves control
    # of the mailbox, not of the account, and every other session was revoked —
    # so the next step is a normal sign-in with the new password.
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"data": {"reset": True, "message": "Password changed. Sign in with it."}},
    )
    _prepare(response, request)
    return response
