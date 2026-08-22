"""Account settings, for the React application.

Alert preferences, password, sessions, two-factor and account-wide API keys.

Everything here goes through the services the rendered page used. In
particular the two-factor flow is untouched: `begin_setup` holds an
unconfirmed secret, `confirm_setup` promotes it only on a correct code, and
`verify_code` carries the replay guard. None of that is re-implemented, because
the second factor is the control that survives a stolen password and a second
copy of it would be a second thing to get subtly wrong.

One shape worth noting: nothing here returns a secret twice. A TOTP secret is
in the response that starts setup and nowhere else; backup codes are in the
response that generates them and nowhere else; a new API key's plaintext is in
the response that mints it. The rendered page had the same property, for the
same reason — a secret that can be re-read is a secret that lives in whatever
cache, history or log touched the page.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ValidationError

from app.core.totp import provisioning_uri
from app.core.types import KeyScope
from app.deps import CsrfProtected, CurrentInternalUser, DbSession
from app.logging_config import get_logger
from app.schemas import AlertPreferencesForm, ApiKeyForm, ChangePasswordForm, first_error
from app.security import hash_session_token, verify_password
from app.services.api_key_service import ApiKeyError, issue_api_key, keys_for_user, revoke_api_key
from app.services.auth_service import (
    AuthError,
    active_sessions,
    change_password,
    revoke_session_by_id,
    revoke_sessions_except,
)
from app.services.target_service import get_target_for_user, list_targets
from app.services.twofactor_service import ISSUER as TOTP_ISSUER
from app.services.twofactor_service import (
    TwoFactorError,
    backup_code_status,
    begin_setup,
    confirm_setup,
    qr_svg,
    regenerate_backup_codes,
)
from app.services.twofactor_service import disable as disable_two_factor_for

log = get_logger(__name__)

router = APIRouter(prefix="/api/internal", tags=["internal-settings"])


def _fail(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code, detail={"error": {"code": code, "message": message}}
    )


def _current_session_hash(request: Request) -> str | None:
    """The stored hash of the session this request arrived on.

    Used to mark "this device" in the list and to avoid signing yourself out
    when you meant to sign out everything else. Hashed here so the plaintext
    token never reaches a response body.
    """
    from app.config import get_settings

    token = request.cookies.get(get_settings().session_cookie_name)
    return hash_session_token(token) if token else None


@router.get("/settings")
async def settings(
    request: Request, response: Response, db: DbSession, user: CurrentInternalUser
) -> dict:
    """Everything the settings page shows, in one response."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"

    unused_codes, total_codes = await backup_code_status(db, user)
    current = _current_session_hash(request)

    return {
        "data": {
            "email": user.email,
            "tier": str(user.tier),
            "is_admin": user.is_admin,
            "email_alerts": user.email_alerts_enabled,
            "two_factor_enabled": user.two_factor_enabled,
            "backup_codes_unused": unused_codes,
            "backup_codes_total": total_codes,
        },
        "projects": [
            {"id": summary.target.id, "name": summary.target.name}
            for summary in await list_targets(db, user.id)
        ],
        "api_keys": [
            {
                "id": key.id,
                "prefix": key.prefix,
                "name": key.name,
                "scope": key.scope.value,
                "project": ({"id": key.target.id, "name": key.target.name} if key.target else None),
                "created_at": key.created_at,
                "last_used_at": key.last_used_at,
                "call_count": key.call_count,
                "is_active": key.is_active,
                "revoked_at": key.revoked_at,
            }
            for key in await keys_for_user(db, user)
        ],
        "sessions": [
            {
                "id": session.id,
                "user_agent": session.user_agent,
                "ip_address": session.ip_address,
                "created_at": session.created_at,
                "last_seen_at": session.last_seen_at,
                # Marked rather than hidden: somebody signing out everything
                # else needs to know which row is the one they are sitting at.
                "is_current": current is not None and session.token_hash == current,
            }
            for session in await active_sessions(db, user)
        ],
    }


# ---------------------------------------------------------------------------
# Preferences
# ---------------------------------------------------------------------------


class AlertsBody(BaseModel):
    email_alerts: bool = False


@router.post("/settings/alerts", dependencies=[CsrfProtected])
async def update_alerts(db: DbSession, user: CurrentInternalUser, body: AlertsBody) -> dict:
    try:
        form = AlertPreferencesForm(email_alerts_enabled=body.email_alerts)
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None

    user.email_alerts_enabled = form.email_alerts_enabled
    await db.commit()
    return {"data": {"email_alerts": user.email_alerts_enabled}}


class PasswordBody(BaseModel):
    current_password: str = ""
    new_password: str = ""


@router.post("/settings/password", dependencies=[CsrfProtected])
async def update_password(
    request: Request, db: DbSession, user: CurrentInternalUser, body: PasswordBody
) -> dict:
    """Change the password, keeping this session and ending the others.

    `change_password` revokes every session for the account. Reissuing this one
    afterwards is what stops somebody being signed out of the page they just
    used to change it — while anyone else holding a session is still ejected,
    which is the point of revoking them.
    """
    from app.config import get_settings
    from app.services.auth_service import create_session

    try:
        form = ChangePasswordForm(
            current_password=body.current_password, new_password=body.new_password
        )
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None

    try:
        await change_password(db, user, form.current_password, form.new_password)
    except AuthError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "REJECTED", str(exc)) from None

    settings_ = get_settings()
    token = await create_session(db, user, request.headers.get("user-agent"), None)
    await db.commit()

    from fastapi.responses import JSONResponse

    response = JSONResponse(
        content={
            "data": {
                "changed": True,
                "message": "Password changed. Other sessions were signed out.",
            }
        }
    )
    response.set_cookie(
        settings_.session_cookie_name,
        token,
        max_age=settings_.session_ttl_hours * 3600,
        httponly=True,
        secure=settings_.cookie_secure,
        samesite=settings_.session_cookie_samesite,
        path="/",
    )
    return response


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


@router.post("/settings/sessions/{session_id}/revoke", dependencies=[CsrfProtected])
async def revoke_one_session(db: DbSession, user: CurrentInternalUser, session_id: int) -> dict:
    revoked = await revoke_session_by_id(db, user, session_id)
    if revoked is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That session doesn't exist.")

    await db.commit()
    return {"data": {"revoked": True}}


@router.post("/settings/sessions/revoke-others", dependencies=[CsrfProtected])
async def revoke_other_sessions(request: Request, db: DbSession, user: CurrentInternalUser) -> dict:
    """Sign out everywhere except here.

    The current session is passed in by hash so it survives. Without that this
    would sign the caller out of the page they clicked it on, which reads as a
    bug rather than as the security action it is.
    """
    count = await revoke_sessions_except(db, user, _current_session_hash(request))
    await db.commit()
    return {"data": {"revoked": count}}


# ---------------------------------------------------------------------------
# Two-factor
# ---------------------------------------------------------------------------


@router.post("/settings/2fa/start", dependencies=[CsrfProtected])
async def start_two_factor(db: DbSession, user: CurrentInternalUser) -> dict:
    """Begin setup: an unconfirmed secret, a QR code, and backup codes.

    The secret is not active yet. It becomes the account's second factor only
    when a correct code proves the authenticator actually holds it — otherwise
    a mis-scanned QR would lock somebody out of their own account.
    """
    try:
        offer = await begin_setup(db, user)
    except TwoFactorError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "REJECTED", str(exc)) from None

    await db.commit()

    uri = provisioning_uri(offer.secret, account=user.email, issuer=TOTP_ISSUER)
    return {
        "data": {
            # Shown once, here. Never returned again — only the confirmed state
            # is readable afterwards.
            "secret": offer.secret,
            "uri": uri,
            "qr_svg": qr_svg(uri),
        }
    }


class CodeBody(BaseModel):
    code: str = ""


@router.post("/settings/2fa/confirm", dependencies=[CsrfProtected])
async def confirm_two_factor(db: DbSession, user: CurrentInternalUser, body: CodeBody) -> dict:
    try:
        generated = await confirm_setup(db, user, body.code)
    except TwoFactorError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_CODE", str(exc)) from None

    await db.commit()
    log.info("twofactor.enabled", user_id=user.id)

    # The backup codes arrive here rather than at setup, which is the right
    # moment: they are the way back in once the factor is actually on, and
    # handing them out before it is confirmed would leave a set in circulation
    # for an account that never enabled anything. Shown once.
    return {"data": {"two_factor_enabled": True, "backup_codes": list(generated.codes)}}


@router.post("/settings/2fa/codes", dependencies=[CsrfProtected])
async def new_backup_codes(db: DbSession, user: CurrentInternalUser) -> dict:
    """Replace the backup codes.

    Every previous code stops working. Shown once, here — they are the way back
    in when the authenticator is gone, so a set that could be re-read from the
    page would be a set sitting in a browser cache.
    """
    if not user.two_factor_enabled:
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "NOT_ENABLED",
            "Two-factor is not switched on for this account.",
        )

    generated = await regenerate_backup_codes(db, user)
    await db.commit()
    return {"data": {"backup_codes": list(generated.codes)}}


class DisableBody(BaseModel):
    password: str = ""


@router.post("/settings/2fa/disable", dependencies=[CsrfProtected])
async def disable_two_factor(db: DbSession, user: CurrentInternalUser, body: DisableBody) -> dict:
    """Turn the second factor off, on proof of the password.

    Asking for the password is the point: a session left open on a shared
    machine must not be enough to remove the control that protects the account
    when a password leaks.
    """
    # The password is checked here, not in the service — `disable` takes only
    # the account and destroys the secret unconditionally. An earlier version
    # of this handler passed the password to it and assumed it was verified,
    # which raised rather than silently skipping the check; had the signature
    # happened to accept and ignore it, a borrowed session would have been
    # enough to strip the second factor.
    if not user.password_hash or not verify_password(body.password, user.password_hash):
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "REJECTED",
            "That password isn't right. Two-factor is still on.",
        )

    await disable_two_factor_for(db, user)
    await db.commit()
    log.info("twofactor.disabled", user_id=user.id)
    return {"data": {"two_factor_enabled": False}}


# ---------------------------------------------------------------------------
# Account-wide API keys
# ---------------------------------------------------------------------------


class NewKeyBody(BaseModel):
    target_id: int | None = None
    name: str = ""
    scope: str = KeyScope.SCAN.value


@router.post("/settings/api-keys", dependencies=[CsrfProtected])
async def create_key(db: DbSession, user: CurrentInternalUser, body: NewKeyBody) -> dict:
    try:
        form = ApiKeyForm(target_id=body.target_id, name=body.name, scope=body.scope)
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None

    target = await get_target_for_user(db, user.id, form.target_id)
    if target is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That project could not be found.")

    try:
        issued = await issue_api_key(db, user, target, form.name, scope=form.scope)
    except ApiKeyError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "KEY_REFUSED", str(exc)) from None

    await db.commit()
    return {
        "data": {
            "id": issued.record.id,
            "prefix": issued.record.prefix,
            "scope": issued.record.scope.value,
            # Once. Only the hash is stored.
            "token": issued.token,
        }
    }


@router.post("/settings/api-keys/{key_id}/revoke", dependencies=[CsrfProtected])
async def revoke_key(db: DbSession, user: CurrentInternalUser, key_id: int) -> dict:
    if not await revoke_api_key(db, user, key_id):
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That key doesn't exist.")

    await db.commit()
    return {"data": {"revoked": True}}
