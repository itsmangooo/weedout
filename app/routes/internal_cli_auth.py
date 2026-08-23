"""Approving a `weedout auth` request from the browser.

Session-authenticated and CSRF-protected, which is the half of the flow that
carries the authorisation. The terminal proves it started the request; the
browser proves who is approving it.

CSRF matters more here than almost anywhere else in the application. Without
it, a page somebody visits while signed in could approve a login request an
attacker started, and hand that attacker a credential for the account — with no
sign of it in the interface beyond a token in a list nobody reads.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from app.deps import CsrfProtected, CurrentInternalUser, DbSession
from app.logging_config import get_logger
from app.services.cli_auth_service import (
    CliAuthError,
    approve,
    deny,
    find_pending,
    list_tokens,
    revoke_token,
)

router = APIRouter(prefix="/api/internal", tags=["internal-cli-auth"])

log = get_logger(__name__)


def _fail(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


class CodeBody(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    code: str = Field(default="", max_length=32)


@router.get("/cli-auth/{code}")
async def pending_request(
    response: Response, db: DbSession, user: CurrentInternalUser, code: str
) -> dict:
    """What the approval page shows before anybody clicks anything.

    Signed in, because the page it feeds asks somebody to grant a credential
    for their account and there is no version of that worth showing to a
    stranger.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"

    request = await find_pending(db, code)
    if request is None:
        # Expired, already approved and already denied all read the same. The
        # distinctions only help somebody sweeping the code space.
        raise _fail(
            status.HTTP_404_NOT_FOUND,
            "NOT_FOUND",
            "That code is not waiting for approval. It may have expired — codes last "
            "ten minutes. Run the command again to get a new one.",
        )

    return {
        "data": {
            "code": request.user_code,
            # Both untrusted, both shown, and the page says so. They are the
            # signals a person uses to notice a request that is not theirs.
            "device_label": request.device_label,
            "ip_address": request.ip_address,
            "requested_at": request.created_at,
            "expires_at": request.expires_at,
        }
    }


@router.post("/cli-auth/approve", dependencies=[CsrfProtected])
async def approve_request(db: DbSession, user: CurrentInternalUser, body: CodeBody) -> dict:
    """Grant the waiting terminal a credential for this account."""
    request = await find_pending(db, body.code)
    if request is None:
        raise _fail(
            status.HTTP_404_NOT_FOUND,
            "NOT_FOUND",
            "That code is no longer waiting for approval.",
        )

    try:
        await approve(db, request, user)
    except CliAuthError as exc:
        raise _fail(status.HTTP_409_CONFLICT, "NOT_PENDING", str(exc)) from None

    await db.commit()
    return {"data": {"approved": True}}


@router.post("/cli-auth/deny", dependencies=[CsrfProtected])
async def deny_request(db: DbSession, user: CurrentInternalUser, body: CodeBody) -> dict:
    """Refuse it, so the waiting terminal stops now rather than timing out."""
    request = await find_pending(db, body.code)
    if request is None:
        raise _fail(
            status.HTTP_404_NOT_FOUND,
            "NOT_FOUND",
            "That code is no longer waiting for approval.",
        )

    try:
        await deny(db, request)
    except CliAuthError as exc:
        raise _fail(status.HTTP_409_CONFLICT, "NOT_PENDING", str(exc)) from None

    await db.commit()
    return {"data": {"denied": True}}


@router.get("/cli-tokens")
async def signed_in_machines(response: Response, db: DbSession, user: CurrentInternalUser) -> dict:
    """Which machines hold a credential for this account.

    The other half of the flow being worth anything. A login you can grant and
    cannot see afterwards is a login you cannot take back.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"

    return {
        "data": [
            {
                "id": token.id,
                "prefix": token.prefix,
                "device_label": token.device_label,
                "created_at": token.created_at,
                "last_used_at": token.last_used_at,
                "expires_at": token.expires_at,
            }
            for token in await list_tokens(db, user.id)
        ]
    }


@router.post("/cli-tokens/{token_id}/revoke", dependencies=[CsrfProtected])
async def revoke_machine(db: DbSession, user: CurrentInternalUser, token_id: int) -> dict:
    if not await revoke_token(db, user.id, token_id):
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That machine isn't signed in.")

    await db.commit()
    return {"data": {"revoked": True}}


__all__ = ["router"]
