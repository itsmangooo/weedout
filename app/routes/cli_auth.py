"""The two unauthenticated halves of `weedout auth`.

These sit apart from `/api/v1/*` deliberately. Everything under that prefix is
bearer-key authenticated and asserted to be so by `test_route_authorization`;
these two endpoints exist precisely because the caller has no credential yet,
and mixing them into that namespace would mean weakening the assertion that
protects everything else in it.

What stands in for authentication here is the rest of the design: a start that
writes one short-lived row and is rate limited by IP, and a poll that requires
a 256-bit secret only the process that started the request has ever held.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from app.config import get_settings
from app.deps import DbSession
from app.logging_config import get_logger
from app.services.cli_auth_service import (
    POLL_INTERVAL_SECONDS,
    CliAuthError,
    collect,
    start_request,
)
from app.services.rate_limit_service import check_rate_limit, client_ip, record_attempt

router = APIRouter(prefix="/api/cli-auth", tags=["cli-auth"])

log = get_logger(__name__)

#: Starting a login writes a row from an unauthenticated caller, so the ceiling
#: is low. Ten an hour from one address is far more than a person needs and far
#: less than a script would want.
START_LIMIT = 10
START_WINDOW = timedelta(hours=1)

#: Polling is cheap but unbounded in principle. This allows a client polling at
#: the advertised interval for the full approval window, several times over,
#: while stopping one that ignores the interval entirely.
POLL_LIMIT = 400
POLL_WINDOW = timedelta(hours=1)


def _fail(status_code: int, code: str, message: str, **extra) -> HTTPException:
    return HTTPException(
        status_code=status_code, detail={"error": code, "message": message, **extra}
    )


class StartBody(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    #: What the machine calls itself, shown on the approval page so somebody
    #: can tell their own laptop from a request they did not make. Untrusted
    #: display text and nothing more.
    device_label: str = Field(default="", max_length=120)


class PollBody(BaseModel):
    device_code: str = Field(default="", max_length=200)


@router.post("/start")
async def start(request: Request, response: Response, db: DbSession, body: StartBody) -> dict:
    """Begin a login. Returns a code to read and a secret to poll with."""
    response.headers["Cache-Control"] = "no-store"

    settings = get_settings()
    address = client_ip(request, settings)
    bucket = f"cli_auth_start:{address}"
    allowance = await check_rate_limit(db, bucket, START_LIMIT, START_WINDOW)
    if not allowance.allowed:
        raise _fail(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too_many_requests",
            "Too many login attempts from this address. Try again shortly.",
            retry_after=allowance.retry_after_seconds,
        )
    await record_attempt(db, bucket)

    try:
        started = await start_request(db, device_label=body.device_label, ip_address=address)
    except CliAuthError as exc:
        raise _fail(status.HTTP_503_SERVICE_UNAVAILABLE, "unavailable", str(exc)) from None

    await db.commit()

    base = settings.base_url.rstrip("/")
    return {
        "user_code": started.user_code,
        # Carries the code so the browser can pre-fill it. The person still
        # compares what the page shows against what their terminal shows --
        # that comparison is the security property, and a pre-filled field
        # does not weaken it as long as the page displays the code back.
        "verification_url": f"{base}/cli-auth?code={started.user_code}",
        # Without the code, for anybody who would rather type it themselves.
        "verification_url_plain": f"{base}/cli-auth",
        "device_code": started.device_code,
        "expires_in": started.expires_in,
        "interval": started.interval,
    }


@router.post("/poll")
async def poll(request: Request, response: Response, db: DbSession, body: PollBody) -> dict:
    """Has it been approved yet? Returns the token once, if so."""
    response.headers["Cache-Control"] = "no-store"

    bucket = f"cli_auth_poll:{client_ip(request, get_settings())}"
    allowance = await check_rate_limit(db, bucket, POLL_LIMIT, POLL_WINDOW)
    if not allowance.allowed:
        raise _fail(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too_many_requests",
            "Polling too fast. Wait a moment and try again.",
            retry_after=allowance.retry_after_seconds,
        )
    await record_attempt(db, bucket)

    outcome = await collect(db, body.device_code)
    await db.commit()

    if outcome.state == "approved":
        return {
            "state": "approved",
            # Once. Only the hash is stored, and the request is marked
            # collected so a replayed device code gets nothing.
            "token": outcome.token,
            "email": outcome.email,
        }

    # Pending, denied and expired all come back 200 with a state. A poll that
    # has not been approved yet is not an error, and a CLI branching on HTTP
    # status would have to treat "wait" and "something is wrong" alike.
    return {"state": outcome.state, "interval": POLL_INTERVAL_SECONDS}


__all__ = ["router"]
