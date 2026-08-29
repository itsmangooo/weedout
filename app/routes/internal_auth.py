"""Cookie-authenticated JSON boundary for the React application.

This namespace is intentionally separate from ``/api/v1``. Browser requests
use the existing opaque session cookie and CSRF protection; public and CLI
requests continue to use bearer API keys and never read browser cookies.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse

from app.core.types import Tier
from app.deps import AppSettings, OptionalUser, set_csrf_cookie
from app.schemas import CurrentAuthResponse, CurrentAuthState, CurrentUserView

router = APIRouter(prefix="/api/internal/auth", tags=["internal-auth"])


def _prepare_response(response: Response, request: Request) -> None:
    """Prevent shared caching and bootstrap the double-submit CSRF cookie."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"
    set_csrf_cookie(response, request)


@router.get(
    "/me",
    response_model=CurrentAuthResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "description": "A session cookie was present but is no longer valid."
        }
    },
)
async def current_user(
    request: Request,
    response: Response,
    settings: AppSettings,
    user: OptionalUser,
) -> CurrentAuthResponse | JSONResponse:
    """Return the current browser identity without ever serializing the ORM.

    No cookie is a normal anonymous bootstrap and therefore returns 200. A
    cookie that no longer resolves is a distinct 401 so the React boundary can
    explain that an existing session expired rather than showing a generic
    signed-out state. Revoked, expired, malformed, suspended, and deactivated
    sessions deliberately share that response.
    """
    _prepare_response(response, request)

    if user is None:
        if request.cookies.get(settings.session_cookie_name):
            expired = JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": {
                        "code": "SESSION_EXPIRED",
                        "message": "Your session has expired. Sign in again.",
                    }
                },
            )
            expired.delete_cookie(
                settings.session_cookie_name,
                path="/",
                secure=settings.cookie_secure,
                httponly=True,
                samesite=settings.session_cookie_samesite,
            )
            _prepare_response(expired, request)
            return expired

        return CurrentAuthResponse(
            data=CurrentAuthState(
                authenticated=False,
                session_state="anonymous",
                user=None,
            )
        )

    safe_user = CurrentUserView(
        id=user.id,
        email=user.email,
        is_admin=user.is_admin,
        tier=Tier.FREE,
        account_state="active",
    )
    return CurrentAuthResponse(
        data=CurrentAuthState(
            authenticated=True,
            session_state="authenticated",
            user=safe_user,
        )
    )
