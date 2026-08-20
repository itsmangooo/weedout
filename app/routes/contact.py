"""The contact / bug-report form.

Public on purpose, and not tier-gated. The two reports most worth having --
"I cannot sign up" and "I cannot log in" -- come from people who by definition
cannot authenticate, so an account requirement here would filter out exactly
the messages that matter most.

Rate limited per IP rather than per account, for the same reason.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Form, Request
from pydantic import ValidationError

from app.config import get_settings
from app.deps import CsrfProtected, DbSession, OptionalUser
from app.logging_config import get_logger
from app.schemas import ContactForm
from app.schemas import first_error as _first_error
from app.services.contact_service import ContactError, submit_message
from app.services.rate_limit_service import check_rate_limit, client_ip, record_attempt
from app.templating import render

log = get_logger(__name__)

router = APIRouter(tags=["contact"])

#: Messages per IP per hour. Generous for a person, tedious for a script.
CONTACT_LIMIT = 8
CONTACT_WINDOW = timedelta(hours=1)


def _page(
    request: Request,
    user,
    *,
    status_code: int = 200,
    **extra: Any,
):
    return render(
        request,
        "contact.html",
        {
            "page_title": "Contact",
            # Prefilled and fixed when we know who it is, so nobody types an
            # address we are going to ignore in favour of the session's.
            "known_email": user.email if user else "",
            **extra,
        },
        status_code=status_code,
    )


@router.get("/contact")
async def contact_form(request: Request, user: OptionalUser):
    return _page(request, user)


@router.post("/contact", dependencies=[CsrfProtected])
async def contact_submit(
    request: Request,
    db: DbSession,
    user: OptionalUser,
    message: Annotated[str, Form()] = "",
    category: Annotated[str, Form()] = "",
    email: Annotated[str, Form()] = "",
):
    typed = {"message": message, "category": category, "email": email}
    ip = client_ip(request, get_settings())
    bucket = f"contact:{ip}"

    decision = await check_rate_limit(db, bucket, limit=CONTACT_LIMIT, window=CONTACT_WINDOW)
    if not decision.allowed:
        return _page(
            request,
            user,
            status_code=429,
            values=typed,
            error=(
                "That is a lot of messages in one hour. Give it a little while, "
                "or email us directly if it is urgent."
            ),
        )

    try:
        form = ContactForm(message=message, category=category, email=email)
    except ValidationError as exc:
        return _page(request, user, status_code=400, values=typed, error=_first_error(exc))

    # An anonymous sender has to give us somewhere to reply.
    address = user.email if user else form.email
    if not user and ("@" not in address or "." not in address.rpartition("@")[2]):
        return _page(
            request,
            user,
            status_code=400,
            values=typed,
            error="We need an address to reply to.",
        )

    await record_attempt(db, bucket)

    try:
        await submit_message(
            db,
            email=address,
            message=form.message,
            category=form.category,
            user=user,
            page_url=request.headers.get("referer"),
            user_agent=request.headers.get("user-agent"),
            ip_address=ip,
        )
    except ContactError as exc:
        return _page(request, user, status_code=400, values=typed, error=str(exc))

    log.info("contact.received", authenticated=bool(user), category=form.category.value)
    return _page(request, user, sent=True, sent_to=address)
