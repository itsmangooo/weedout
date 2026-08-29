"""Pricing, the CLI page, docs and contact, for the React application.

All public. These are the pages a stranger reads before there is an account,
so nothing here needs a session — the one exception is that a signed-in sender
does not have to type their address into the contact form, because we already
know it and a typed one could be anybody's.

Two things are fetched rather than written down. The CLI's version and its
dependency list come from the release feed and go.mod, because a hardcoded
claim on a page about dependency honesty is the worst possible thing to let go
stale; both degrade to "unavailable" rather than to a confident old answer.
And the plan table comes from app/tiers.py, the same module the limits are
enforced from, so the page cannot promise something the product does not do.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import ValidationError

from app.config import get_settings
from app.content.legal import PRIVACY, TERMS
from app.core.types import Tier
from app.deps import CsrfProtected, DbSession, OptionalUser
from app.logging_config import get_logger
from app.schemas import ContactForm
from app.schemas import first_error as _first_error
from app.services.cli_release_service import REPO as CLI_REPO
from app.services.cli_release_service import go_module, latest_release
from app.services.contact_service import submit_message
from app.services.docs_service import get_published, list_public
from app.services.rate_limit_service import check_rate_limit, client_ip, record_attempt
from app.services.status_service import public_status
from app.tiers import PLANS

log = get_logger(__name__)

router = APIRouter(prefix="/api/internal", tags=["internal-marketing"])

#: Matches the rendered contact page it replaces.
CONTACT_LIMIT = 5
CONTACT_WINDOW_HOURS = 1


def _fail(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code, detail={"error": {"code": code, "message": message}}
    )


@router.get("/pricing")
async def pricing(response: Response) -> dict:
    """The plan table, straight from the module that enforces the limits.

    Not a second copy written for the page. A pricing page that has drifted
    from the product is a promise nobody kept.
    """
    response.headers["Cache-Control"] = "public, max-age=300"

    return {
        "data": {
            "plans": [
                {
                    "id": key,
                    "name": plan.display_name,
                    "price": plan.price_label,
                    "features": list(plan.features),
                }
                for key, plan in (("free", PLANS[Tier.FREE]),)
            ]
        }
    }


@router.get("/cli")
async def cli(response: Response) -> dict:
    """Everything factual about the CLI, fetched rather than asserted."""
    response.headers["Cache-Control"] = "public, max-age=300"

    release = latest_release()
    module = go_module()

    return {
        "data": {
            "repo": CLI_REPO,
            # `available` rather than a null: both services answer with an
            # object that says the lookup failed, so the page can print
            # "unavailable" instead of an empty list that reads as "no
            # dependencies" — which on a page about dependency honesty would be
            # the worst possible way to be wrong.
            "release": {
                "available": release.available,
                "version": release.version,
                "published_at": release.published_at,
                "notes_url": release.notes_url,
                "assets": [
                    {
                        "name": asset.name,
                        "url": asset.url,
                        "platform": asset.platform,
                        "size_label": asset.size_label,
                    }
                    for asset in release.assets
                ],
            },
            "go_module": {
                "available": module.available,
                "module_path": module.module_path,
                "go_version": module.go_version,
                "dependencies": [
                    {
                        "module": dependency.module,
                        "version": dependency.version,
                        "indirect": dependency.indirect,
                    }
                    for dependency in module.dependencies
                ],
            },
        }
    }


@router.get("/status")
async def service_status(response: Response, db: DbSession) -> dict:
    """What the service can honestly say about itself, to anyone.

    Public, because the failure it reports is one users have a right to know
    about and cannot otherwise detect: a stale advisory feed breaks the promise
    without breaking a page, and every user of that ecosystem is quietly told
    they are clean.

    Cached briefly rather than computed per visitor. This is the page people
    load when they think something is wrong, which is exactly when the database
    is least able to answer six aggregates per request -- a status page that
    becomes part of the outage is worse than none.
    """
    # Short and public. A CDN or proxy holding this for a minute is the
    # intended behaviour, not a compromise.
    response.headers["Cache-Control"] = "public, max-age=60"

    current = await public_status(db)

    return {
        "data": {
            "state": current.state,
            "checked_at": current.checked_at,
            "feeds": [
                {
                    "label": feed.label,
                    "hours_behind": feed.hours_behind,
                    "stale_after_hours": feed.stale_after_hours,
                    "record_count": feed.record_count,
                    "is_stale": feed.is_stale,
                }
                for feed in current.feeds
            ],
            "scans_24h": current.scans_24h,
            "advisories": current.advisories,
            # Null unless the deployment publishes them. The page renders the
            # section only when both are present, rather than showing a zero
            # that reads as "nobody uses this".
            "accounts": current.accounts,
            "projects": current.projects,
        }
    }


@router.get("/docs")
async def docs_index(response: Response, db: DbSession) -> dict:
    response.headers["Cache-Control"] = "public, max-age=120"

    return {
        "data": {
            "pages": [
                {"slug": page.slug, "title": page.title, "summary": page.summary}
                for page in await list_public(db)
            ]
        }
    }


@router.get("/docs/{slug}")
async def docs_page(response: Response, db: DbSession, slug: str) -> dict:
    """One published page, rendered to HTML on the server.

    The markdown is turned into HTML here rather than in the browser: it is the
    same renderer the rendered page used, it is sanitised, and shipping a
    markdown parser to every visitor to re-do work the server already did would
    be a strange trade.
    """
    from app.markdown import render_markdown

    page = await get_published(db, slug)
    if page is None:
        # A draft and a page that does not exist answer identically, which is
        # what makes "unpublished" mean anything.
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That page doesn't exist.")

    response.headers["Cache-Control"] = "public, max-age=120"

    return {
        "data": {
            "slug": page.slug,
            "title": page.title,
            "summary": page.summary,
            "body_html": render_markdown(page.content),
            "updated_at": page.updated_at,
        },
        "pages": [{"slug": entry.slug, "title": entry.title} for entry in await list_public(db)],
    }


#: The two legal pages, by the slug their URL uses.
_LEGAL = {"terms": ("Terms of service", TERMS), "privacy": ("Privacy policy", PRIVACY)}


@router.get("/legal/{slug}")
async def legal(response: Response, slug: str) -> dict:
    """The terms, or the privacy policy.

    Served from the repository rather than the database. They change rarely,
    and when they do the change should go through review like any other change
    to what the product promises -- and `git log` is then the version history,
    which matters because "what did the privacy policy say when I signed up?"
    is a question somebody may ask in earnest.
    """
    from app.markdown import render_markdown

    entry = _LEGAL.get(slug)
    if entry is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That page doesn't exist.")

    title, body = entry

    # Cacheable and public. Nothing here varies by visitor, and these are
    # exactly the pages somebody links to.
    response.headers["Cache-Control"] = "public, max-age=600"

    return {
        "data": {
            "slug": slug,
            "title": title,
            "body_html": render_markdown(body),
        }
    }


@router.post("/contact", dependencies=[CsrfProtected])
async def contact(request: Request, db: DbSession, user: OptionalUser, body: dict) -> dict:
    """Send a message.

    Rate limited per address, because a form that emails an operator is a
    weapon pointed at that operator's inbox.
    """
    from datetime import timedelta

    settings = get_settings()
    ip = client_ip(request, settings)
    bucket = f"contact:{ip}"

    decision = await check_rate_limit(
        db, bucket, limit=CONTACT_LIMIT, window=timedelta(hours=CONTACT_WINDOW_HOURS)
    )
    if not decision.allowed:
        raise _fail(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            "That is a lot of messages in one hour. Give it a little while, or email "
            "us directly if it is urgent.",
        )

    try:
        form = ContactForm(
            message=str(body.get("message", "")),
            category=str(body.get("category", "")),
            email=str(body.get("email", "")),
        )
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", _first_error(exc)) from None

    # A signed-in sender's address comes from their session, never the form:
    # a typed one could be anybody's, and a reply going to the wrong person is
    # worse than no reply.
    address = user.email if user else form.email
    if not user and ("@" not in address or "." not in address.rpartition("@")[2]):
        raise _fail(
            status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", "We need an address to reply to."
        )

    await record_attempt(db, bucket)

    await submit_message(
        db,
        email=address,
        category=form.category,
        message=form.message,
        # The user object, not an id: the service reads the account off it to
        # attribute the message, and passing an id would be a second way to say
        # the same thing.
        user=user,
        user_agent=request.headers.get("user-agent"),
        ip_address=ip,
    )
    await db.commit()

    return {
        "data": {
            "sent": True,
            "message": "Thanks — that reached us. We reply to everything, usually within a day.",
        }
    }
