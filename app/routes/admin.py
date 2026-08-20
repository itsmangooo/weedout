"""Administrative routes.

Every route in this module is behind `require_admin`, applied once at the router
level rather than per-handler so a new endpoint cannot be added without it.
There is no path through this file that a non-admin can reach.

Handlers stay thin: validate input into a Pydantic model, call
`app.services.admin_service`, render. All queries and all mutations live in the
service, so this file is a readable inventory of what an administrator can do.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from pydantic import ValidationError

from app.charts import build_signup_chart
from app.config import get_settings
from app.core.types import MessageStatus, Tier
from app.deps import CsrfProtected, CurrentAdmin, DbSession, redirect, require_admin
from app.logging_config import get_logger
from app.models import ContactMessage
from app.schemas import (
    ContactStatusForm,
    DeleteUserForm,
    DocPageForm,
    SignupChartQuery,
    SuspendForm,
    TierChangeForm,
    UserListQuery,
)
from app.schemas import (
    first_error as _first_error,
)
from app.services.admin_service import (
    AdminActionError,
    change_user_tier,
    delete_user,
    feed_health,
    list_subscribers,
    list_users,
    platform_metrics,
    recent_audit_entries,
    record_audit,
    revenue_snapshot,
    signups_over_time,
    suspend_user,
    unsuspend_user,
    user_detail,
)
from app.services.contact_service import (
    count_unread,
    list_messages,
    mark_status,
)
from app.services.docs_service import (
    DocsError,
)
from app.services.docs_service import (
    create_page as create_doc_page,
)
from app.services.docs_service import (
    delete_page as delete_doc_page,
)
from app.services.docs_service import (
    get_by_id as get_doc_page,
)
from app.services.docs_service import (
    list_all as docs_list_all,
)
from app.services.docs_service import (
    update_page as update_doc_page,
)
from app.templating import render

log = get_logger(__name__)

# The dependency is declared on the router, so it applies to every route
# defined below — including any added later without a second thought.
router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


# ---------------------------------------------------------------------------
# Overview / metrics
# ---------------------------------------------------------------------------


@router.get("")
async def overview(
    request: Request,
    db: DbSession,
    admin: CurrentAdmin,
    # Taken as a string so the Pydantic model owns coercion *and* the fallback.
    # Declaring it `int` would let FastAPI 422 on `?days=abc` before this
    # handler runs, and a hand-edited URL should show the default page rather
    # than an error.
    days: Annotated[str, Query()] = "30",
):
    """Platform metrics, feed health and the signup trend."""
    try:
        chart_query = SignupChartQuery(days=days)
    except ValidationError:
        chart_query = SignupChartQuery()

    metrics = await platform_metrics(db)
    feeds = await feed_health(db)
    signups = await signups_over_time(db, chart_query.days)

    return render(
        request,
        "admin/overview.html",
        {
            "page_title": "Admin",
            "admin_section": "overview",
            "metrics": metrics,
            "feeds": feeds,
            "signups": signups,
            "chart": build_signup_chart(signups),
            "chart_days": chart_query.days,
        },
    )


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@router.get("/users")
async def users_index(
    request: Request,
    db: DbSession,
    admin: CurrentAdmin,
    # All taken as strings for the same reason as `days` above: the Pydantic
    # model is the single validator, and it can fall back where FastAPI's own
    # coercion would only reject.
    page: Annotated[str, Query()] = "1",
    per_page: Annotated[str, Query()] = "25",
    search: Annotated[str, Query()] = "",
    tier: Annotated[str, Query()] = "",
    status: Annotated[str, Query()] = "",
):
    """Paginated, searchable user list.

    Bad query parameters fall back to defaults rather than returning a 422:
    someone hand-editing a URL should get the first page, not an error page.
    """
    try:
        query = UserListQuery(page=page, per_page=per_page, search=search, tier=tier, status=status)
    except ValidationError:
        query = UserListQuery()

    result = await list_users(
        db,
        page=query.page,
        per_page=query.per_page,
        search=query.search_filter,
        tier=query.tier_filter,
        status=query.status_filter,
    )

    return render(
        request,
        "admin/users.html",
        {
            "page_title": "Users",
            "admin_section": "users",
            "result": result,
            "query": query,
        },
    )


@router.get("/users/{user_id}")
async def user_view(request: Request, db: DbSession, admin: CurrentAdmin, user_id: int):
    detail = await user_detail(db, user_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="No such user.")

    return render(
        request,
        "admin/user_detail.html",
        {
            "page_title": detail.user.email,
            "admin_section": "users",
            "detail": detail,
            "tiers": list(Tier),
        },
    )


@router.post("/users/{user_id}/tier", dependencies=[CsrfProtected])
async def change_tier(
    request: Request,
    db: DbSession,
    admin: CurrentAdmin,
    user_id: int,
    tier: Annotated[str, Form()] = "",
    note: Annotated[str, Form()] = "",
):
    """Manually move a user between plans."""
    target = await _load_target(db, user_id)

    try:
        form = TierChangeForm(tier=tier, note=note)
    except ValidationError:
        return await _user_view_with_error(request, db, user_id, "That isn't a valid plan.")

    try:
        await change_user_tier(
            db, admin, target, form.tier, form.note, ip_address=_client_ip(request)
        )
    except AdminActionError as exc:
        return await _user_view_with_error(request, db, user_id, str(exc))

    await db.commit()
    return redirect(f"/admin/users/{user_id}")


@router.post("/users/{user_id}/suspend", dependencies=[CsrfProtected])
async def suspend(
    request: Request,
    db: DbSession,
    admin: CurrentAdmin,
    user_id: int,
    reason: Annotated[str, Form()] = "",
):
    target = await _load_target(db, user_id)

    try:
        form = SuspendForm(reason=reason)
    except ValidationError:
        return await _user_view_with_error(request, db, user_id, "That reason was too long.")

    try:
        await suspend_user(db, admin, target, form.reason, ip_address=_client_ip(request))
    except AdminActionError as exc:
        return await _user_view_with_error(request, db, user_id, str(exc))

    await db.commit()
    return redirect(f"/admin/users/{user_id}")


@router.post("/users/{user_id}/delete", dependencies=[CsrfProtected])
async def delete_user_route(
    request: Request,
    db: DbSession,
    admin: CurrentAdmin,
    user_id: int,
    confirm_email: Annotated[str, Form()] = "",
):
    """Permanently delete an account and all of its data.

    The typed-email confirmation is enforced here, not just in the modal. The
    dialog is a courtesy; this is the check, and it is the one that still
    applies to a hand-crafted POST or a mis-aimed script.
    """
    target = await _load_target(db, user_id)

    try:
        form = DeleteUserForm(confirm_email=confirm_email)
    except ValidationError:
        return await _user_view_with_error(
            request, db, user_id, "Type the account's email address to confirm."
        )

    if form.confirm_email != target.email.strip().lower():
        return await _user_view_with_error(
            request,
            db,
            user_id,
            "That address doesn't match this account. Nothing was deleted.",
        )

    deleted_email = target.email
    try:
        removed = await delete_user(db, admin, target, ip_address=_client_ip(request))
    except AdminActionError as exc:
        return await _user_view_with_error(request, db, user_id, str(exc))

    await db.commit()
    log.info("admin.delete_completed", email=deleted_email, **removed)

    return redirect("/admin/users")


@router.post("/users/{user_id}/unsuspend", dependencies=[CsrfProtected])
async def unsuspend(request: Request, db: DbSession, admin: CurrentAdmin, user_id: int):
    target = await _load_target(db, user_id)

    try:
        await unsuspend_user(db, admin, target, ip_address=_client_ip(request))
    except AdminActionError as exc:
        return await _user_view_with_error(request, db, user_id, str(exc))

    await db.commit()
    return redirect(f"/admin/users/{user_id}")


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------


@router.get("/billing")
async def billing(request: Request, db: DbSession, admin: CurrentAdmin):
    """Revenue at a glance, from what the Dodo webhooks already stored."""
    settings = get_settings()
    return render(
        request,
        "admin/billing.html",
        {
            "page_title": "Billing",
            "admin_section": "billing",
            "snapshot": await revenue_snapshot(db),
            "subscribers": await list_subscribers(db),
            "dodo_dashboard_url": settings.dodo_dashboard_url,
            "dodo_enabled": settings.dodo_enabled,
        },
    )


# ---------------------------------------------------------------------------
# Documentation
#
# Inside the admin router, so `require_admin` covers every route below without
# a per-handler check to forget. The public read-only views live in
# `app/routes/docs.py`.
# ---------------------------------------------------------------------------


@router.get("/docs")
async def docs_index(request: Request, db: DbSession, admin: CurrentAdmin):
    return render(
        request,
        "admin/docs_list.html",
        {
            "page_title": "Docs",
            "admin_section": "docs",
            "pages": await docs_list_all(db),
        },
    )


@router.get("/docs/new")
async def docs_new(request: Request, admin: CurrentAdmin):
    return render(
        request,
        "admin/docs_edit.html",
        {"page_title": "New page", "admin_section": "docs", "page": None},
    )


@router.post("/docs", dependencies=[CsrfProtected])
async def docs_create(
    request: Request,
    db: DbSession,
    admin: CurrentAdmin,
    title: Annotated[str, Form()] = "",
    slug: Annotated[str, Form()] = "",
    summary: Annotated[str, Form()] = "",
    content: Annotated[str, Form()] = "",
    published: Annotated[str, Form()] = "",
    position: Annotated[str, Form()] = "0",
):
    try:
        form = _doc_form(title, slug, summary, content, published, position)
    except ValidationError as exc:
        return _docs_edit_with_error(request, None, _form_values(request), _first_error(exc))

    try:
        page = await create_doc_page(
            db,
            title=form.title,
            slug=form.slug,
            content=form.content,
            summary=form.summary,
            published=form.published,
            position=form.position or None,
        )
    except DocsError as exc:
        return _docs_edit_with_error(request, None, form.model_dump(), str(exc))

    await db.commit()
    record_audit(
        db, admin, "docs.created", details={"slug": page.slug}, ip_address=_client_ip(request)
    )
    await db.commit()
    return redirect("/admin/docs")


@router.get("/docs/{page_id}")
async def docs_edit(request: Request, db: DbSession, admin: CurrentAdmin, page_id: int):
    page = await get_doc_page(db, page_id)
    if page is None:
        raise HTTPException(status_code=404, detail="No such page.")

    return render(
        request,
        "admin/docs_edit.html",
        {"page_title": page.title, "admin_section": "docs", "page": page},
    )


@router.post("/docs/{page_id}", dependencies=[CsrfProtected])
async def docs_update(
    request: Request,
    db: DbSession,
    admin: CurrentAdmin,
    page_id: int,
    title: Annotated[str, Form()] = "",
    slug: Annotated[str, Form()] = "",
    summary: Annotated[str, Form()] = "",
    content: Annotated[str, Form()] = "",
    published: Annotated[str, Form()] = "",
    position: Annotated[str, Form()] = "0",
):
    page = await get_doc_page(db, page_id)
    if page is None:
        raise HTTPException(status_code=404, detail="No such page.")

    try:
        form = _doc_form(title, slug, summary, content, published, position)
    except ValidationError as exc:
        return _docs_edit_with_error(request, page, _form_values(request), _first_error(exc))

    try:
        await update_doc_page(
            db,
            page,
            title=form.title,
            slug=form.slug,
            content=form.content,
            summary=form.summary,
            published=form.published,
            position=form.position,
        )
    except DocsError as exc:
        return _docs_edit_with_error(request, page, form.model_dump(), str(exc))

    record_audit(
        db, admin, "docs.updated", details={"slug": page.slug}, ip_address=_client_ip(request)
    )
    await db.commit()
    return redirect("/admin/docs")


@router.post("/docs/{page_id}/delete", dependencies=[CsrfProtected])
async def docs_delete(request: Request, db: DbSession, admin: CurrentAdmin, page_id: int):
    page = await get_doc_page(db, page_id)
    if page is None:
        raise HTTPException(status_code=404, detail="No such page.")

    slug = page.slug
    await delete_doc_page(db, page)
    record_audit(db, admin, "docs.deleted", details={"slug": slug}, ip_address=_client_ip(request))
    await db.commit()
    return redirect("/admin/docs")


def _doc_form(
    title: str, slug: str, summary: str, content: str, published: str, position: str
) -> DocPageForm:
    try:
        parsed_position = int(position or 0)
    except (TypeError, ValueError):
        parsed_position = 0

    return DocPageForm(
        title=title,
        slug=slug,
        summary=summary,
        content=content,
        published=published == "on",
        position=parsed_position,
    )


def _form_values(request: Request) -> dict:
    """Best-effort echo of what was submitted, so a rejected edit is not lost."""
    return getattr(request.state, "submitted_doc", {}) or {}


def _docs_edit_with_error(request: Request, page, values: dict, message: str):
    return render(
        request,
        "admin/docs_edit.html",
        {
            "page_title": "Edit page",
            "admin_section": "docs",
            "page": page,
            "values": values,
            "error": message,
        },
        status_code=400,
    )


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Inbox — messages from the contact form
# ---------------------------------------------------------------------------


@router.get("/inbox")
async def inbox(
    request: Request,
    db: DbSession,
    admin: CurrentAdmin,
    show: str = Query("new"),
):
    """The contact queue.

    Defaults to unread rather than to everything, because the question this
    page exists to answer is "is anybody waiting on me?" and an all-time list
    buries that under six months of resolved threads.
    """
    status = None
    if show in {s.value for s in MessageStatus}:
        status = MessageStatus(show)
    elif show != "all":
        show = "new"
        status = MessageStatus.NEW

    page = await list_messages(db, status=status, limit=100)
    return render(
        request,
        "admin/inbox.html",
        {
            "page_title": "Inbox",
            "admin_section": "inbox",
            "messages": page.messages,
            "total": page.total,
            "unread": page.unread,
            "show": show,
        },
    )


@router.get("/inbox/{message_id}")
async def inbox_message(request: Request, db: DbSession, admin: CurrentAdmin, message_id: int):
    message = await db.get(ContactMessage, message_id)
    if message is None:
        raise HTTPException(status_code=404, detail="No such message")

    # Opening it counts as reading it. Making the admin press a second button
    # to say so would mean the unread count drifts from reality within a day.
    if message.status is MessageStatus.NEW:
        message.status = MessageStatus.READ
        await db.commit()

    return render(
        request,
        "admin/inbox_message.html",
        {
            "page_title": "Message",
            "admin_section": "inbox",
            "message": message,
            "unread": await count_unread(db),
        },
    )


@router.post("/inbox/{message_id}/status", dependencies=[CsrfProtected])
async def inbox_set_status(
    request: Request,
    db: DbSession,
    admin: CurrentAdmin,
    message_id: int,
    status: Annotated[str, Form()] = "",
    note: Annotated[str, Form()] = "",
):
    message = await db.get(ContactMessage, message_id)
    if message is None:
        raise HTTPException(status_code=404, detail="No such message")

    try:
        form = ContactStatusForm(status=status, note=note)
    except ValidationError as exc:
        return render(
            request,
            "admin/inbox_message.html",
            {
                "page_title": "Message",
                "admin_section": "inbox",
                "message": message,
                "unread": await count_unread(db),
                "error": _first_error(exc),
            },
            status_code=400,
        )

    await mark_status(db, message, form.status, admin=admin, note=form.note)
    record_audit(
        db,
        actor=admin,
        action="contact.status_changed",
        details={"message_id": message.id, "status": form.status.value},
        ip_address=_client_ip(request),
    )
    await db.commit()
    return redirect(f"/admin/inbox/{message.id}")


@router.get("/audit")
async def audit(request: Request, db: DbSession, admin: CurrentAdmin):
    return render(
        request,
        "admin/audit.html",
        {
            "page_title": "Audit log",
            "admin_section": "audit",
            "entries": await recent_audit_entries(db),
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _load_target(db, user_id: int):
    from app.models import User

    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="No such user.")
    return target


async def _user_view_with_error(request: Request, db, user_id: int, message: str):
    """Re-render the user page with an error, rather than a bare 400.

    An admin who mistypes something should land back on the page they were on,
    with the record still in front of them and the reason stated.
    """
    detail = await user_detail(db, user_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="No such user.")

    return render(
        request,
        "admin/user_detail.html",
        {
            "page_title": detail.user.email,
            "admin_section": "users",
            "detail": detail,
            "tiers": list(Tier),
            "error": message,
        },
        status_code=400,
    )
