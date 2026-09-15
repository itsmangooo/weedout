"""The admin panel, for the React application.

Every route is behind `require_internal_admin`, applied once at the router
level rather than per-handler, exactly as the rendered panel does it and for
the same reason: a handler that forgets the check is a handler nobody notices
until it matters. `tests/test_admin_access.py` sweeps every route under this
prefix and asserts a signed-in non-admin is refused by all of them, so an
endpoint added without the guard fails the suite instead of shipping.

No decision lives here. Suspension, deletion, doc edits and campaign sends all
go through the same services the rendered panel called,
which record the audit entry alongside the change — an administrative action
with no trace of who did it is worse than one that did not happen.

Two guards are re-stated in full rather than trusted to the browser, because
both are the last thing standing in front of something irreversible: the
typed-email confirmation on delete, and the confirmed recipient count on send.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ValidationError

from app.config import get_settings
from app.core.types import AudienceKind, MessageStatus
from app.deps import CsrfProtected, CurrentInternalAdmin, DbSession, require_internal_admin
from app.logging_config import get_logger
from app.models import ContactMessage, User
from app.schemas import (
    ComposeEmailForm,
    ContactStatusForm,
    DeleteUserForm,
    DocPageForm,
    SignupChartQuery,
    SuspendForm,
    UserListQuery,
    first_error,
)
from app.services.admin_service import (
    AdminActionError,
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
from app.services.contact_service import count_unread, list_messages, mark_status
from app.services.docs_service import DocsError
from app.services.docs_service import create_page as create_doc_page
from app.services.docs_service import delete_page as delete_doc_page
from app.services.docs_service import get_by_id as get_doc_page
from app.services.docs_service import list_all as docs_list_all
from app.services.docs_service import update_page as update_doc_page
from app.services.email_service import (
    CAMPAIGN_VARIABLES,
    CONFIRM_THRESHOLD,
    fill,
    preview_audience,
    recent_sends,
    send_campaign,
)
from app.services.organisation_service import (
    OrganisationError,
    approve_showcase,
    revoke_showcase,
)

log = get_logger(__name__)

# Declared on the router, so it covers every route below — including any added
# later without a second thought.
router = APIRouter(
    prefix="/api/internal/admin",
    tags=["internal-admin"],
    dependencies=[Depends(require_internal_admin)],
)


def _fail(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code, detail={"error": {"code": code, "message": message}}
    )


def _no_store(response: Response) -> None:
    """Every response here is somebody's account data. None of it is cacheable."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


async def _load_target(db, user_id: int) -> User:
    target = await db.get(User, user_id)
    if target is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "No such user.")
    return target


def _user_summary(user: User) -> dict:
    """What the panel shows about an account.

    An explicit view rather than a serialised model, so nothing reaches a
    browser because it happened to be a column — `password_hash`, `totp_secret`
    and the backup codes are all on this object, and an admin panel is still a
    browser.
    """
    return {
        "id": user.id,
        "email": user.email,
        "tier": "free",
        "tier_label": "Free",
        "status_label": user.status_label,
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        "is_suspended": user.is_suspended,
        "email_alerts_enabled": user.email_alerts_enabled,
        "account_kind": str(user.account_kind),
        "organisation_name": user.organisation_name,
        # Shown so whoever is deciding has something to check the name
        # against. That check is the whole reason approval is a person rather
        # than a rule.
        "organisation_website": user.organisation_website,
        "showcase_opt_in": user.showcase_opt_in,
        "showcase_approved_at": user.showcase_approved_at,
        "showcase_listed": user.is_showcased,
        "created_at": user.created_at,
        "last_login_at": user.last_login_at,
        "suspended_at": user.suspended_at,
        "suspension_reason": user.suspension_reason,
        "subscription_status": user.subscription_status,
        "subscription_ends_at": user.subscription_ends_at,
        "subscription_amount_cents": user.subscription_amount_cents,
        "subscription_currency": user.subscription_currency,
        "subscription_interval": user.subscription_interval,
        # The id, not the customer id: it is what a support question about a
        # charge is looked up by in Dodo.
        "dodo_subscription_id": user.dodo_subscription_id,
    }


def _audit_entry(entry: Any) -> dict:
    return {
        "id": entry.id,
        "action": entry.action,
        "actor_email": entry.actor_email,
        "target_email": entry.target_email,
        "details": entry.details,
        "ip_address": entry.ip_address,
        "created_at": entry.created_at,
    }


# ---------------------------------------------------------------------------
# Overview / metrics
# ---------------------------------------------------------------------------


@router.get("/overview")
async def overview(
    response: Response,
    db: DbSession,
    admin: CurrentInternalAdmin,
    # Taken as a string so the Pydantic model owns coercion *and* the fallback,
    # as on the rendered page. Declaring it `int` would let FastAPI 422 on
    # `?days=abc` before this handler runs, and a hand-edited URL should show
    # the default range rather than an error.
    days: Annotated[str, Query()] = "30",
) -> dict:
    """Platform metrics, feed health and the signup trend."""
    _no_store(response)

    try:
        chart_query = SignupChartQuery(days=days)
    except ValidationError:
        chart_query = SignupChartQuery()

    metrics = await platform_metrics(db)
    signups = await signups_over_time(db, chart_query.days)

    return {
        "data": {
            "metrics": {
                **{name: getattr(metrics, name) for name in metrics.__slots__},
                # The product's headline claim measured across every account.
                "noise_filtered_share": metrics.noise_filtered_share,
            },
            "feeds": [
                {
                    "name": feed.name,
                    "label": feed.label,
                    "last_success_at": feed.last_success_at,
                    "last_attempt_at": feed.last_attempt_at,
                    "last_error": feed.last_error,
                    "record_count": feed.record_count,
                    "catalog_version": feed.catalog_version,
                    # The service decides what a feed's state is called. The
                    # panel must not re-derive it from the timestamps and reach
                    # a different answer than the one the alerts run on.
                    "status": feed.status,
                    "is_healthy": feed.is_healthy,
                    "is_stale": feed.is_stale,
                }
                for feed in await feed_health(db)
            ],
            "signups": [
                {
                    "day": point.day.isoformat(),
                    "count": point.count,
                    "cumulative": point.cumulative,
                }
                for point in signups
            ],
            "chart_days": chart_query.days,
        }
    }


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@router.get("/users")
async def users_index(
    response: Response,
    db: DbSession,
    admin: CurrentInternalAdmin,
    page: Annotated[str, Query()] = "1",
    per_page: Annotated[str, Query()] = "25",
    search: Annotated[str, Query()] = "",
    status_filter: Annotated[str, Query(alias="status")] = "",
) -> dict:
    """Paginated, searchable user list.

    Bad query parameters fall back to defaults rather than returning a 422:
    somebody hand-editing a URL should get the first page, not an error.
    """
    _no_store(response)

    try:
        query = UserListQuery(
            page=page,
            per_page=per_page,
            search=search,
            status=status_filter,
        )
    except ValidationError:
        query = UserListQuery()

    result = await list_users(
        db,
        page=query.page,
        per_page=query.per_page,
        search=query.search_filter,
        status=query.status_filter,
    )

    return {
        "data": {
            "rows": [
                {
                    "user": _user_summary(row.user),
                    "target_count": row.target_count,
                    "open_alert_count": row.open_alert_count,
                }
                for row in result.rows
            ],
            "total": result.total,
            "page": result.page,
            "per_page": result.per_page,
            "pages": result.pages,
            "start_index": result.start_index,
            "end_index": result.end_index,
        },
        "query": {"search": query.search, "status": query.status},
    }


@router.get("/users/{user_id}")
async def user_view(
    response: Response, db: DbSession, admin: CurrentInternalAdmin, user_id: int
) -> dict:
    _no_store(response)

    detail = await user_detail(db, user_id)
    if detail is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "No such user.")

    return {
        "data": {
            "user": _user_summary(detail.user),
            "targets": [
                {
                    "id": target.id,
                    "name": target.name,
                    "ecosystem": target.ecosystem.value,
                    # Nullable: a project added by repository URL has no
                    # manifest until the first scan finds one. The rendered
                    # panel dereferenced this unguarded and would 500 the whole
                    # user page for such an account.
                    "manifest_kind": (target.manifest_kind.value if target.manifest_kind else None),
                    "dependency_count": target.dependency_count,
                    "last_scanned_at": target.last_scanned_at,
                    "next_scan_at": target.next_scan_at,
                }
                for target in detail.targets
            ],
            "recent_alerts": [
                {
                    "id": alert.id,
                    # Plain strings on this model, not enums: alerts predate
                    # the typed columns elsewhere and "pending" is a real value
                    # no enum lists.
                    "channel": alert.channel,
                    "subject": alert.subject,
                    "status": alert.status,
                    "error": alert.error,
                    "created_at": alert.created_at,
                    "sent_at": alert.sent_at,
                }
                for alert in detail.recent_alerts
            ],
            "audit_entries": [_audit_entry(entry) for entry in detail.audit_entries],
            "open_alert_count": detail.open_alert_count,
            "suppressed_count": detail.suppressed_count,
            "scan_count": detail.scan_count,
        }
    }


class ShowcaseApprovalBody(BaseModel):
    approved: bool = False


class SuspendBody(BaseModel):
    reason: str = ""


@router.post("/users/{user_id}/showcase", dependencies=[CsrfProtected])
async def set_user_showcase(
    request: Request,
    db: DbSession,
    admin: CurrentInternalAdmin,
    user_id: int,
    body: ShowcaseApprovalBody,
) -> dict:
    """Approve or withdraw a company's appearance on the landing page.

    The second half of a two-part gate. The account has to have asked, and
    somebody here has to have checked that the name is theirs to give --
    consent alone would let anybody sign up as a well-known company and land on
    our front page, which is impersonation with our own marketing as the
    vehicle.

    Approving does not create the consent, and withdrawing does not remove it.
    They are separate facts, and conflating them would let a withdrawal by us
    look like a decision by them.
    """
    target = await _load_target(db, user_id)

    try:
        if body.approved:
            await approve_showcase(db, target)
        else:
            await revoke_showcase(db, target)
    except OrganisationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "REFUSED", str(exc)) from None

    # Audited like every other admin action on an account. Publishing a
    # customer's name is not a small thing, and "who approved that, and when"
    # has to have an answer.
    record_audit(
        db,
        admin,
        action="user.showcase_approved" if body.approved else "user.showcase_revoked",
        target=target,
        details={"organisation": target.organisation_name},
        ip_address=_client_ip(request),
    )

    await db.commit()
    return {"data": {"user": _user_summary(target)}}


@router.post("/users/{user_id}/suspend", dependencies=[CsrfProtected])
async def suspend(
    request: Request,
    db: DbSession,
    admin: CurrentInternalAdmin,
    user_id: int,
    body: SuspendBody,
) -> dict:
    target = await _load_target(db, user_id)

    try:
        form = SuspendForm(reason=body.reason)
    except ValidationError:
        raise _fail(
            status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", "That reason was too long."
        ) from None

    try:
        await suspend_user(db, admin, target, form.reason, ip_address=_client_ip(request))
    except AdminActionError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "REFUSED", str(exc)) from None

    await db.commit()
    return {"data": {"user": _user_summary(target)}}


@router.post("/users/{user_id}/unsuspend", dependencies=[CsrfProtected])
async def unsuspend(
    request: Request, db: DbSession, admin: CurrentInternalAdmin, user_id: int
) -> dict:
    target = await _load_target(db, user_id)

    try:
        await unsuspend_user(db, admin, target, ip_address=_client_ip(request))
    except AdminActionError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "REFUSED", str(exc)) from None

    await db.commit()
    return {"data": {"user": _user_summary(target)}}


class DeleteBody(BaseModel):
    confirm_email: str = ""


@router.post("/users/{user_id}/delete", dependencies=[CsrfProtected])
async def delete_user_route(
    request: Request,
    db: DbSession,
    admin: CurrentInternalAdmin,
    user_id: int,
    body: DeleteBody,
) -> dict:
    """Permanently delete an account and all of its data.

    The typed-email confirmation is enforced here, not just in the modal. The
    dialog is a courtesy; this is the check, and it is the one that still
    applies to a hand-crafted POST or a mis-aimed script.
    """
    target = await _load_target(db, user_id)

    try:
        form = DeleteUserForm(confirm_email=body.confirm_email)
    except ValidationError:
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "CONFIRMATION_REQUIRED",
            "Type the account's email address to confirm.",
        ) from None

    if form.confirm_email != target.email.strip().lower():
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "CONFIRMATION_MISMATCH",
            "That address doesn't match this account. Nothing was deleted.",
        )

    deleted_email = target.email
    try:
        removed = await delete_user(db, admin, target, ip_address=_client_ip(request))
    except AdminActionError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "REFUSED", str(exc)) from None

    await db.commit()
    log.info("admin.delete_completed", email=deleted_email, **removed)

    return {"data": {"deleted": True, "email": deleted_email, "removed": removed}}


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------


@router.get("/billing")
async def billing(response: Response, db: DbSession, admin: CurrentInternalAdmin) -> dict:
    """Revenue at a glance, from what the Dodo webhooks already stored."""
    _no_store(response)
    settings = get_settings()
    snapshot = await revenue_snapshot(db)

    return {
        "data": {
            "snapshot": {
                **{name: getattr(snapshot, name) for name in snapshot.__slots__},
                "mrr": snapshot.mrr,
                "arr": snapshot.arr,
            },
            # The same account view the user list uses, so the two pages never
            # disagree about what somebody's plan or status is called.
            "subscribers": [_user_summary(row) for row in await list_subscribers(db)],
            "dodo_enabled": settings.dodo_enabled,
            "dodo_dashboard_url": settings.dodo_dashboard_url,
        }
    }


# ---------------------------------------------------------------------------
# Documentation
#
# Behind the same admin guard as everything else here. The public read-only
# views live in `internal_marketing`.
# ---------------------------------------------------------------------------


def _doc_view(page: Any) -> dict:
    return {
        "id": page.id,
        "slug": page.slug,
        "title": page.title,
        "summary": page.summary,
        "content": page.content,
        "published": page.published,
        "position": page.position,
        "updated_at": page.updated_at,
    }


@router.get("/docs")
async def docs_index(response: Response, db: DbSession, admin: CurrentInternalAdmin) -> dict:
    _no_store(response)
    return {"data": {"pages": [_doc_view(page) for page in await docs_list_all(db)]}}


@router.get("/docs/{page_id}")
async def docs_edit(
    response: Response, db: DbSession, admin: CurrentInternalAdmin, page_id: int
) -> dict:
    _no_store(response)

    page = await get_doc_page(db, page_id)
    if page is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "No such page.")
    return {"data": {"page": _doc_view(page)}}


class DocBody(BaseModel):
    title: str = ""
    #: Blank is legal — the service derives it from the title.
    slug: str = ""
    summary: str = ""
    content: str = ""
    published: bool = False
    position: int = 0


def _doc_form(body: DocBody) -> DocPageForm:
    try:
        return DocPageForm(
            title=body.title,
            slug=body.slug,
            summary=body.summary,
            content=body.content,
            published=body.published,
            position=body.position,
        )
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None


@router.post("/docs", dependencies=[CsrfProtected])
async def docs_create(
    request: Request, db: DbSession, admin: CurrentInternalAdmin, body: DocBody
) -> dict:
    form = _doc_form(body)

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
        raise _fail(status.HTTP_400_BAD_REQUEST, "REFUSED", str(exc)) from None

    await db.commit()
    record_audit(
        db, admin, "docs.created", details={"slug": page.slug}, ip_address=_client_ip(request)
    )
    await db.commit()
    return {"data": {"page": _doc_view(page)}}


@router.post("/docs/{page_id}", dependencies=[CsrfProtected])
async def docs_update(
    request: Request,
    db: DbSession,
    admin: CurrentInternalAdmin,
    page_id: int,
    body: DocBody,
) -> dict:
    page = await get_doc_page(db, page_id)
    if page is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "No such page.")

    form = _doc_form(body)

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
        raise _fail(status.HTTP_400_BAD_REQUEST, "REFUSED", str(exc)) from None

    record_audit(
        db, admin, "docs.updated", details={"slug": page.slug}, ip_address=_client_ip(request)
    )
    await db.commit()
    return {"data": {"page": _doc_view(page)}}


@router.post("/docs/{page_id}/delete", dependencies=[CsrfProtected])
async def docs_delete(
    request: Request, db: DbSession, admin: CurrentInternalAdmin, page_id: int
) -> dict:
    page = await get_doc_page(db, page_id)
    if page is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "No such page.")

    slug = page.slug
    await delete_doc_page(db, page)
    record_audit(db, admin, "docs.deleted", details={"slug": slug}, ip_address=_client_ip(request))
    await db.commit()
    return {"data": {"deleted": True, "slug": slug}}


# ---------------------------------------------------------------------------
# Inbox — messages from the contact form
# ---------------------------------------------------------------------------


def _message_view(message: ContactMessage, *, full: bool = False) -> dict:
    view = {
        "id": message.id,
        "email": message.email,
        "category": message.category.value,
        "category_label": message.category.label,
        "status": message.status.value,
        "status_label": message.status.label,
        "created_at": message.created_at,
        "preview": message.preview,
        "user_id": message.user_id,
        # In the list too: it marks a message whose notification email never
        # left, which is a mail problem rather than a lost report.
        "notified_at": message.notified_at,
        "handled_at": message.handled_at,
        "handled_by_email": message.handled_by_email,
        "admin_note": message.admin_note,
    }
    if full:
        view |= {
            "message": message.message,
            "page_url": message.page_url,
            "user_agent": message.user_agent,
            "ip_address": message.ip_address,
        }
    return view


@router.get("/inbox")
async def inbox(
    response: Response,
    db: DbSession,
    admin: CurrentInternalAdmin,
    show: Annotated[str, Query()] = "new",
) -> dict:
    """The contact queue.

    Defaults to unread rather than to everything, because the question this
    page exists to answer is "is anybody waiting on me?" and an all-time list
    buries that under six months of resolved threads.
    """
    _no_store(response)

    message_status = None
    if show in {entry.value for entry in MessageStatus}:
        message_status = MessageStatus(show)
    elif show != "all":
        show = "new"
        message_status = MessageStatus.NEW

    page = await list_messages(db, status=message_status, limit=100)

    return {
        "data": {
            "messages": [_message_view(message) for message in page.messages],
            "total": page.total,
            "unread": page.unread,
            "show": show,
            "statuses": [entry.value for entry in MessageStatus],
        }
    }


@router.get("/inbox/{message_id}")
async def inbox_message(
    response: Response, db: DbSession, admin: CurrentInternalAdmin, message_id: int
) -> dict:
    _no_store(response)

    message = await db.get(ContactMessage, message_id)
    if message is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "No such message.")

    # Opening it counts as reading it. Making the admin press a second button
    # to say so would mean the unread count drifts from reality within a day.
    if message.status is MessageStatus.NEW:
        message.status = MessageStatus.READ
        await db.commit()

    return {
        "data": {
            "message": _message_view(message, full=True),
            "unread": await count_unread(db),
            "statuses": [entry.value for entry in MessageStatus],
        }
    }


class MessageStatusBody(BaseModel):
    status: str = ""
    note: str = ""


@router.post("/inbox/{message_id}/status", dependencies=[CsrfProtected])
async def inbox_set_status(
    request: Request,
    db: DbSession,
    admin: CurrentInternalAdmin,
    message_id: int,
    body: MessageStatusBody,
) -> dict:
    message = await db.get(ContactMessage, message_id)
    if message is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "No such message.")

    try:
        form = ContactStatusForm(status=body.status, note=body.note)
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None

    await mark_status(db, message, form.status, admin=admin, note=form.note)
    record_audit(
        db,
        actor=admin,
        action="contact.status_changed",
        details={"message_id": message.id, "status": form.status.value},
        ip_address=_client_ip(request),
    )
    await db.commit()

    return {
        "data": {
            "message": _message_view(message, full=True),
            "unread": await count_unread(db),
        }
    }


# ---------------------------------------------------------------------------
# Compose and send
#
# The guardrail is the whole feature. Composing an email is a textarea; sending
# one to every account is irreversible, and the failure mode is not a bug
# report, it is six hundred people receiving something that was meant for one.
#
# So the send is two requests. The first resolves the audience and returns the
# exact count; the second carries that count back and is refused if it no
# longer matches. Between those two, somebody could sign up -- and a
# confirmation screen that said 47 while the send reached 48 would make the
# count decorative.
# ---------------------------------------------------------------------------


class ComposeBody(BaseModel):
    subject: str = ""
    body: str = ""
    audience: str = ""
    audience_email: str = ""


class SendBody(ComposeBody):
    #: The count the admin agreed to in the preview. Absent means the preview
    #: was skipped, which is refused rather than read as agreement.
    confirmed_count: int | None = None


def _compose_form(body: ComposeBody) -> ComposeEmailForm:
    try:
        return ComposeEmailForm(
            subject=body.subject,
            body=body.body,
            audience=body.audience,
            audience_email=body.audience_email,
        )
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None


@router.get("/email")
async def compose(response: Response, db: DbSession, admin: CurrentInternalAdmin) -> dict:
    """What the composer needs before anything is typed: the variables, the
    threshold above which a send needs confirming, and what already went out."""
    _no_store(response)

    return {
        "data": {
            "variables": CAMPAIGN_VARIABLES,
            "confirm_threshold": CONFIRM_THRESHOLD,
            # Ordered least dangerous first: "One address" is the default the
            # composer starts on, so the safe option is the one you get by not
            # choosing.
            "audiences": [
                {"value": kind.value, "label": kind.label}
                for kind in (AudienceKind.ONE, AudienceKind.ALL)
            ],
            "sends": [
                {
                    "id": row.id,
                    "recipient": row.recipient,
                    "subject": row.subject,
                    "template": row.template,
                    "trigger": row.trigger.value,
                    "status": row.status.value,
                    "status_label": row.status.label,
                    "actor_email": row.actor_email,
                    "error": row.error,
                    "batch_id": row.batch_id,
                    "created_at": row.created_at,
                }
                for row in await recent_sends(db, limit=40)
            ],
        }
    }


@router.post("/email/preview", dependencies=[CsrfProtected])
async def compose_preview(db: DbSession, admin: CurrentInternalAdmin, body: ComposeBody) -> dict:
    """Resolve the audience and return what would go out.

    Nothing is sent here. The rendered sample uses the first recipient, so the
    variables are shown resolved against a real person rather than against
    placeholder text that hides an empty value.
    """
    form = _compose_form(body)

    resolved = await preview_audience(db, form.audience, email=form.audience_email)
    if resolved.count == 0:
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "EMPTY_AUDIENCE",
            (
                "That audience has nobody in it."
                if form.audience is not AudienceKind.ONE
                else "No account with that address, and it is not a valid address either."
            ),
        )

    sample = resolved.recipients[0]
    return {
        "data": {
            "audience": form.audience.value,
            "audience_label": form.audience.label,
            "count": resolved.count,
            "needs_confirmation": resolved.needs_confirmation,
            "without_projects": resolved.without_projects,
            "sample_email": sample.email,
            "subject": fill(form.subject, sample),
            "body": fill(form.body, sample),
        }
    }


@router.post("/email/send", dependencies=[CsrfProtected])
async def compose_send(
    request: Request, db: DbSession, admin: CurrentInternalAdmin, body: SendBody
) -> dict:
    form = _compose_form(body)
    resolved = await preview_audience(db, form.audience, email=form.audience_email)

    # The count the admin agreed to. Reaching this route without one means the
    # preview step was skipped -- by a bookmarked call, a replayed request, or
    # a script -- and the confirmation is the only thing standing between a
    # textarea and every account on the platform.
    if body.confirmed_count is None:
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "NOT_PREVIEWED",
            "Preview the message before sending it.",
        )

    if body.confirmed_count != resolved.count:
        agreed = body.confirmed_count
        raise _fail(
            status.HTTP_409_CONFLICT,
            "AUDIENCE_CHANGED",
            (
                f"The audience changed while you were reading it: you confirmed "
                f"{agreed} {'recipient' if agreed == 1 else 'recipients'}, and it is now "
                f"{resolved.count}. Nothing was sent. Check the count and confirm again."
            ),
        )

    report = await send_campaign(
        db, subject=form.subject, body=form.body, audience=resolved, actor=admin
    )

    record_audit(
        db,
        actor=admin,
        action="email.campaign_sent",
        details={
            "audience": form.audience.value,
            "recipients": resolved.count,
            "sent": report.sent,
            "failed": report.failed,
            "subject": form.subject[:200],
            "batch_id": report.batch_id,
        },
        ip_address=_client_ip(request),
    )
    await db.commit()

    return {
        "data": {
            "batch_id": report.batch_id,
            "attempted": report.attempted,
            "sent": report.sent,
            "failed": report.failed,
            # Reported rather than raised. A partial send did happen, and the
            # admin needs both halves of that: who got it, and what broke.
            "errors": list(report.errors),
        }
    }


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


@router.get("/audit")
async def audit(response: Response, db: DbSession, admin: CurrentInternalAdmin) -> dict:
    _no_store(response)
    return {"data": {"entries": [_audit_entry(entry) for entry in await recent_audit_entries(db)]}}
