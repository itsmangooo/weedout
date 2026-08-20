"""Capturing what people tell us, and telling the admin about it.

Three rules shape this module:

* **Never lose the message.** The row is committed before the notification is
  attempted, and a delivery failure is recorded on the row rather than raised
  at the sender. Somebody who took the trouble to report a bug should not be
  shown an error because our mail provider is having an afternoon.
* **Never require an account.** Two of the reports most worth having -- "I
  cannot sign up" and "I cannot log in" -- come from people who by definition
  cannot authenticate.
* **Rate limit by IP, not by account,** for the same reason.

There is no reply path here. Responses go out from a normal mailbox; this is
capture and a queue, not a support desk.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.core.types import ContactCategory, MessageStatus
from app.logging_config import get_logger
from app.mail import EmailError
from app.models import ContactMessage, User, utcnow
from app.services.email_service import EmailTrigger, send_templated

log = get_logger(__name__)

__all__ = [
    "ContactError",
    "count_unread",
    "list_messages",
    "mark_status",
    "submit_message",
]


class ContactError(RuntimeError):
    """The message could not be accepted."""


@dataclass(slots=True)
class InboxPage:
    messages: list[ContactMessage]
    total: int
    unread: int


async def submit_message(
    db: AsyncSession,
    *,
    email: str,
    message: str,
    category: ContactCategory = ContactCategory.OTHER,
    user: User | None = None,
    page_url: str | None = None,
    user_agent: str | None = None,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> ContactMessage:
    """Store a message and try to tell the admin. Returns the stored row.

    The commit happens before the email, so the record survives a mail failure.
    `notified_at` stays null in that case, which is the signal the inbox uses to
    show that nobody was paged about it.
    """
    settings = settings or get_settings()

    body = message.strip()
    if not body:
        raise ContactError("The message is empty.")

    row = ContactMessage(
        user_id=user.id if user else None,
        # An authenticated sender's address comes from the session, never from
        # the form -- otherwise the form is a way to put words in an account's
        # mouth, and the reply would go to whoever typed it.
        email=(user.email if user else email).strip().lower(),
        category=category,
        message=body,
        page_url=(page_url or "")[:500] or None,
        user_agent=(user_agent or "")[:300] or None,
        ip_address=(ip_address or "")[:64] or None,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    await _notify_admin(db, row, settings)
    return row


async def _notify_admin(db: AsyncSession, row: ContactMessage, settings: Settings) -> None:
    recipient = settings.admin_email or settings.admin_bootstrap_notify_email
    if not recipient:
        log.warning("contact.no_admin_recipient", message_id=row.id)
        return

    try:
        await send_templated(
            db,
            template="contact_received",
            recipient=recipient,
            context={
                "category": row.category.label,
                "from_email": row.email,
                "account": "yes" if row.user_id else "no (logged out)",
                "page_url": row.page_url or "not recorded",
                "message": row.message,
                "inbox_url": f"{settings.base_url.rstrip('/')}/admin/inbox/{row.id}",
            },
            trigger=EmailTrigger.SYSTEM,
            settings=settings,
        )
    except EmailError as exc:
        # Recorded, not raised. The sender's experience must not depend on our
        # outbound mail working.
        log.error("contact.notify_failed", message_id=row.id, error=str(exc))
        return

    row.notified_at = utcnow()
    await db.commit()


async def list_messages(
    db: AsyncSession,
    *,
    status: MessageStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> InboxPage:
    """The inbox, newest first, optionally filtered to one status."""
    where = [ContactMessage.status == status] if status else []

    rows = (
        (
            await db.execute(
                select(ContactMessage)
                .where(*where)
                .order_by(ContactMessage.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )

    total = await db.scalar(select(func.count(ContactMessage.id)).where(*where)) or 0
    unread = await count_unread(db)
    return InboxPage(messages=list(rows), total=int(total), unread=unread)


async def count_unread(db: AsyncSession) -> int:
    """How many messages nobody has looked at. Drives the inbox badge."""
    return int(
        await db.scalar(
            select(func.count(ContactMessage.id)).where(ContactMessage.status == MessageStatus.NEW)
        )
        or 0
    )


async def mark_status(
    db: AsyncSession,
    message: ContactMessage,
    status: MessageStatus,
    *,
    admin: User,
    note: str | None = None,
) -> ContactMessage:
    """Move a message through the queue. Caller commits."""
    message.status = status
    if note is not None:
        message.admin_note = note.strip() or None
    if status is MessageStatus.RESOLVED:
        message.handled_at = utcnow()
        message.handled_by_email = admin.email
    else:
        # Re-opening clears the handled marks rather than leaving a stale claim
        # that somebody dealt with it.
        message.handled_at = None
        message.handled_by_email = None
    return message
