"""The one way mail leaves this application.

Before this module, four call sites each built their own subject line, called
`app.mail.send_email`, and handled failure differently. Nothing recorded what
had gone out, so "did the reset email send?" was a question you answered by
grepping logs, and "why did this user get three digests?" was a question you
could not answer at all.

So: one function, `send_templated`, which

* renders a named template to a subject and a body,
* hands it to the delivery backend,
* and writes an `EmailLog` row either way -- including when a preference held
  the message back, because "we chose not to send it" is the answer to a real
  question and an absent row is not.

`app.mail.send_email` is still the transport and is still used directly by the
one caller that must not touch the database (bootstrap, which runs before
migrations are guaranteed). Everything else comes through here.

Templates live in `app/templates/email/` as plain text. The first line is
``Subject: ...`` and the rest is the body, so a message is one file rather than
a subject in Python and a body somewhere else that drift apart.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any

from jinja2 import TemplateNotFound
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.core.types import AudienceKind, EmailStatus, EmailTrigger, Tier
from app.logging_config import get_logger
from app.mail import EmailError, send_email
from app.models import EmailCampaign, EmailLog, User
from app.templating import templates

log = get_logger(__name__)

__all__ = [
    "AudiencePreview",
    "EmailTrigger",
    "SendReport",
    "known_templates",
    "preview_audience",
    "recent_sends",
    "render_template",
    "send_campaign",
    "send_templated",
]

#: Above this many recipients, a manual send needs a second confirmation that
#: names the exact count. Small enough that testing a send to yourself and two
#: colleagues stays one click; large enough that "everybody" never is.
CONFIRM_THRESHOLD = 5


@dataclass(slots=True)
class RenderedEmail:
    subject: str
    text: str


@dataclass(slots=True)
class SendReport:
    """What actually happened, for the caller and for the confirmation screen."""

    batch_id: str
    attempted: int = 0
    sent: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AudiencePreview:
    kind: AudienceKind
    recipients: list[tuple[int | None, str]]

    @property
    def count(self) -> int:
        return len(self.recipients)

    @property
    def needs_confirmation(self) -> bool:
        return self.count > CONFIRM_THRESHOLD


def known_templates() -> list[str]:
    """Every email the application can send, by name.

    Read off disk rather than kept as a list, so a template that exists is
    sendable and a name that is not a file fails loudly at send time.
    """
    directory = templates.env.loader.searchpath[0]  # type: ignore[union-attr]
    from pathlib import Path

    return sorted(p.stem for p in (Path(directory) / "email").glob("*.txt"))


def render_template(template: str, context: dict[str, Any]) -> RenderedEmail:
    """Render one email. Raises `EmailError` if the template does not exist.

    Autoescaping stays off: `select_autoescape` covers .html and .xml, and
    escaping a plain-text body would turn every apostrophe in a package name
    into `&#39;` on its way to somebody's terminal-shaped inbox.
    """
    try:
        source = templates.env.get_template(f"email/{template}.txt")
    except TemplateNotFound as exc:
        raise EmailError(f"no such email template: {template}") from exc

    rendered = source.render(**context)
    return _split_subject(rendered, fallback=template)


def _split_subject(rendered: str, *, fallback: str) -> RenderedEmail:
    lines = rendered.strip().splitlines()
    if lines and lines[0].lower().startswith("subject:"):
        subject = lines[0].split(":", 1)[1].strip()
        body = "\n".join(lines[1:]).strip()
        return RenderedEmail(subject=subject or fallback, text=body)
    # A template with no subject line is a bug, but sending it with a usable
    # subject beats raising in the middle of a password reset.
    log.warning("email.template_missing_subject", template=fallback)
    return RenderedEmail(subject=fallback.replace("_", " ").capitalize(), text=rendered.strip())


async def send_templated(
    db: AsyncSession,
    *,
    template: str,
    recipient: str,
    context: dict[str, Any] | None = None,
    trigger: EmailTrigger = EmailTrigger.SYSTEM,
    user: User | None = None,
    actor_email: str | None = None,
    batch_id: str | None = None,
    settings: Settings | None = None,
    commit: bool = True,
) -> EmailLog:
    """Render, send, and log one email. Raises `EmailError` on failure.

    The log row is written before the exception propagates, so a caller that
    lets the error through still leaves a record of the attempt.
    """
    settings = settings or get_settings()
    message = render_template(template, context or {})

    entry = EmailLog(
        recipient=recipient,
        user_id=user.id if user else None,
        template=template,
        subject=message.subject[:500],
        trigger=trigger,
        status=EmailStatus.SENT,
        actor_email=actor_email,
        batch_id=batch_id,
    )

    try:
        await send_email(
            to=recipient, subject=message.subject, text=message.text, settings=settings
        )
    except EmailError as exc:
        entry.status = EmailStatus.FAILED
        entry.error = str(exc)[:2000]
        db.add(entry)
        if commit:
            await db.commit()
        raise

    db.add(entry)
    if commit:
        await db.commit()
    return entry


async def record_skipped(
    db: AsyncSession,
    *,
    template: str,
    recipient: str,
    reason: str,
    user: User | None = None,
    commit: bool = False,
) -> EmailLog:
    """Log a message that was deliberately not sent.

    Used where a preference suppresses a notification. Without this the log
    reads as though the send never came up, which is indistinguishable from a
    bug that dropped it.
    """
    entry = EmailLog(
        recipient=recipient,
        user_id=user.id if user else None,
        template=template,
        subject=f"(not sent) {template}"[:500],
        trigger=EmailTrigger.SYSTEM,
        status=EmailStatus.SKIPPED,
        error=reason[:2000],
    )
    db.add(entry)
    if commit:
        await db.commit()
    return entry


# ---------------------------------------------------------------------------
# Manual sends to an audience
# ---------------------------------------------------------------------------


async def preview_audience(
    db: AsyncSession, kind: AudienceKind, *, email: str | None = None
) -> AudiencePreview:
    """Exactly who a send would reach. Runs before the confirmation screen.

    Suspended accounts are excluded. Somebody we have locked out of the product
    is not somebody to put a marketing email in front of.
    """
    if kind is AudienceKind.ONE:
        address = (email or "").strip().lower()
        if not address:
            return AudiencePreview(kind=kind, recipients=[])
        row = (await db.execute(select(User.id, User.email).where(User.email == address))).first()
        # An address with no account is still a valid recipient -- it is how you
        # reply to somebody whose signup failed.
        return AudiencePreview(kind=kind, recipients=[(row[0], row[1]) if row else (None, address)])

    where = [User.is_active.is_(True), User.is_suspended.is_(False)]
    if kind is AudienceKind.PRO:
        where.append(User.tier == Tier.PRO)
    elif kind is AudienceKind.FREE:
        where.append(User.tier == Tier.FREE)

    rows = (await db.execute(select(User.id, User.email).where(*where).order_by(User.id))).all()
    return AudiencePreview(kind=kind, recipients=[(r[0], r[1]) for r in rows])


async def send_campaign(
    db: AsyncSession,
    *,
    subject: str,
    body: str,
    audience: AudiencePreview,
    actor: User,
    settings: Settings | None = None,
) -> SendReport:
    """Send one composed message to an audience, one email at a time.

    Per-recipient rather than one message with many addresses, for two
    reasons: the template variables are per-recipient, and a single failure
    should cost one delivery rather than all of them.
    """
    settings = settings or get_settings()
    batch_id = secrets.token_hex(8)
    report = SendReport(batch_id=batch_id)

    campaign = EmailCampaign(
        subject=subject[:500],
        body=body,
        audience=audience.kind,
        audience_email=audience.recipients[0][1] if audience.kind is AudienceKind.ONE else None,
        actor_email=actor.email,
        batch_id=batch_id,
        recipient_count=audience.count,
    )
    db.add(campaign)

    for user_id, address in audience.recipients:
        report.attempted += 1
        rendered_subject = _fill(subject, address)
        rendered_body = _fill(body, address)

        entry = EmailLog(
            recipient=address,
            user_id=user_id,
            template="custom",
            subject=rendered_subject[:500],
            trigger=EmailTrigger.ADMIN_MANUAL,
            status=EmailStatus.SENT,
            actor_email=actor.email,
            batch_id=batch_id,
        )
        try:
            await send_email(
                to=address, subject=rendered_subject, text=rendered_body, settings=settings
            )
            report.sent += 1
        except EmailError as exc:
            entry.status = EmailStatus.FAILED
            entry.error = str(exc)[:2000]
            report.failed += 1
            if len(report.errors) < 5:
                report.errors.append(f"{address}: {exc}")
        db.add(entry)

    campaign.sent_count = report.sent
    campaign.failed_count = report.failed
    await db.commit()

    log.info(
        "email.campaign_sent",
        batch_id=batch_id,
        audience=audience.kind.value,
        attempted=report.attempted,
        sent=report.sent,
        failed=report.failed,
        actor=actor.email,
    )
    return report


#: The variables a composed email may use. Deliberately tiny: every one of
#: these has to be available for every recipient, and a variable that resolves
#: to an empty string for half the audience is worse than not offering it.
CAMPAIGN_VARIABLES: dict[str, str] = {
    "{{user_email}}": "The recipient's email address",
}


def _fill(text: str, address: str) -> str:
    """Substitute campaign variables.

    Plain string replacement rather than Jinja on purpose. This body is typed
    into a browser by a human; handing it to a template engine would make
    `{{ settings.secret_key }}` a working expression.
    """
    return text.replace("{{user_email}}", address).replace("{{ user_email }}", address)


# ---------------------------------------------------------------------------
# Reading the log
# ---------------------------------------------------------------------------


async def recent_sends(
    db: AsyncSession,
    *,
    limit: int = 100,
    trigger: EmailTrigger | None = None,
    status: EmailStatus | None = None,
) -> list[EmailLog]:
    where = []
    if trigger:
        where.append(EmailLog.trigger == trigger)
    if status:
        where.append(EmailLog.status == status)
    rows = (
        (
            await db.execute(
                select(EmailLog).where(*where).order_by(EmailLog.created_at.desc()).limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def send_counts(db: AsyncSession) -> dict[str, int]:
    """Totals for the admin panel header."""
    rows = (
        await db.execute(select(EmailLog.status, func.count(EmailLog.id)).group_by(EmailLog.status))
    ).all()
    counts = {status.value: 0 for status in EmailStatus}
    for status, count in rows:
        counts[status.value if hasattr(status, "value") else str(status)] = int(count)
    counts["total"] = sum(counts[s.value] for s in EmailStatus)
    return counts
