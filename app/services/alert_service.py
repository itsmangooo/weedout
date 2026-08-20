"""Turning new findings into notifications.

Restraint is the feature. Three rules keep the mail volume honest:

* Only matches that triage marked actionable are ever sent.
* Each match notifies once — `CVEMatch.notified_at` is the guard, so a scan that
  re-confirms yesterday's finding sends nothing.
* One scan produces one digest per channel, not one message per CVE.

Two channels exist: email, and a per-project Discord webhook on the Pro plan.
They are delivered independently and recorded independently, so a broken
webhook cannot stop the email carrying the same news. `notified_at` is set if
*any* channel got through — the guard means "this person has been told", and a
retry because one of two channels failed would re-send on the one that worked.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.discord import DigestFinding, build_digest_payload
from app.core.types import ActionableReason, AlertStatus, Verdict
from app.core.webhooks import WebhookKind, build_custom_payload
from app.logging_config import get_logger
from app.mail import EmailError, send_email
from app.models import Alert, CVEMatch, TrackedTarget, User, VulnerabilityRecord, utcnow
from app.services.discord_service import post_webhook
from app.tiers import can_use_webhooks

log = get_logger(__name__)

__all__ = ["mark_delivered_in_app", "send_new_match_digest"]


async def send_new_match_digest(
    db: AsyncSession, user: User, target: TrackedTarget, matches: list[CVEMatch]
) -> int:
    """Email a user about newly actionable findings. Returns the number covered.

    Every match gets an `Alert` row before the send is attempted, so a delivery
    failure leaves a durable, inspectable record instead of vanishing.
    """
    sendable = [
        match
        for match in matches
        if match.verdict is Verdict.ACTIONABLE
        and match.status is AlertStatus.OPEN
        and match.notified_at is None
    ]
    if not sendable:
        return 0

    if not user.email_alerts_enabled:
        log.info("alert.suppressed_by_preference", user_id=user.id, count=len(sendable))
        # Mark them notified anyway: the user opted out, and leaving them unset
        # would cause a flood the moment they opt back in.
        for match in sendable:
            match.notified_at = utcnow()
        return 0

    # Load the advisories explicitly. `CVEMatch.vulnerability` is a lazy
    # relationship, and a match this scan just created has never loaded it —
    # touching it here would trigger IO outside the async greenlet context.
    cve_by_vuln_id = await _load_cve_ids(db, [m.vulnerability_id for m in sendable])

    settings = get_settings()
    subject = _subject(target, sendable)
    text = _render_text(settings.base_url, target, sendable, cve_by_vuln_id)

    delivered_any = False

    if await _deliver_email(db, user, target, sendable, subject, text, settings):
        delivered_any = True

    # Independent of the email, and after it: the email is the channel every
    # plan has, and a webhook that hangs for its full timeout should not delay
    # the message that always goes out.
    if await _deliver_discord(db, user, target, sendable, cve_by_vuln_id, settings):
        delivered_any = True

    if not delivered_any:
        # notified_at stays unset, so the next scan retries rather than dropping
        # it. Nobody heard about this finding.
        return 0

    now = utcnow()
    for match in sendable:
        match.notified_at = now

    log.info("alert.sent", user_id=user.id, target_id=target.id, matches=len(sendable))
    return len(sendable)


async def _deliver_email(
    db: AsyncSession,
    user: User,
    target: TrackedTarget,
    sendable: list[CVEMatch],
    subject: str,
    text: str,
    settings,
) -> bool:
    """The digest email. Returns whether it was handed off for delivery."""
    alerts = [
        Alert(
            user_id=user.id,
            match_id=match.id,
            channel="email",
            destination=user.email,
            subject=subject[:500],
            status="pending",
        )
        for match in sendable
    ]
    for alert in alerts:
        db.add(alert)
    await db.flush()

    try:
        await send_email(to=user.email, subject=subject, text=text, settings=settings)
    except EmailError as exc:
        for alert in alerts:
            alert.status = "failed"
            alert.error = str(exc)[:2000]
        log.error("alert.delivery_failed", user_id=user.id, target_id=target.id, error=str(exc))
        return False

    now = utcnow()
    for alert in alerts:
        alert.status = "sent"
        alert.sent_at = now
    return True


async def _deliver_discord(
    db: AsyncSession,
    user: User,
    target: TrackedTarget,
    sendable: list[CVEMatch],
    cve_by_vuln_id: dict[str, str],
    settings,
) -> bool:
    """The Discord webhook, if this project has one and the plan allows it.

    Tier is checked here rather than at the point the URL is saved, so a
    subscription that lapses stops the posts without anybody having to remember
    to clear the field — and starts them again on renewal without the user
    re-entering a credential they already gave us.
    """
    if not target.discord_webhook_url:
        return False

    if not can_use_webhooks(user.tier):
        log.info("alert.discord_skipped_tier", user_id=user.id, target_id=target.id)
        return False

    findings = [
        DigestFinding(
            package=match.package_name,
            version=match.package_version,
            cve=cve_by_vuln_id.get(match.vulnerability_id, match.vulnerability_id),
            severity=str(match.severity),
            exploited=bool(match.is_kev),
            fixed_version=match.fixed_version,
        )
        for match in sendable
    ]
    dashboard_url = f"{settings.base_url.rstrip('/')}/targets/{target.id}"

    # Discord wants an embed; anybody else's endpoint wants plain JSON they can
    # write a handler against.
    build = (
        build_custom_payload if target.webhook_kind == WebhookKind.CUSTOM else build_digest_payload
    )
    payload = build(project=target.name, findings=findings, dashboard_url=dashboard_url)

    alerts = [
        Alert(
            user_id=user.id,
            match_id=match.id,
            channel=target.webhook_kind,
            # The destination is the channel, not the credential. Storing the
            # webhook URL on every alert row would scatter a secret across a
            # table nobody thinks of as holding one.
            destination=f"{target.webhook_kind}:{target.id}",
            subject=f"{len(sendable)} findings in {target.name}"[:500],
            status="pending",
        )
        for match in sendable
    ]
    for alert in alerts:
        db.add(alert)
    await db.flush()

    result = await post_webhook(
        target.discord_webhook_url, payload, kind=target.webhook_kind, settings=settings
    )

    now = utcnow()
    if result.ok:
        for alert in alerts:
            alert.status = "sent"
            alert.sent_at = now
        target.discord_last_sent_at = now
        target.discord_last_error = None
        return True

    for alert in alerts:
        alert.status = "failed"
        alert.error = (result.error or "Delivery failed")[:2000]
    target.discord_last_error = (result.error or "Delivery failed")[:500]
    return False


def _subject(target: TrackedTarget, matches: list[CVEMatch]) -> str:
    exploited = sum(1 for m in matches if m.is_kev)
    count = len(matches)

    if exploited:
        noun = "vulnerability" if exploited == 1 else "vulnerabilities"
        return f"[Weedout] {exploited} actively exploited {noun} in {target.name}"

    noun = "finding" if count == 1 else "findings"
    return f"[Weedout] {count} new {noun} in {target.name}"


def mark_delivered_in_app(matches: list[CVEMatch]) -> int:
    """Record findings as notified because the user is looking at them.

    Used after the scan that runs when a project is first added, or when the
    user clicks "Check now". They are watching the results render; emailing the
    same list would be the exact behaviour this product exists to avoid. Setting
    `notified_at` also stops the next scheduled scan from treating them as news.
    """
    now = utcnow()
    marked = 0
    for match in matches:
        if match.notified_at is None:
            match.notified_at = now
            marked += 1
    return marked


async def _load_cve_ids(db: AsyncSession, vuln_ids: list[str]) -> dict[str, str]:
    """Map advisory ID to its primary CVE ID, in one query."""
    unique = list(dict.fromkeys(vuln_ids))
    if not unique:
        return {}
    rows = (
        await db.scalars(select(VulnerabilityRecord).where(VulnerabilityRecord.id.in_(unique)))
    ).all()
    return {row.id: row.cve_ids[0] for row in rows if row.cve_ids}


def _render_text(
    base_url: str,
    target: TrackedTarget,
    matches: list[CVEMatch],
    cve_by_vuln_id: dict[str, str],
) -> str:
    """Plain-text digest.

    Written to be readable in a terminal mail client and to lead with the reason
    each item cleared the filter, since that is what tells the reader whether to
    stop what they are doing.
    """
    lines: list[str] = [
        f"Weedout checked {target.name} and found "
        f"{len(matches)} thing{'' if len(matches) == 1 else 's'} worth your attention.",
        "",
    ]

    for match in matches:
        # Prefer a CVE ID — it is what people search for and paste into tickets.
        cve = cve_by_vuln_id.get(match.vulnerability_id, match.vulnerability_id)
        lines.append(f"  {cve} — {match.package_name} {match.package_version}")
        lines.append(f"    Severity: {match.severity.label}")
        lines.append(f"    Why you're seeing this: {_reason_line(match)}")
        if match.fixed_version:
            lines.append(f"    Fix: upgrade to {match.fixed_version} or later")
        else:
            lines.append("    Fix: no patched version published yet")
        if not match.version_exact:
            lines.append(
                f"    Note: your manifest specifies '{match.version_spec}', so this "
                f"assumes the lowest allowed version ({match.package_version})."
            )
        lines.append("")

    lines.extend(
        [
            f"Full details: {base_url}/targets/{target.id}",
            "",
            "Weedout only emails about vulnerabilities that are being exploited in",
            "the wild, or that are severe and reachable in code you ship. Everything",
            "else is filtered and waiting on your dashboard if you want to review it.",
            "",
            f"Manage alert settings: {base_url}/settings",
        ]
    )
    return "\n".join(lines)


def _reason_line(match: CVEMatch) -> str:
    if match.actionable_reason is ActionableReason.EXPLOITED_IN_WILD:
        return "listed by CISA as actively exploited in the wild"
    if match.actionable_reason is ActionableReason.CRITICAL_IN_PRODUCTION:
        return "critical severity in a package that ships to production"
    if match.actionable_reason is ActionableReason.HIGH_SEVERITY_DIRECT:
        return "high severity in a direct dependency you control"
    return "cleared the alerting threshold"
