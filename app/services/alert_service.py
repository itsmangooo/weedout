"""Turning new findings into notifications.

Restraint is the feature. Three rules keep the mail volume honest:

* Only matches that triage marked actionable are ever sent.
* Each match notifies once — `CVEMatch.notified_at` is the guard, so a scan that
  re-confirms yesterday's finding sends nothing.
* One scan produces one digest email, not one email per CVE.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.types import ActionableReason, AlertStatus, Verdict
from app.logging_config import get_logger
from app.mail import EmailError, send_email
from app.models import Alert, CVEMatch, TrackedTarget, User, VulnerabilityRecord, utcnow

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
        # notified_at stays unset, so the next scan retries rather than dropping it.
        return 0

    now = utcnow()
    for alert in alerts:
        alert.status = "sent"
        alert.sent_at = now
    for match in sendable:
        match.notified_at = now

    log.info("alert.sent", user_id=user.id, target_id=target.id, matches=len(sendable))
    return len(sendable)


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
