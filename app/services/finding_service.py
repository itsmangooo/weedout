"""Ownership-scoped finding reads shared by HTML and internal APIs."""

from __future__ import annotations

from datetime import timedelta
from typing import Literal

from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager

from app.core.types import AlertStatus, Tier, Verdict
from app.models import SEVERITY_RANK, CVEMatch, TrackedTarget, utcnow
from app.tiers import history_cutoff_days

FindingShow = Literal["open", "filtered", "dismissed", "resolved"]

DEFAULT_FINDING_LIMIT = 25
MAX_FINDING_LIMIT = 200

_FILTERS = {
    "open": (
        CVEMatch.verdict == Verdict.ACTIONABLE,
        CVEMatch.status == AlertStatus.OPEN,
    ),
    "filtered": (CVEMatch.verdict == Verdict.SUPPRESSED,),
    "dismissed": (CVEMatch.status == AlertStatus.DISMISSED,),
    "resolved": (CVEMatch.status == AlertStatus.RESOLVED,),
}

#: The archive tabs, and the column that dates each one.
#:
#: Only these are subject to the plan's retention window. Open and filtered
#: findings describe the present -- what is wrong now, and what was decided not
#: to raise -- and are never truncated by plan. Putting a live vulnerability
#: behind a paywall would be an indefensible thing for a security product to
#: do, so the boundary is drawn here rather than left to a `history_days`
#: filter applied uniformly.
_ARCHIVED = {
    "dismissed": CVEMatch.dismissed_at,
    "resolved": CVEMatch.resolved_at,
}


def history_window(tier: Tier | str, show: FindingShow) -> int | None:
    """How many days back this tab reaches, or None where nothing is trimmed.

    Exposed rather than kept private so the interface can say what it is
    showing. An archive that silently ends 30 days ago reads as lost data
    rather than as a plan limit, and the fix for that is one sentence in the
    interface, not a support ticket.
    """
    if show not in _ARCHIVED:
        return None
    return history_cutoff_days(tier)


def capped_finding_limit(limit: int) -> int:
    """Apply the server-owned upper bound even outside FastAPI validation."""
    return min(max(limit, 1), MAX_FINDING_LIMIT)


async def list_findings(
    db: AsyncSession,
    user_id: int,
    *,
    tier: Tier | str,
    show: FindingShow = "open",
    limit: int = DEFAULT_FINDING_LIMIT,
) -> list[CVEMatch]:
    """Return one user's findings in the legacy urgency order.

    Ownership, status/verdict filtering, the retention window, ordering, and
    the result cap live in this query so the Jinja dashboard and internal API
    cannot drift apart. The joined target is eagerly populated for safe project
    serialization without a second lookup or an async lazy load.

    `tier` is keyword-only and has no default deliberately. The plan's
    retention window is applied here rather than by the caller, and a default
    would let a new call site quietly opt out of it.
    """
    try:
        filters = [*_FILTERS[show]]
    except KeyError as exc:
        raise ValueError(f"Unsupported finding filter: {show}") from exc

    days = history_window(tier, show)
    if days is not None:
        dated = _ARCHIVED[show]
        # Undated rows are kept. Both columns are written alongside the status
        # today, so this should not arise -- but a row that somehow has no date
        # has no age either, and dropping it would delete history rather than
        # age it out, which is the one direction this filter must not fail in.
        filters.append(or_(dated.is_(None), dated >= utcnow() - timedelta(days=days)))

    rows = await db.scalars(
        select(CVEMatch)
        .join(CVEMatch.target)
        .options(contains_eager(CVEMatch.target))
        .where(TrackedTarget.user_id == user_id, *filters)
        .order_by(
            desc(CVEMatch.is_kev),
            desc(SEVERITY_RANK),
            desc(CVEMatch.first_seen_at),
        )
        .limit(capped_finding_limit(limit))
    )
    return list(rows.all())
