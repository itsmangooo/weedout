"""Ownership-scoped finding reads shared by HTML and internal APIs."""

from __future__ import annotations

from typing import Literal

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager

from app.core.types import AlertStatus, Verdict
from app.models import SEVERITY_RANK, CVEMatch, TrackedTarget

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


def capped_finding_limit(limit: int) -> int:
    """Apply the server-owned upper bound even outside FastAPI validation."""
    return min(max(limit, 1), MAX_FINDING_LIMIT)


async def list_findings(
    db: AsyncSession,
    user_id: int,
    *,
    show: FindingShow = "open",
    limit: int = DEFAULT_FINDING_LIMIT,
) -> list[CVEMatch]:
    """Return one user's findings in the legacy urgency order.

    Ownership, status/verdict filtering, ordering, and the result cap live in
    this query so the Jinja dashboard and React API cannot drift apart. The
    joined target is eagerly populated for safe project serialization without
    a second lookup or an async lazy load.
    """
    try:
        filters = _FILTERS[show]
    except KeyError as exc:
        raise ValueError(f"Unsupported finding filter: {show}") from exc

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
