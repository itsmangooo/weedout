"""Landing page, dashboard and pricing."""

from __future__ import annotations

from fastapi import APIRouter, Request
from sqlalchemy import desc, select

from app.core.types import AlertStatus, Verdict
from app.deps import CurrentUser, DbSession, OptionalUser, redirect
from app.logging_config import get_logger
from app.models import SEVERITY_RANK, CVEMatch, TrackedTarget
from app.services.docs_service import list_public
from app.services.public_service import LandingData, get_landing_data
from app.services.target_service import dashboard_stats, list_targets
from app.templating import render

log = get_logger(__name__)

router = APIRouter(tags=["pages"])


@router.get("/")
async def landing(request: Request, db: DbSession, user: OptionalUser):
    """Marketing page. Signed-in visitors go straight to their dashboard."""
    if user is not None:
        return redirect("/dashboard")

    # Real findings from real scans, anonymised in the service. If the query
    # fails or the platform is brand new, the section is simply absent — the
    # page never fabricates example data to fill it, because the whole claim
    # of that section is that it is live.
    try:
        landing_data = await get_landing_data(db)
    except Exception as exc:
        log.warning("landing.data_unavailable", error=str(exc))
        landing_data = LandingData()

    return render(
        request,
        "landing.html",
        {
            "page_title": None,
            "landing": landing_data,
            "docs_pages": await list_public(db),
        },
    )


@router.get("/pricing")
async def pricing(request: Request, user: OptionalUser):
    return render(request, "pricing.html", {"page_title": "Pricing"})


@router.get("/dashboard")
async def dashboard(request: Request, db: DbSession, user: CurrentUser):
    """The one screen that answers: what needs my attention, and what didn't."""
    stats = await dashboard_stats(db, user.id)
    summaries = await list_targets(db, user.id)

    open_alerts = list(
        (
            await db.scalars(
                select(CVEMatch)
                .join(TrackedTarget, TrackedTarget.id == CVEMatch.target_id)
                .where(
                    TrackedTarget.user_id == user.id,
                    CVEMatch.verdict == Verdict.ACTIONABLE,
                    CVEMatch.status == AlertStatus.OPEN,
                )
                .order_by(
                    desc(CVEMatch.is_kev),
                    desc(SEVERITY_RANK),
                    desc(CVEMatch.first_seen_at),
                )
                .limit(25)
            )
        ).all()
    )

    target_names = {summary.target.id: summary.target.name for summary in summaries}

    return render(
        request,
        "dashboard.html",
        {
            "page_title": "Dashboard",
            "stats": stats,
            "summaries": summaries,
            "open_alerts": open_alerts,
            "target_names": target_names,
        },
    )
