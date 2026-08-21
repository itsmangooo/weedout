"""Read-only dashboard data for the authenticated React application."""

from __future__ import annotations

from fastapi import APIRouter, Response

from app.deps import CurrentInternalUser, DbSession
from app.schemas import (
    DashboardDataView,
    DashboardProjectFindingsView,
    DashboardProjectView,
    DashboardResponse,
    DashboardSummaryView,
)
from app.services.target_service import dashboard_stats, list_targets

router = APIRouter(prefix="/api/internal", tags=["internal-dashboard"])


@router.get("/dashboard", response_model=DashboardResponse)
async def dashboard(
    response: Response,
    db: DbSession,
    user: CurrentInternalUser,
) -> DashboardResponse:
    """Return the existing ownership-scoped dashboard read model.

    The services own the queries and counts. This handler only copies the
    fields the React view renders into response models that cannot accept ORM
    instances implicitly.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"

    stats = await dashboard_stats(db, user.id)
    summaries = await list_targets(db, user.id)

    projects = [
        DashboardProjectView(
            id=summary.target.id,
            name=summary.target.name,
            ecosystem=summary.target.ecosystem,
            manifest_kind=(
                summary.target.manifest_kind.value if summary.target.manifest_kind else None
            ),
            dependency_count=summary.target.dependency_count,
            is_active=summary.target.is_active,
            has_manifest=summary.target.has_manifest,
            last_scanned_at=summary.target.last_scanned_at,
            last_scan_failed=bool(summary.target.last_scan_error),
            findings=DashboardProjectFindingsView(
                open=summary.open_actionable,
                exploited=summary.exploited,
                filtered=summary.suppressed,
            ),
        )
        for summary in summaries
    ]

    return DashboardResponse(
        data=DashboardDataView(
            summary=DashboardSummaryView(
                projects=stats.targets,
                dependencies=stats.dependencies,
                open_findings=stats.open_alerts,
                exploited_findings=stats.exploited,
                critical_findings=stats.critical,
                filtered_findings=stats.suppressed,
                dismissed_findings=stats.dismissed,
                resolved_findings=stats.resolved,
                filter_rate_percent=stats.noise_ratio,
            ),
            projects=projects,
        )
    )
