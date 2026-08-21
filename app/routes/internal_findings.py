"""Read-only findings for the cookie-authenticated React application."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Response

from app.deps import CurrentInternalUser, DbSession
from app.schemas import (
    FindingAttentionView,
    FindingListMeta,
    FindingListResponse,
    FindingProjectView,
)
from app.services.finding_service import (
    DEFAULT_FINDING_LIMIT,
    FindingShow,
    capped_finding_limit,
    list_findings,
)

router = APIRouter(prefix="/api/internal", tags=["internal-findings"])


@router.get("/findings", response_model=FindingListResponse)
async def findings(
    response: Response,
    db: DbSession,
    user: CurrentInternalUser,
    show: Annotated[FindingShow, Query()] = "open",
    limit: Annotated[int, Query(ge=1)] = DEFAULT_FINDING_LIMIT,
) -> FindingListResponse:
    """Return an ownership-scoped, capped finding list with no ORM leakage."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"

    effective_limit = capped_finding_limit(limit)
    matches = await list_findings(
        db,
        user.id,
        show=show,
        limit=effective_limit,
    )

    data = [
        FindingAttentionView(
            id=match.id,
            project=FindingProjectView(id=match.target.id, name=match.target.name),
            identifier=(
                match.vulnerability.cve_ids[0]
                if match.vulnerability.cve_ids
                else match.vulnerability_id
            ),
            package_name=match.package_name,
            installed_version=match.package_version,
            severity=match.severity,
            is_exploited=match.is_kev,
            reachability=match.reachability,
            status=match.status,
            detected_at=match.first_seen_at,
        )
        for match in matches
    ]

    return FindingListResponse(
        data=data,
        meta=FindingListMeta(
            show=show,
            limit=effective_limit,
            count=len(data),
        ),
    )
