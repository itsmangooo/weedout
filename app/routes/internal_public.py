"""Public data for the React marketing pages.

Unauthenticated by design — this is what the landing page shows a stranger.
It sits under /api/internal because it is the browser's namespace rather than
the CLI's, not because it is private.

What it may contain is decided in `app.services.public_service`, not here.
Every field is already public information: advisory ids and summaries come
from OSV, package names and versions from public registries, and the headline
numbers are rounded so they cannot be used to count customers. There is
deliberately no field that could carry a project name or an account.

The one rule this route adds is the one the rendered page had: a section with
no data is absent rather than padded. An empty "this week" list is an honest
"not enough data yet", and inventing rows to fill it would turn the one
genuinely factual thing on the page into fiction.
"""

from __future__ import annotations

from fastapi import APIRouter, Response

from app.deps import DbSession
from app.logging_config import get_logger
from app.services.docs_service import list_public
from app.services.public_service import LandingData, get_landing_data

log = get_logger(__name__)

router = APIRouter(prefix="/api/internal", tags=["internal-public"])


@router.get("/landing")
async def landing(response: Response, db: DbSession) -> dict:
    """Live, anonymised figures for the landing page."""
    # Cacheable, unlike everything else under this prefix: it is the same for
    # every visitor and carries nothing account-specific. The service caches it
    # too; this lets a CDN or the browser skip the round trip entirely.
    response.headers["Cache-Control"] = "public, max-age=300"

    try:
        data = await get_landing_data(db)
    except Exception as exc:
        # The page renders without this section rather than not at all. It is
        # the one part that is live, and a database hiccup should cost the
        # section, not the whole page.
        log.warning("landing.data_unavailable", error=str(exc))
        data = LandingData()

    return {
        "data": {
            "stats": {
                "advisories_matched": data.stats.advisories_matched,
                "filtered_out": data.stats.filtered_out,
                "filtered_share": data.stats.filtered_share,
                "dependencies_watched": data.stats.dependencies_watched,
                "kev_entries": data.stats.kev_entries,
            },
            # Absent rather than empty when there is nothing to show, so the
            # client renders no section at all instead of an empty one.
            "findings": [
                {
                    "cve_id": finding.cve_id,
                    "package": finding.package,
                    "version": finding.version,
                    "severity": str(finding.severity),
                    "is_kev": finding.is_kev,
                    "summary": finding.summary,
                }
                for finding in data.findings
            ],
            "trending_cves": [
                {
                    "cve_id": entry.cve_id,
                    "summary": entry.summary,
                    "severity": str(entry.severity),
                    "is_kev": entry.is_kev,
                    "project_count": entry.project_count,
                }
                for entry in data.trending_cves
            ],
            "trending_packages": [
                {
                    "ecosystem": package.ecosystem,
                    "name": package.name,
                    "project_count": package.project_count,
                    "advisory_count": package.advisory_count,
                }
                for package in data.trending_packages
            ],
            "docs": [{"slug": page.slug, "title": page.title} for page in await list_public(db)],
        }
    }
