"""Landing page, dashboard and pricing."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from app.deps import CurrentUser, DbSession, OptionalUser, redirect
from app.logging_config import get_logger
from app.services.cli_release_service import REPO as CLI_REPO
from app.services.cli_release_service import go_module, latest_release
from app.services.docs_service import list_public
from app.services.finding_service import list_findings
from app.services.public_service import LandingData, get_landing_data
from app.services.target_service import dashboard_stats, list_targets
from app.templating import render

log = get_logger(__name__)

router = APIRouter(tags=["pages"])

#: The install script, kept as one file rather than two that can disagree.
#: Synced from the CLI repository by scripts/sync_cli.py.
INSTALL_SCRIPT = Path(__file__).resolve().parents[1] / "static" / "install.sh"


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


@router.get("/cli")
async def cli_page(request: Request, user: OptionalUser):
    """The CLI's own page.

    Everything factual on it — the version, the download links, the dependency
    list — is fetched rather than written here, because a hardcoded claim on a
    page about dependency honesty is the worst possible thing to let go stale.
    Both fetches are cached and both degrade to "unavailable" rather than to a
    stale hardcoded copy.
    """
    return render(
        request,
        "cli.html",
        {
            "page_title": "CLI",
            "go_module": go_module(),
            "release": latest_release(),
            "repo": CLI_REPO,
        },
    )


@router.get("/install.sh", include_in_schema=False)
async def install_script() -> Response:
    """Serve the install script at the address the docs promise.

    `curl -sSL https://weedout.dev/install.sh | sh` has to keep working, so the
    canonical copy lives in the CLI repository and is served from here rather
    than being a second copy that can drift. Plain text, never an attachment —
    a browser should show it, because anyone sensible reads a script before
    piping it into a shell.
    """
    try:
        body = INSTALL_SCRIPT.read_text(encoding="utf-8")
    except OSError:
        raise HTTPException(status_code=404, detail="Install script unavailable.") from None

    return Response(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.get("/dashboard/legacy")
async def legacy_dashboard(request: Request, db: DbSession, user: CurrentUser):
    """Temporary protected rollback route for the server-rendered dashboard."""
    stats = await dashboard_stats(db, user.id)
    summaries = await list_targets(db, user.id)

    open_alerts = await list_findings(db, user.id, show="open", limit=25)

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
