"""Landing page, dashboard and pricing."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from app.deps import OptionalUser
from app.logging_config import get_logger
from app.services.cli_release_service import REPO as CLI_REPO
from app.services.cli_release_service import go_module, latest_release
from app.templating import render

log = get_logger(__name__)

router = APIRouter(tags=["pages"])

#: The install script, kept as one file rather than two that can disagree.
#: Synced from the CLI repository by scripts/sync_cli.py.
INSTALL_SCRIPT = Path(__file__).resolve().parents[1] / "static" / "install.sh"


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
