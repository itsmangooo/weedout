"""Landing page, dashboard and pricing."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.logging_config import get_logger

log = get_logger(__name__)

router = APIRouter(tags=["pages"])

INSTALLERS = Path(__file__).resolve().parents[1] / "static"


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
        body = (INSTALLERS / "install.sh").read_text(encoding="utf-8")
    except OSError:
        raise HTTPException(status_code=404, detail="Install script unavailable.") from None

    return Response(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.get("/install.ps1", include_in_schema=False)
async def install_script_powershell() -> Response:
    """Serve the checksum-verifying Windows installer promised by the CLI page."""
    try:
        body = (INSTALLERS / "install.ps1").read_text(encoding="utf-8")
    except OSError:
        raise HTTPException(status_code=404, detail="Install script unavailable.") from None

    return Response(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )
