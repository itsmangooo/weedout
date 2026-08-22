"""Explicit production entry points for the incrementally migrated frontend."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.deps import OptionalUser, redirect

router = APIRouter(tags=["frontend"])

# The container build copies Vite here. The source-tree fallback supports a
# local `npm run build` without placing generated files inside the Python
# package. Neither location is a source asset or committed application code.
_APP_DIR = Path(__file__).resolve().parents[1]
_CONTAINER_DIST = _APP_DIR / "frontend_dist"
_SOURCE_DIST = _APP_DIR.parent / "frontend" / "dist"
FRONTEND_DIST_DIR = _CONTAINER_DIST if _CONTAINER_DIST.is_dir() else _SOURCE_DIST
FRONTEND_INDEX = FRONTEND_DIST_DIR / "index.html"
FRONTEND_ASSETS_DIR = FRONTEND_DIST_DIR / "assets"


def _safe_asset_path(asset_path: str) -> Path | None:
    root = FRONTEND_ASSETS_DIR.resolve()
    candidate = (root / asset_path).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    return candidate


@router.get("/assets/{asset_path:path}", include_in_schema=False)
async def frontend_asset(asset_path: str) -> FileResponse:
    """Serve content-hashed Vite output with immutable caching."""
    path = _safe_asset_path(asset_path)
    if path is None:
        raise HTTPException(status_code=404, detail="Frontend asset not found.")

    return FileResponse(
        path,
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


#: URLs the React application owns.
#:
#: Listed one by one rather than served by a catch-all, and that is deliberate
#: while the migration is in progress. A catch-all would swallow every path
#: that has not been built in React yet, turning a working server-rendered page
#: into the React 404 the moment someone mistypes a route name here. An
#: explicit list fails the other way: a route that is missing from it keeps
#: serving the page it always did.
SHELL_ROUTES = (
    "/",
    "/dashboard",
    "/login",
    "/login/2fa",
    "/signup",
    "/forgot-password",
    "/reset-password",
    "/targets/new",
    "/targets/{target_id}",
    "/alerts",
    "/settings",
    "/pricing",
    "/cli",
    "/contact",
    "/docs",
    "/docs/{slug}",
    "/alerts/{match_id}",
)


def _shell() -> FileResponse:
    """Serve the React shell.

    The shell holds no user data, so serving it to anonymous, expired and
    signed-in callers alike is safe and is what lets the React auth boundary
    tell those states apart through `/api/internal/auth/me` — which also clears
    a stale cookie and bootstraps CSRF on the way past.
    """
    if not FRONTEND_INDEX.is_file():
        raise HTTPException(
            status_code=503,
            detail="The application frontend is temporarily unavailable.",
        )

    return FileResponse(
        FRONTEND_INDEX,
        media_type="text/html",
        headers={"Cache-Control": "private, no-store", "Vary": "Cookie"},
    )


@router.get("/", include_in_schema=False)
async def landing_entry(user: OptionalUser):
    """The marketing page, or a redirect for somebody already signed in.

    The redirect is kept from the rendered version rather than reasoned away.
    Somebody with a session who types the bare domain wants their dashboard,
    and changing that during a migration would be a product decision smuggled
    in as a refactor.

    It is the one shell route that reads the session, which is why it is not
    in the plain list above.
    """
    if user is not None:
        return redirect("/dashboard")
    return _shell()


@router.get("/dashboard", include_in_schema=False)
async def dashboard_entry() -> FileResponse:
    return _shell()


@router.get("/login", include_in_schema=False)
async def login_entry() -> FileResponse:
    return _shell()


@router.get("/login/2fa", include_in_schema=False)
async def two_factor_entry() -> FileResponse:
    return _shell()


@router.get("/signup", include_in_schema=False)
async def signup_entry() -> FileResponse:
    return _shell()


@router.get("/forgot-password", include_in_schema=False)
async def forgot_password_entry() -> FileResponse:
    return _shell()


@router.get("/reset-password", include_in_schema=False)
async def reset_password_entry() -> FileResponse:
    return _shell()


@router.get("/targets/new", include_in_schema=False)
async def new_project_entry() -> FileResponse:
    return _shell()


@router.get("/pricing", include_in_schema=False)
async def pricing_entry() -> FileResponse:
    return _shell()


@router.get("/cli", include_in_schema=False)
async def cli_entry() -> FileResponse:
    return _shell()


@router.get("/contact", include_in_schema=False)
async def contact_entry() -> FileResponse:
    return _shell()


@router.get("/docs", include_in_schema=False)
async def docs_entry() -> FileResponse:
    return _shell()


@router.get("/docs/{slug}", include_in_schema=False)
async def docs_article_entry(slug: str) -> FileResponse:
    """A documentation page.

    Served for any slug. Whether the page exists is the API's answer, not this
    route's — a draft and a page that never existed have to be
    indistinguishable, and deciding it here would mean two places that must
    agree about what "published" means.
    """
    return _shell()


@router.get("/settings", include_in_schema=False)
async def settings_entry() -> FileResponse:
    return _shell()


@router.get("/alerts", include_in_schema=False)
async def alerts_entry() -> FileResponse:
    return _shell()


@router.get("/alerts/{match_id}", include_in_schema=False)
async def alert_entry(match_id: int) -> FileResponse:
    return _shell()


@router.get("/targets/{target_id}", include_in_schema=False)
async def project_entry(target_id: int) -> FileResponse:
    """The project page.

    `target_id` is declared as an int so that `/targets/new` cannot be matched
    here — FastAPI tries routes in registration order and the literal path is
    registered first, but typing this one means a stray `/targets/anything`
    is a 422 rather than a shell that then fails to load a project.
    """
    return _shell()
