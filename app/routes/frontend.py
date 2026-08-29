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
    "/cli-auth",
    "/settings",
    "/pricing",
    "/status",
    "/terms",
    "/privacy",
    "/cli",
    "/contact",
    "/docs",
    "/docs/{slug}",
    "/alerts/{match_id}",
    "/admin",
    "/admin/users",
    "/admin/users/{user_id}",
    "/admin/billing",
    "/admin/inbox",
    "/admin/inbox/{message_id}",
    "/admin/email",
    "/admin/docs",
    "/admin/docs/new",
    "/admin/docs/{page_id}",
    "/admin/audit",
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


@router.get("/billing", include_in_schema=False)
async def billing_entry():
    return redirect("/settings")


@router.get("/billing/success", include_in_schema=False)
async def billing_success_entry():
    """Where Dodo returns somebody after checkout.

    The address is kept rather than folded into /billing with a query
    parameter, because it is baked into every checkout link already issued —
    including any open in a browser tab right now. Changing it would turn a
    payment that has just succeeded into a 404.
    """
    return redirect("/settings")


@router.get("/terms", include_in_schema=False)
async def terms_entry() -> FileResponse:
    return _shell()


@router.get("/privacy", include_in_schema=False)
async def privacy_entry() -> FileResponse:
    return _shell()


@router.get("/status", include_in_schema=False)
async def status_entry() -> FileResponse:
    """The public status page. No session, and none implied."""
    return _shell()


@router.get("/cli-auth", include_in_schema=False)
async def cli_auth_entry() -> FileResponse:
    """Where `weedout auth` sends somebody to approve a machine.

    A plain page load, not a link from anywhere in the product: the URL is
    printed in a terminal and opened by hand, so it has to work as a first
    request into the application.
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


# ---------------------------------------------------------------------------
# The admin panel
#
# Shell routes like every other, and deliberately not behind `require_admin`.
# The shell holds no data: what a non-admin gets here is an empty page that
# immediately asks `/api/internal/auth/me` and renders "not allowed". Every
# byte of admin data comes from `/api/internal/admin/*`, which does enforce it.
#
# Guarding these would mean two places that have to agree about who is an
# administrator, and the redirect a guard produces is useless to the router
# that would receive it.
# ---------------------------------------------------------------------------


@router.get("/admin", include_in_schema=False)
async def admin_entry() -> FileResponse:
    return _shell()


@router.get("/admin/users", include_in_schema=False)
async def admin_users_entry() -> FileResponse:
    return _shell()


@router.get("/admin/users/{user_id}", include_in_schema=False)
async def admin_user_entry(user_id: int) -> FileResponse:
    return _shell()


@router.get("/admin/billing", include_in_schema=False)
async def admin_billing_entry() -> FileResponse:
    return _shell()


@router.get("/admin/inbox", include_in_schema=False)
async def admin_inbox_entry() -> FileResponse:
    return _shell()


@router.get("/admin/inbox/{message_id}", include_in_schema=False)
async def admin_message_entry(message_id: int) -> FileResponse:
    return _shell()


@router.get("/admin/email", include_in_schema=False)
async def admin_email_entry() -> FileResponse:
    return _shell()


@router.get("/admin/docs", include_in_schema=False)
async def admin_docs_entry() -> FileResponse:
    return _shell()


@router.get("/admin/docs/new", include_in_schema=False)
async def admin_doc_new_entry() -> FileResponse:
    """Registered before the id route, so "new" is the create form.

    The id route is typed as an int as well, so both halves of the protection
    are in place: order decides it, and a type makes a mismatch a 422 rather
    than a shell that then fails to load a page called "new".
    """
    return _shell()


@router.get("/admin/docs/{page_id}", include_in_schema=False)
async def admin_doc_entry(page_id: int) -> FileResponse:
    return _shell()


@router.get("/admin/audit", include_in_schema=False)
async def admin_audit_entry() -> FileResponse:
    return _shell()
