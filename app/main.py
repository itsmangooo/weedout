"""FastAPI application factory.

Wires configuration, logging, routes, error handling and (optionally) the
background scheduler into one ASGI app.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import Settings, get_settings
from app.db import configure_event_loop_policy, dispose_engine
from app.deps import RedirectToLogin
from app.logging_config import configure_logging, get_logger
from app.routes import (
    admin,
    alerts,
    api,
    auth,
    billing,
    contact,
    docs,
    events,
    frontend,
    health,
    internal_auth,
    internal_auth_actions,
    internal_dashboard,
    internal_findings,
    pages,
    targets,
)
from app.templating import render

log = get_logger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start and stop process-wide resources."""
    settings: Settings = app.state.settings
    scheduler = None

    # Starter documentation, created once and never overwritten. Idempotent by
    # slug, so a deployment that already has these pages — edited or not — is
    # left alone. Failure here must not stop the app from serving.
    try:
        from app.db import session_scope
        from app.services.docs_service import seed_starter_pages

        async with session_scope() as db:
            created = await seed_starter_pages(db)
        if created:
            log.info("app.docs_seeded", pages=created)
    except Exception as exc:
        log.warning("app.docs_seed_failed", error=str(exc))

    # First administrator, if this deployment has none. Idempotent and holds an
    # advisory lock, so replicas starting together and restart loops cannot
    # create two or re-send a password. A failure here must not stop the app
    # from serving — `python -m app.manage ensure-admin` retries it, and
    # `promote-admin` is always available as the manual path.
    try:
        from app.db import session_scope
        from app.services.bootstrap_service import ensure_admin

        async with session_scope() as db:
            outcome = await ensure_admin(db, settings)
            if outcome.changed:
                await db.commit()
        if outcome.action != "noop":
            log.info("app.admin_bootstrap", action=outcome.action, detail=outcome.detail)
    except Exception as exc:
        log.warning("app.admin_bootstrap_failed", error=str(exc))

    if settings.run_scheduler_in_web:
        # Imported here so a web process with the scheduler disabled never pays
        # for APScheduler at import time.
        from app.jobs.scheduler import build_scheduler
        from app.jobs.tasks import refresh_feeds_task

        scheduler = build_scheduler(settings)
        scheduler.start()
        app.state.scheduler = scheduler
        log.info("app.scheduler_started")

        # Warm the KEV cache so a fresh deployment is not blind until the first
        # scheduled interval elapses. Failure here must not block startup.
        try:
            await refresh_feeds_task()
        except Exception as exc:
            log.warning("app.initial_kev_refresh_failed", error=str(exc))

    # Configuration that is legal but probably unintended. Hard failures are
    # raised by the settings validator before we ever get here; these are the
    # ones with a legitimate use during a rollout, so they are announced rather
    # than fatal. Logged one per line at WARNING so they are greppable and hard
    # to scroll past.
    for warning in settings.production_warnings:
        log.warning("app.config_warning", detail=warning)

    log.info(
        "app.started",
        environment=settings.environment,
        scheduler=bool(scheduler),
        email_backend=settings.email_backend,
        billing=settings.dodo_enabled,
    )

    try:
        yield
    finally:
        if scheduler is not None:
            scheduler.shutdown(wait=False)
            log.info("app.scheduler_stopped")
        await dispose_engine()
        log.info("app.stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)
    # Must happen before uvicorn creates its event loop; see the docstring.
    configure_event_loop_policy()

    app = FastAPI(
        title="Weedout",
        description="A reachable-CVE watchlist for small dev teams.",
        version="0.1.0",
        lifespan=lifespan,
        # The HTML app is the product; the interactive API docs would only
        # expose form endpoints out of context.
        docs_url="/api/docs" if settings.debug else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.debug else None,
    )
    app.state.settings = settings

    # No signed-cookie session middleware: the only thing that used it was
    # Authlib's OAuth state, and application login has never relied on it —
    # sessions are database rows carrying an opaque token. One fewer cookie
    # leaving the server, and one fewer thing holding the secret key.

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(frontend.router)
    app.include_router(health.router)
    app.include_router(internal_auth.router)
    app.include_router(internal_auth_actions.router)
    app.include_router(internal_dashboard.router)
    app.include_router(internal_findings.router)
    app.include_router(pages.router)
    app.include_router(auth.router)
    app.include_router(targets.router)
    app.include_router(alerts.router)
    app.include_router(billing.router)
    app.include_router(contact.router)
    app.include_router(docs.router)
    app.include_router(admin.router)
    app.include_router(api.router)
    app.include_router(events.router)

    _register_middleware(app)
    _register_error_handlers(app)

    return app


def _register_middleware(app: FastAPI) -> None:
    settings: Settings = app.state.settings

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        """Tag every log line in a request with the same request id."""
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        structlog.contextvars.bind_contextvars(
            request_id=request_id, method=request.method, path=request.url.path
        )
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:
            # Deliberately without the traceback: the `Exception` handler below
            # logs that, and doing it here as well wrote every 500 to the log
            # twice, doubling the volume of exactly the entries someone is
            # trying to read. This line exists to close out the request context.
            log.error("request.unhandled", error=type(exc).__name__)
            structlog.contextvars.clear_contextvars()
            raise

        duration_ms = round((time.perf_counter() - started) * 1000, 1)
        response.headers["X-Request-ID"] = request_id

        if not request.url.path.startswith("/static"):
            log.info("request", status=response.status_code, duration_ms=duration_ms)
        structlog.contextvars.clear_contextvars()
        return response

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        # No inline <script> is used anywhere, so script-src can stay strict.
        # 'unsafe-inline' for styles covers the few inline style attributes used
        # for progress bars and chart segments.
        #
        # Dodo uses a hosted checkout on its own domain rather than an embedded
        # SDK, so unlike the previous provider this needs no third-party script
        # or frame source at all — the policy stays strict even when billing is
        # switched on, and `form-action` allows the redirect out to checkout.
        script_src = "'self'"
        frame_src = "'none'"
        connect_src = "'self'"
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            f"script-src {script_src}; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            f"connect-src {connect_src}; "
            f"frame-src {frame_src}; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )
        if settings.cookie_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


def _wants_html(request: Request) -> bool:
    if request.url.path.startswith(("/api/", "/webhooks/")):
        return False
    return "text/html" in request.headers.get("accept", "")


def _register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RedirectToLogin)
    async def handle_redirect_to_login(request: Request, exc: RedirectToLogin):
        next_url = exc.next_url or "/dashboard"
        return RedirectResponse(url=f"/login?next={next_url}", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException):
        if exc.status_code >= 500:
            log.error("http.server_error", status=exc.status_code, detail=str(exc.detail))

        # A dict detail is already a structured API error — pass it through
        # rather than stringifying it, which would hand the client a Python
        # repr of a dict and no way to branch on the failure.
        if isinstance(exc.detail, dict):
            return JSONResponse(
                exc.detail, status_code=exc.status_code, headers=getattr(exc, "headers", None)
            )

        if _wants_html(request):
            return render(
                request,
                "error.html",
                {
                    "status_code": exc.status_code,
                    "title": _error_title(exc.status_code),
                    "message": str(exc.detail),
                },
                status_code=exc.status_code,
            )
        return JSONResponse(
            {"error": str(exc.detail)},
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError):
        """Turn Pydantic's error list into one readable sentence."""
        problems = []
        for error in exc.errors():
            field = ".".join(str(part) for part in error["loc"] if part not in ("body", "query"))
            problems.append(f"{field}: {error['msg']}" if field else error["msg"])
        message = "; ".join(problems) or "The submitted data was not valid."

        if _wants_html(request):
            return render(
                request,
                "error.html",
                {"status_code": 422, "title": "That didn't look right", "message": message},
                status_code=422,
            )
        if request.url.path.startswith("/api/internal/"):
            return JSONResponse(
                {
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": message,
                    }
                },
                status_code=422,
                headers={"Cache-Control": "private, no-store", "Vary": "Cookie"},
            )
        return JSONResponse({"error": message}, status_code=422)

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception):
        """Last resort: log the traceback, show the user something calm."""
        log.exception("unhandled_exception", error=str(exc))
        if _wants_html(request):
            return render(
                request,
                "error.html",
                {
                    "status_code": 500,
                    "title": "Something broke on our side",
                    "message": "This has been logged. Try again in a moment.",
                },
                status_code=500,
            )
        return JSONResponse({"error": "Internal server error"}, status_code=500)


def _error_title(status_code: int) -> str:
    return {
        400: "Bad request",
        403: "Not allowed",
        404: "Page not found",
        405: "Method not allowed",
        413: "That file is too large",
        429: "Slow down a moment",
        500: "Something broke on our side",
        503: "Temporarily unavailable",
    }.get(status_code, "Something went wrong")


app = create_app()
