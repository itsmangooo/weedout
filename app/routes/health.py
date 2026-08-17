"""Liveness and readiness endpoints."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Response
from sqlalchemy import text

from app import __version__
from app.deps import DbSession
from app.logging_config import get_logger
from app.models import FeedSync
from app.services.feed_service import KEV_FEED_NAME

log = get_logger(__name__)

router = APIRouter(tags=["health"])


@router.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    """Liveness: is the process up? Deliberately touches nothing external."""
    return {"status": "ok", "version": __version__}


@router.get("/readyz", include_in_schema=False)
async def readyz(db: DbSession, response: Response) -> dict[str, object]:
    """Readiness: can this instance actually serve traffic?

    The database is a hard requirement — without it nothing works, so a failure
    returns 503 and a load balancer should stop sending traffic here.

    Feed state is reported but does *not* fail the check. The app still serves,
    the dashboard still renders, and briefly-old advisory data is not a reason
    to take an instance out of rotation — it is a reason to look at the admin
    panel, which is where feed health is presented properly.

    This endpoint is unauthenticated, so it deliberately reports *states*
    rather than details: "unavailable" rather than the driver's error, and
    counts and ages rather than anything about how the app is wired together.
    An exception string from a failed connection can carry the host, port and
    user it tried, which is not something to hand to anonymous callers.
    """
    checks: dict[str, object] = {"database": "ok", "kev_feed": "unknown"}
    healthy = True

    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        # The detail goes to the log, never to the response.
        log.error("readyz.database_failed", error=str(exc))
        checks["database"] = "unavailable"
        healthy = False

    if healthy:
        try:
            sync = await db.get(FeedSync, KEV_FEED_NAME)
            if sync is None or sync.last_success_at is None:
                checks["kev_feed"] = "never synced"
            elif sync.is_stale(timedelta(hours=24)):
                checks["kev_feed"] = "stale"
            else:
                checks["kev_feed"] = "ok"
            checks["kev_entries"] = sync.record_count if sync else 0
        except Exception as exc:
            log.warning("readyz.kev_check_failed", error=str(exc))
            checks["kev_feed"] = "unknown"

        # The advisory mirror is what scans actually read. An empty one makes
        # every scan fail loudly rather than report a false all-clear, so it is
        # worth surfacing here as well as in the admin panel.
        try:
            checks["advisory_mirror"] = await _mirror_state(db)
        except Exception as exc:
            log.warning("readyz.mirror_check_failed", error=str(exc))
            checks["advisory_mirror"] = "unknown"

    if not healthy:
        response.status_code = 503

    return {"status": "ok" if healthy else "degraded", "version": __version__, "checks": checks}


async def _mirror_state(db) -> str:
    """One word for the state of the advisory mirror.

    "empty" is the one that matters: with no advisories loaded every scan
    refuses rather than reporting projects clean, so a deployment in that state
    is serving pages but not doing its job.
    """
    from app.config import get_settings
    from app.services.mirror_service import (
        MIRRORED_ECOSYSTEMS,
        mirror_feed_name,
        mirror_is_populated,
    )

    if not await mirror_is_populated(db):
        return "empty"

    max_age = timedelta(hours=get_settings().mirror_stale_after_hours)
    for ecosystem in MIRRORED_ECOSYSTEMS:
        sync = await db.get(FeedSync, mirror_feed_name(ecosystem))
        if sync is None or sync.last_success_at is None or sync.is_stale(max_age):
            return "stale"
    return "ok"
