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

    A stale KEV catalog is reported but does *not* fail the check: the app still
    serves, scans still run, and briefly-old exploitation data is not a reason
    to take an instance out of rotation.
    """
    checks: dict[str, object] = {"database": "ok", "kev_feed": "unknown"}
    healthy = True

    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        log.error("readyz.database_failed", error=str(exc))
        checks["database"] = "unavailable"
        healthy = False

    if healthy:
        try:
            sync = await db.get(FeedSync, KEV_FEED_NAME)
            if sync is None or sync.last_success_at is None:
                checks["kev_feed"] = "never synced"
            elif sync.is_stale(timedelta(hours=24)):
                checks["kev_feed"] = f"stale (last success {sync.last_success_at.isoformat()})"
            else:
                checks["kev_feed"] = "ok"
                checks["kev_entries"] = sync.record_count
        except Exception as exc:
            log.warning("readyz.kev_check_failed", error=str(exc))
            checks["kev_feed"] = "unknown"

    if not healthy:
        response.status_code = 503

    return {"status": "ok" if healthy else "degraded", "version": __version__, "checks": checks}
