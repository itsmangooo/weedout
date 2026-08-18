"""APScheduler wiring.

Deliberately not Celery. This workload is a handful of periodic sweeps over a
table that is already in Postgres; adding a broker, a result backend and a
separate worker fleet would be more infrastructure than the job requires, and a
solo maintainer pays for that complexity forever.

The scheduler runs in-process by default. Set ``RUN_SCHEDULER_IN_WEB=false`` and
run `python -m app.jobs.runner loop` in a second container to separate them —
the Postgres advisory lock in `tasks` makes either arrangement safe.
"""

from __future__ import annotations

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.config import Settings
from app.jobs.tasks import (
    backup_task,
    expire_subscriptions_task,
    refresh_feeds_task,
    run_scan_cycle,
    sweep_sessions_task,
    sync_mirror_task,
)
from app.logging_config import get_logger

log = get_logger(__name__)

__all__ = ["build_scheduler"]


def build_scheduler(settings: Settings) -> AsyncIOScheduler:
    """Create a configured, not-yet-started scheduler."""
    scheduler = AsyncIOScheduler(
        timezone="UTC",
        job_defaults={
            # Never run two copies of the same job concurrently, and collapse
            # missed runs after a restart into one rather than replaying them.
            "coalesce": True,
            "max_instances": 1,
            "misfire_grace_time": 300,
        },
    )

    scheduler.add_job(
        refresh_feeds_task,
        trigger=IntervalTrigger(hours=settings.kev_refresh_hours),
        id="refresh_feeds",
        name="Refresh CISA KEV catalog",
        replace_existing=True,
    )

    scheduler.add_job(
        sync_mirror_task,
        trigger=IntervalTrigger(hours=settings.mirror_refresh_hours),
        id="sync_mirror",
        name="Sync the local advisory mirror",
        replace_existing=True,
    )

    scheduler.add_job(
        run_scan_cycle,
        trigger=IntervalTrigger(minutes=settings.scan_tick_minutes),
        id="scan_cycle",
        name="Scan due targets",
        replace_existing=True,
    )

    scheduler.add_job(
        sweep_sessions_task,
        trigger=IntervalTrigger(hours=24),
        id="sweep_sessions",
        name="Purge expired sessions",
        replace_existing=True,
    )

    if settings.backup_enabled:
        scheduler.add_job(
            backup_task,
            trigger=IntervalTrigger(hours=settings.backup_interval_hours),
            id="backup",
            name="Back up the database",
            replace_existing=True,
        )

    scheduler.add_job(
        expire_subscriptions_task,
        trigger=IntervalTrigger(hours=1),
        id="expire_subscriptions",
        name="Apply scheduled subscription downgrades",
        replace_existing=True,
    )

    log.info(
        "scheduler.configured",
        kev_refresh_hours=settings.kev_refresh_hours,
        scan_tick_minutes=settings.scan_tick_minutes,
        backups=settings.backup_enabled,
    )
    return scheduler
