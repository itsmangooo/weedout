"""The unit-of-work functions the scheduler and the CLI both call.

Each task owns its own database session and swallows nothing: failures are
logged with context and returned as counts, so one broken target cannot stop
the sweep, and a scheduler tick never raises into APScheduler's executor.

Concurrency is handled with a PostgreSQL advisory lock rather than a job queue.
Two app replicas both running a scheduler is a realistic deployment, and
double-scanning would mean double emails. The lock is taken with
``pg_try_advisory_lock``, so a second worker declines the tick instead of
queueing behind it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import session_scope
from app.feeds.epss import EpssFeedError
from app.feeds.kev import KevFeedError
from app.logging_config import get_logger
from app.models import User
from app.services.alert_service import send_new_match_digest
from app.services.auth_service import purge_expired_sessions
from app.services.backup_service import BackupError, record_outcome, run_backup
from app.services.feed_service import refresh_epss_scores, refresh_kev_catalog
from app.services.mirror_service import sync_all_ecosystems
from app.services.package_metadata_service import refresh_package_metadata
from app.services.password_reset_service import purge_expired_reset_tokens
from app.services.rate_limit_service import purge_expired_rate_limits
from app.services.scan_service import due_targets, scan_target

log = get_logger(__name__)

__all__ = [
    "backup_task",
    "refresh_feeds_task",
    "run_scan_cycle",
    "sweep_sessions_task",
    "sync_mirror_task",
]

# Arbitrary but fixed 64-bit keys; they only need to be unique within the database.
LOCK_SCAN_CYCLE = 0x4E4F495345_01
LOCK_FEED_REFRESH = 0x4E4F495345_02
LOCK_BACKUP = 0x4E4F495345_03
#: Its own key, so an npm sweep cannot block the feed refresh behind it.
LOCK_PACKAGE_METADATA = 0x4E4F495345_04


@asynccontextmanager
async def advisory_lock(db: AsyncSession, key: int) -> AsyncIterator[bool]:
    """Hold a Postgres advisory lock for the block, if it is free.

    Yields False when another process holds it, which the caller should treat as
    "someone else is already doing this" rather than as an error.
    """
    acquired = bool(await db.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}))
    try:
        yield acquired
    finally:
        if acquired:
            await db.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})


async def refresh_feeds_task() -> int:
    """Refresh the CISA KEV catalog and the EPSS scores.

    Two independent feeds under one lock and one schedule. Independent
    deliberately: EPSS being unreachable must not cost the KEV refresh, because
    KEV is what promotes a finding to an alert and EPSS only annotates one.
    """
    stored = 0
    try:
        async with session_scope() as db:
            async with advisory_lock(db, LOCK_FEED_REFRESH) as acquired:
                if not acquired:
                    log.debug("feeds.refresh_skipped_locked")
                    return 0

                try:
                    stored += await refresh_kev_catalog(db)
                except KevFeedError as exc:
                    # Already recorded on the FeedSync row; the previous
                    # snapshot stands.
                    log.error("job.kev_refresh_failed", error=str(exc))

                try:
                    stored += await refresh_epss_scores(db)
                except EpssFeedError as exc:
                    log.error("job.epss_refresh_failed", error=str(exc))

                return stored
    except Exception as exc:
        log.exception("job.feed_refresh_crashed", error=str(exc))
        return stored


async def refresh_package_metadata_task() -> int:
    """Top up the package-metadata cache. Returns the number fetched.

    Separate from the feed refresh because it is a different kind of work: many
    small requests to two third-party registries rather than one large file
    from a feed. Sharing a schedule would mean an npm outage delaying the KEV
    catalogue.
    """
    try:
        async with session_scope() as db:
            async with advisory_lock(db, LOCK_PACKAGE_METADATA) as acquired:
                if not acquired:
                    log.debug("package_metadata.refresh_skipped_locked")
                    return 0
                report = await refresh_package_metadata(db)
                return report.fetched
    except Exception as exc:
        log.exception("job.package_metadata_crashed", error=str(exc))
        return 0


async def sync_mirror_task() -> dict[str, int]:
    """Refresh the local advisory mirror from OSV's ecosystem exports.

    This is the job that makes on-demand scanning possible: it moves the cost
    of talking to OSV out of the request path and onto a schedule, so a CI
    pipeline blocking on a scan never waits on a third party.

    Holds the same advisory lock as the KEV refresh — two workers pulling
    hundreds of megabytes simultaneously would be pure waste.
    """
    stats = {"ecosystems": 0, "stored": 0, "failed": 0}
    try:
        async with session_scope() as db:
            async with advisory_lock(db, LOCK_FEED_REFRESH) as acquired:
                if not acquired:
                    log.debug("mirror.sync_skipped_locked")
                    return stats

                for report in await sync_all_ecosystems(db):
                    stats["ecosystems"] += 1
                    stats["stored"] += report.records_stored
                    if report.errors:
                        stats["failed"] += 1

        log.info("mirror.sync_finished", **stats)
        return stats
    except Exception as exc:
        log.exception("job.mirror_sync_crashed", error=str(exc))
        stats["failed"] += 1
        return stats


async def backup_task() -> dict[str, int]:
    """Take a database dump, prune old ones, and push a copy off-box.

    Holds its own advisory lock: two replicas dumping simultaneously would
    double the load on the database at exactly the moment it is least wanted,
    and the second dump would add nothing.

    Like every other scheduled task this returns rather than raising, so a
    failed backup does not take the scheduler down with it — but unlike most of
    them it logs at ERROR, because nobody finds out a backup stopped working
    until they need one.
    """
    stats = {"ok": 0, "failed": 0, "bytes": 0, "uploaded": 0}
    settings = get_settings()

    if not settings.backup_enabled:
        return stats

    try:
        async with session_scope() as db:
            async with advisory_lock(db, LOCK_BACKUP) as acquired:
                if not acquired:
                    log.debug("backup.skipped_locked")
                    return stats

                try:
                    result = await run_backup(settings)
                except BackupError as exc:
                    log.error("backup.failed", error=str(exc))
                    await record_outcome(db, success=False, error=str(exc))
                    stats["failed"] = 1
                    return stats

                stats["ok"] = 1
                stats["bytes"] = result.size_bytes
                stats["uploaded"] = int(result.uploaded)

                if settings.backup_s3_bucket and not result.uploaded:
                    # The dump exists but never left the machine. Recorded as an
                    # error as well as logged, so the admin health board does not
                    # read green: a local-only backup does not survive the
                    # failure it is most needed for.
                    message = (
                        "dump written but the off-box copy failed; "
                        "this backup exists only on the database host"
                    )
                    log.error("backup.upload_failed", path=str(result.path))
                    await record_outcome(
                        db, success=True, size_bytes=result.size_bytes, error=message
                    )
                else:
                    log.info(
                        "backup.completed",
                        bytes=result.size_bytes,
                        off_box=result.uploaded,
                    )
                    await record_outcome(db, success=True, size_bytes=result.size_bytes)
                return stats
    except Exception as exc:
        log.exception("job.backup_crashed", error=str(exc))
        stats["failed"] = 1
        return stats


async def run_scan_cycle(limit: int | None = None) -> dict[str, int]:
    """Scan every target that is due, then send digests for what is new.

    Each target is committed independently. A long sweep therefore makes steady
    progress rather than risking the whole batch on one final commit, and a
    target that fails does not roll back the ones already scanned.
    """
    stats = {"targets": 0, "failed": 0, "new_matches": 0, "emails": 0}

    async with session_scope() as db:
        async with advisory_lock(db, LOCK_SCAN_CYCLE) as acquired:
            if not acquired:
                log.info("scan_cycle.skipped_locked")
                return stats

            targets = await due_targets(db, limit)
            if not targets:
                log.debug("scan_cycle.nothing_due")
                return stats

            log.info("scan_cycle.started", targets=len(targets))

            for target in targets:
                try:
                    outcome = await scan_target(db, target)
                except Exception as exc:
                    log.exception("scan_cycle.target_crashed", target_id=target.id, error=str(exc))
                    await db.rollback()
                    stats["failed"] += 1
                    continue

                stats["targets"] += 1
                if outcome.failed:
                    stats["failed"] += 1
                stats["new_matches"] += len(outcome.new_matches)

                if outcome.new_matches:
                    user = await db.get(User, target.user_id)
                    if user is not None:
                        try:
                            sent = await send_new_match_digest(
                                db, user, target, outcome.new_matches
                            )
                            stats["emails"] += 1 if sent else 0
                        except Exception as exc:
                            log.exception(
                                "scan_cycle.alert_crashed",
                                target_id=target.id,
                                error=str(exc),
                            )

                # Commit per target so progress survives a later failure.
                await db.commit()

    log.info("scan_cycle.finished", **stats)
    return stats


async def sweep_sessions_task() -> int:
    """Delete expired sessions, spent reset tokens and stale rate-limit hits.

    The first two are dead credentials whose only remaining function is to
    occupy space. The third is bookkeeping: every failed sign-in writes a row,
    so without pruning the table grows for as long as anyone is probing the
    login page. Returns the combined number removed.
    """
    try:
        async with session_scope() as db:
            sessions = await purge_expired_sessions(db)
            tokens = await purge_expired_reset_tokens(db)
            hits = await purge_expired_rate_limits(db)
            if sessions or tokens or hits:
                log.info(
                    "job.credentials_purged",
                    sessions=sessions,
                    reset_tokens=tokens,
                    rate_limit_hits=hits,
                )
            return sessions + tokens + hits
    except Exception as exc:
        log.exception("job.session_sweep_failed", error=str(exc))
        return 0
