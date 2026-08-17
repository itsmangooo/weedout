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

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.types import Tier
from app.db import session_scope
from app.feeds.kev import KevFeedError
from app.logging_config import get_logger
from app.models import User, utcnow
from app.services.admin_service import PAYING_STATUSES
from app.services.alert_service import send_new_match_digest
from app.services.auth_service import purge_expired_sessions
from app.services.feed_service import refresh_kev_catalog
from app.services.mirror_service import sync_all_ecosystems
from app.services.password_reset_service import purge_expired_reset_tokens
from app.services.scan_service import due_targets, scan_target

log = get_logger(__name__)

__all__ = [
    "expire_subscriptions_task",
    "refresh_feeds_task",
    "run_scan_cycle",
    "sweep_sessions_task",
    "sync_mirror_task",
]

# Arbitrary but fixed 64-bit keys; they only need to be unique within the database.
LOCK_SCAN_CYCLE = 0x4E4F495345_01
LOCK_FEED_REFRESH = 0x4E4F495345_02


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
    """Refresh the CISA KEV catalog. Returns the number of rows stored."""
    try:
        async with session_scope() as db:
            async with advisory_lock(db, LOCK_FEED_REFRESH) as acquired:
                if not acquired:
                    log.debug("kev.refresh_skipped_locked")
                    return 0
                return await refresh_kev_catalog(db)
    except KevFeedError as exc:
        # Already recorded on the FeedSync row; the previous snapshot stands.
        log.error("job.kev_refresh_failed", error=str(exc))
        return 0
    except Exception as exc:
        log.exception("job.kev_refresh_crashed", error=str(exc))
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


async def expire_subscriptions_task() -> int:
    """Downgrade users whose paid period has now ended.

    Cancellation is recorded by the Dodo webhook with an effective date in the
    future, so that paid-for time is honoured. This job is what actually applies
    the downgrade once that date passes — without it, a cancelled subscriber
    would keep Pro limits indefinitely.
    """
    try:
        async with session_scope() as db:
            now = utcnow()
            stale = (
                await db.scalars(
                    select(User).where(
                        User.tier == Tier.PRO,
                        User.subscription_ends_at.is_not(None),
                        User.subscription_ends_at <= now,
                        # Shared with the billing view so "still paying" means
                        # the same thing in both places.
                        User.subscription_status.not_in(PAYING_STATUSES),
                    )
                )
            ).all()

            for user in stale:
                user.tier = Tier.FREE
                log.info("billing.downgrade_applied", user_id=user.id)

            return len(stale)
    except Exception as exc:
        log.exception("job.expire_subscriptions_failed", error=str(exc))
        return 0


async def sweep_sessions_task() -> int:
    """Delete expired session rows and spent password-reset tokens.

    Both are dead credentials whose only remaining function is to occupy space.
    Returns the combined number removed.
    """
    try:
        async with session_scope() as db:
            sessions = await purge_expired_sessions(db)
            tokens = await purge_expired_reset_tokens(db)
            if sessions or tokens:
                log.info("job.credentials_purged", sessions=sessions, reset_tokens=tokens)
            return sessions + tokens
    except Exception as exc:
        log.exception("job.session_sweep_failed", error=str(exc))
        return 0
