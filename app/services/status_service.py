"""What weedout.dev/status can honestly say about itself.

Start with the limitation, because a status page that overstates what it knows
is worse than no status page: **this runs inside the application it reports
on.** If the service is down, this page is down with it, and its silence is the
only signal. It is not an uptime monitor and must never be presented as one —
that job belongs to something outside the deployment, watching from elsewhere.

What it *is* good for is the failure this product has that nothing else would
catch. A stale advisory feed breaks the core promise without breaking a single
page: scans keep running, the dashboard keeps rendering, and every user of that
ecosystem is quietly told they are clean. An outage is loud. This is not, and
it is the thing worth publishing.

So the page reports freshness per ecosystem rather than one aggregate line. One
green "OSV" row while the Go export had been failing for a week would be the
same lie in a nicer font.

Two things are deliberately absent:

- **Error strings.** They are written for us and leak paths, hostnames and
  library internals. The page says a feed is behind and by how long, which is
  everything a user can act on.
- **Adoption numbers, unless switched on.** `status_show_adoption` is off by
  default: on a product with three accounts those numbers undersell, and on a
  page whose whole purpose is being trusted, a figure chosen to flatter would
  poison everything above it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.logging_config import get_logger
from app.models import ScanRun, TrackedTarget, User, VulnerabilityRecord, utcnow

log = get_logger(__name__)

__all__ = [
    "CACHE_SECONDS",
    "PublicStatus",
    "StatusFeed",
    "public_status",
]

#: How long a computed status is served for.
#:
#: This page is linked from a footer and will be the first thing anybody loads
#: when they think something is wrong, which is exactly when the database is
#: least able to answer six aggregate queries per visitor. A minute is short
#: enough that a recovering feed shows up quickly and long enough that a busy
#: moment does not turn the status page into part of the problem.
CACHE_SECONDS = 60

#: "Operational", "Degraded", "Down" — one word at the top, computed from the
#: rows below rather than set by hand, because a hand-set banner is a banner
#: somebody forgets to change back.
OPERATIONAL = "operational"
DEGRADED = "degraded"
UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class StatusFeed:
    """One upstream feed, as a stranger may see it."""

    label: str
    #: Hours since the last successful sync, or None if it has never run.
    hours_behind: float | None
    #: What "behind" means for this feed. Published so the number has a scale:
    #: eight hours is fine for a daily export and alarming for an hourly one.
    stale_after_hours: int
    #: How many advisories the last successful sync stored. A feed can succeed
    #: and still be broken, and this is what makes that visible.
    record_count: int

    @property
    def is_stale(self) -> bool:
        # Never having run counts as stale. A feed with no successes is not in
        # an unknown state -- it is not working.
        return self.hours_behind is None or self.hours_behind > self.stale_after_hours


@dataclass(frozen=True, slots=True)
class PublicStatus:
    """Everything /status shows."""

    state: str
    feeds: tuple[StatusFeed, ...] = ()
    #: Scans completed in the last 24 hours. The simplest evidence that the
    #: scheduler is alive, which nothing else on the page would reveal.
    scans_24h: int = 0
    #: Advisories currently mirrored, across every ecosystem.
    advisories: int = 0
    #: Adoption, or None where the deployment has not published it.
    accounts: int | None = None
    projects: int | None = None
    #: When this snapshot was computed. Shown, because a cached page that does
    #: not say it is cached is a page that lies for a minute at a time.
    checked_at: datetime = field(default_factory=utcnow)

    @property
    def stale_feeds(self) -> tuple[StatusFeed, ...]:
        return tuple(feed for feed in self.feeds if feed.is_stale)


@dataclass(slots=True)
class _Cache:
    value: PublicStatus | None = None
    computed_at: float = 0.0

    def fresh(self) -> bool:
        return self.value is not None and (time.time() - self.computed_at) < CACHE_SECONDS


_cache = _Cache()


async def public_status(db: AsyncSession, *, refresh: bool = False) -> PublicStatus:
    """The current state, cached for a minute."""
    if not refresh and _cache.fresh():
        return _cache.value  # type: ignore[return-value]

    settings = get_settings()
    feeds = await _feeds(db, settings)

    status = PublicStatus(
        state=_state(feeds),
        feeds=feeds,
        scans_24h=await _scans_since(db, utcnow() - timedelta(hours=24)),
        advisories=await _count(db, VulnerabilityRecord.id),
        accounts=(await _count(db, User.id)) if settings.status_show_adoption else None,
        projects=(await _count(db, TrackedTarget.id)) if settings.status_show_adoption else None,
    )

    _cache.value = status
    _cache.computed_at = time.time()
    return status


def _state(feeds: tuple[StatusFeed, ...]) -> str:
    """One word, derived rather than declared.

    No "down" case: if the service were down this response would not exist, and
    offering the word would imply the page can detect something it cannot.

    A deployment that has never synced comes out `degraded`, not `unknown`, and
    that is correct rather than harsh: the advisory data genuinely is not there,
    and anybody scanning against it would get answers built on nothing.
    `unknown` is reserved for having no feeds defined at all, which should not
    happen and would mean something is wrong with the code rather than the
    data.
    """
    if not feeds:
        return UNKNOWN
    return DEGRADED if any(feed.is_stale for feed in feeds) else OPERATIONAL


async def _feeds(db: AsyncSession, settings) -> tuple[StatusFeed, ...]:
    """The advisory feeds, in the shape a stranger can read.

    Built from the same source the admin board uses, then narrowed: the labels
    are kept, the error strings and attempt timestamps are dropped. A public
    page saying "psycopg.OperationalError: connection to server at ..." helps
    nobody and tells somebody where the database lives.

    The backup job is filtered out for the same reason. Whether our backups ran
    is a real operational concern and none of a visitor's business.
    """
    from app.services.admin_service import feed_health
    from app.services.backup_service import BACKUP_FEED_NAME

    now = utcnow()
    feeds = []
    for row in await feed_health(db):
        # Compared against the constant rather than a name prefix. A prefix
        # match is a filter that silently stops working the day somebody
        # renames the feed, and the failure mode is publishing it.
        if row.name == BACKUP_FEED_NAME:
            continue

        hours = None
        if row.last_success_at is not None:
            hours = round((now - row.last_success_at).total_seconds() / 3600, 1)

        feeds.append(
            StatusFeed(
                label=row.label,
                hours_behind=hours,
                stale_after_hours=row.stale_after_hours,
                record_count=row.record_count,
            )
        )
    return tuple(feeds)


async def _scans_since(db: AsyncSession, since: datetime) -> int:
    return (
        await db.scalar(
            select(func.count(ScanRun.id)).where(
                ScanRun.started_at >= since, ScanRun.status == "ok"
            )
        )
    ) or 0


async def _count(db: AsyncSession, column) -> int:
    return (await db.scalar(select(func.count(column)))) or 0
