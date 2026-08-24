"""The public status page, and the things it must not say.

A status page that overstates what it knows is worse than none. This one runs
inside the application it reports on: if the service is down, the page is down
with it, and its silence is the only signal. It is not an uptime monitor.

What it is good for is the failure nothing else catches. An outage is loud. A
stale advisory feed is not — scans keep running, the dashboard keeps rendering,
and every user of that ecosystem is quietly told they are clean.

Most of these are about what does *not* reach a stranger: error strings written
for us, the backup job, and adoption numbers on a deployment that has not
chosen to publish them.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.models import FeedSync, utcnow
from app.services import status_service
from app.services.status_service import DEGRADED, OPERATIONAL, UNKNOWN, public_status


@pytest.fixture(autouse=True)
def _no_cache():
    """The service caches for a minute; a test suite must not share one.

    Cleared before and after, because a status computed by one test leaking
    into the next would make failures depend on ordering.
    """
    status_service._cache.value = None
    status_service._cache.computed_at = 0.0
    yield
    status_service._cache.value = None
    status_service._cache.computed_at = 0.0


async def a_feed(db, name: str, *, hours_ago: float | None = 1.0, records: int = 100, error=None):
    row = FeedSync(
        name=name,
        last_success_at=(utcnow() - timedelta(hours=hours_ago)) if hours_ago is not None else None,
        last_attempt_at=utcnow(),
        last_error=error,
        record_count=records,
    )
    db.add(row)
    await db.flush()
    return row


async def all_feeds_fresh(db):
    """Every feed the health board knows about, synced recently."""
    from app.services.admin_service import KEV_FEED_NAME
    from app.services.mirror_service import MIRRORED_ECOSYSTEMS, mirror_feed_name

    await a_feed(db, KEV_FEED_NAME)
    for ecosystem in MIRRORED_ECOSYSTEMS:
        await a_feed(db, mirror_feed_name(ecosystem))


class TestTheOverallState:
    async def test_a_deployment_that_has_never_synced_is_not_green(self, db):
        """The single most misleading thing this page could do is report
        healthy for "we have no data". A fresh deployment is degraded, because
        anybody scanning against it would get answers built on nothing."""
        assert (await public_status(db)).state == DEGRADED

    def test_unknown_is_reserved_for_having_no_feeds_defined(self):
        """Which should not happen, and would mean something is wrong with the
        code rather than the data."""
        from app.services.status_service import _state

        assert _state(()) == UNKNOWN

    async def test_everything_fresh_is_operational(self, db):
        await all_feeds_fresh(db)

        assert (await public_status(db)).state == OPERATIONAL

    async def test_one_stale_feed_degrades_the_whole_page(self, db):
        """Per ecosystem rather than aggregated. One green "OSV" row while the
        Go export has been failing for a week is the same lie in a nicer
        font."""
        from sqlalchemy import select

        from app.services.mirror_service import MIRRORED_ECOSYSTEMS, mirror_feed_name

        await all_feeds_fresh(db)
        stale = await db.scalar(
            select(FeedSync).where(FeedSync.name == mirror_feed_name(MIRRORED_ECOSYSTEMS[0]))
        )
        stale.last_success_at = utcnow() - timedelta(days=30)
        await db.flush()

        status = await public_status(db)

        assert status.state == DEGRADED
        assert len(status.stale_feeds) == 1
        assert len(MIRRORED_ECOSYSTEMS) >= 1

    async def test_a_feed_that_never_ran_counts_as_stale(self, db):
        """Not unknown. A feed with no successes is not in an indeterminate
        state — it is not working."""
        from app.services.admin_service import KEV_FEED_NAME

        await a_feed(db, KEV_FEED_NAME, hours_ago=None)

        status = await public_status(db)

        assert status.state == DEGRADED
        assert status.feeds[0].hours_behind is None
        assert status.feeds[0].is_stale is True

    async def test_there_is_no_down_state(self, db):
        """Offering the word would imply the page can detect something it
        cannot. If the service were down, this response would not exist."""
        await all_feeds_fresh(db)

        assert (await public_status(db)).state in {OPERATIONAL, DEGRADED, UNKNOWN}


class TestWhatIsNotPublished:
    async def test_error_strings_never_reach_the_page(self, db):
        """They are written for us, and they name paths, hostnames and library
        internals. A visitor can act on "this feed is behind"; they cannot act
        on a traceback, and it tells somebody where the database lives."""
        from app.services.admin_service import KEV_FEED_NAME

        await a_feed(
            db,
            KEV_FEED_NAME,
            error="psycopg.OperationalError: connection to server at 10.0.1.7 failed",
        )

        status = await public_status(db)

        rendered = repr(status)
        assert "10.0.1.7" not in rendered
        assert "psycopg" not in rendered

    async def test_the_backup_job_is_not_a_public_feed(self, db, monkeypatch):
        """Whether our backups ran is a real operational concern and none of a
        visitor's business."""
        from app.config import get_settings
        from app.services.backup_service import BACKUP_FEED_NAME

        settings = get_settings()
        monkeypatch.setattr(settings, "backup_enabled", True)
        await all_feeds_fresh(db)
        await a_feed(db, BACKUP_FEED_NAME, hours_ago=500)

        status = await public_status(db)

        assert all("backup" not in feed.label.lower() for feed in status.feeds)
        # And a failing backup must not turn the public page yellow: it would
        # tell users something is wrong with their scans when nothing is.
        assert status.state == OPERATIONAL

    async def test_adoption_is_withheld_by_default(self, db):
        """On a product with three accounts the numbers undersell, and on a
        page whose whole purpose is being trusted, a number chosen to flatter
        would poison the rest of it. So it is a switch, not a rounding rule."""
        await all_feeds_fresh(db)

        status = await public_status(db)

        assert status.accounts is None
        assert status.projects is None

    async def test_adoption_appears_when_switched_on(self, db, user, monkeypatch):
        from app.config import get_settings

        monkeypatch.setattr(get_settings(), "status_show_adoption", True)
        await all_feeds_fresh(db)

        status = await public_status(db)

        assert status.accounts == 1
        assert status.projects == 0


class TestWhatIsPublished:
    async def test_record_counts_are_shown(self, db):
        """A feed can succeed and still be broken. An export that starts
        returning near-nothing is invisible without this."""
        from app.services.admin_service import KEV_FEED_NAME

        await a_feed(db, KEV_FEED_NAME, records=1247)

        assert (await public_status(db)).feeds[0].record_count == 1247

    async def test_the_staleness_window_is_published_with_the_number(self, db):
        """So the number has a scale. Eight hours is fine for a daily export
        and alarming for an hourly one."""
        await all_feeds_fresh(db)

        assert all(feed.stale_after_hours > 0 for feed in (await public_status(db)).feeds)

    async def test_recent_scans_show_the_scheduler_is_alive(self, db, user):
        """Nothing else on the page would reveal a scheduler that stopped."""
        from app.models import ScanRun
        from tests.test_api import make_target

        target = await make_target(db, user)
        db.add(ScanRun(target_id=target.id, status="ok"))
        db.add(ScanRun(target_id=target.id, status="ok"))
        await db.flush()

        assert (await public_status(db)).scans_24h == 2

    async def test_a_failed_scan_is_not_counted_as_activity(self, db, user):
        from app.models import ScanRun
        from tests.test_api import make_target

        target = await make_target(db, user)
        db.add(ScanRun(target_id=target.id, status="failed"))
        await db.flush()

        assert (await public_status(db)).scans_24h == 0

    async def test_scans_from_last_week_are_not_recent(self, db, user):
        from app.models import ScanRun
        from tests.test_api import make_target

        target = await make_target(db, user)
        old = ScanRun(target_id=target.id, status="ok")
        db.add(old)
        await db.flush()
        old.started_at = utcnow() - timedelta(days=7)
        await db.flush()

        assert (await public_status(db)).scans_24h == 0


class TestCaching:
    async def test_a_second_call_does_not_recompute(self, db):
        """This is the page people load when they think something is wrong,
        which is exactly when the database can least afford six aggregates per
        visitor. A status page that becomes part of the outage is worse than
        none."""
        await all_feeds_fresh(db)
        first = await public_status(db)

        from app.services.admin_service import KEV_FEED_NAME

        changed = await a_feed(db, f"{KEV_FEED_NAME}-2")
        second = await public_status(db)

        assert second is first
        assert changed is not None

    async def test_refresh_recomputes(self, db):
        await all_feeds_fresh(db)
        first = await public_status(db)
        second = await public_status(db, refresh=True)

        assert second is not first
        assert second.state == first.state


class TestThroughTheEndpoint:
    async def test_a_stranger_can_read_it(self, client, db):
        """A status page you have to sign in to read is not a status page. The
        people most likely to load it are the ones who cannot get in."""
        await all_feeds_fresh(db)
        await db.commit()

        response = await client.get("/api/internal/status")

        assert response.status_code == 200, response.text
        assert response.json()["data"]["state"] == OPERATIONAL

    async def test_it_is_cacheable_by_a_proxy(self, client, db):
        """Public and short. A CDN holding this for a minute is the intended
        behaviour, not a compromise."""
        await db.commit()

        response = await client.get("/api/internal/status")

        assert "public" in response.headers["cache-control"]
        assert "max-age=60" in response.headers["cache-control"]

    async def test_the_shell_is_served_at_status(self, client):
        response = await client.get("/status")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    async def test_no_error_text_survives_to_the_wire(self, client, db):
        from app.services.admin_service import KEV_FEED_NAME

        await a_feed(db, KEV_FEED_NAME, error="Traceback: /srv/weedout/app/mirror.py line 88")
        await db.commit()

        body = (await client.get("/api/internal/status")).text

        assert "Traceback" not in body
        assert "/srv/weedout" not in body

    async def test_adoption_is_null_rather_than_zero_when_withheld(self, client, db, user):
        """A zero would read as "nobody uses this", which is a different claim
        from "we do not publish that"."""
        await db.commit()

        data = (await client.get("/api/internal/status")).json()["data"]

        assert data["accounts"] is None
        assert data["projects"] is None
