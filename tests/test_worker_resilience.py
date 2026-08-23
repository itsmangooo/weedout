"""The background worker survives its own failures, and says so.

A worker that dies on a bad upstream response is worse than one that never ran:
scans silently stop, the dashboard keeps rendering yesterday's answers, and
nothing about the running system looks wrong. Every scheduled task therefore
has to absorb its own failures, record them where an operator will see them,
and be retried by the next tick.

The two halves are tested together because either alone is a false comfort —
surviving without recording is a silent outage, and recording without surviving
only records the first one.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
import respx

from app.jobs.tasks import refresh_feeds_task, run_scan_cycle, sweep_sessions_task, sync_mirror_task
from app.models import FeedSync, User, VulnerabilityAffected, VulnerabilityRecord, utcnow
from app.security import hash_password
from app.services.admin_service import feed_health
from app.services.mirror_service import MIRRORED_ECOSYSTEMS, OSV_EXPORT_URL, mirror_feed_name
from tests.conftest import sign_in


@pytest.fixture
async def committed_task_writes():
    """Undo the real writes a scheduled task makes.

    The task functions open their own `session_scope()` on their own
    connection and genuinely commit — that is the behaviour under test, and it
    is also why their rows escape the per-test transaction that rolls
    everything else back. Without this, one task test leaves feed rows and
    advisories behind for every test that runs after it.
    """
    yield
    from sqlalchemy import delete

    from app.db import session_scope

    async with session_scope() as db:
        await db.execute(delete(VulnerabilityAffected))
        await db.execute(delete(VulnerabilityRecord))
        await db.execute(delete(FeedSync))
        await db.commit()


async def upsert_feed(db, **values) -> None:
    """Insert or update a feed row.

    Written as an upsert rather than an insert so these tests do not depend on
    whether something else has already created the row.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    statement = pg_insert(FeedSync).values(**values)
    await db.execute(
        statement.on_conflict_do_update(
            index_elements=[FeedSync.name],
            set_={k: v for k, v in values.items() if k != "name"},
        )
    )
    await db.flush()


@pytest.fixture
async def admin_client(client, db):
    """A client signed in as an administrator."""
    admin = User(
        email="ops@example.com",
        password_hash=hash_password("correct-horse-battery"),
        is_admin=True,
    )
    db.add(admin)
    await db.flush()

    response = await sign_in(client, admin.email)
    assert response.status_code == 200, response.text
    return client


@pytest.mark.usefixtures("committed_task_writes")
class TestTasksSurviveFailure:
    """Every task returns rather than raising. APScheduler would log and carry
    on either way, but a task that raises has already abandoned its own
    bookkeeping — the sync row never gets its error recorded."""

    @respx.mock
    async def test_a_kev_feed_outage_does_not_kill_the_task(self):
        from app.config import get_settings

        respx.get(get_settings().kev_feed_url).mock(return_value=httpx.Response(503))

        # Returns a count rather than raising, so the scheduler's next tick
        # simply tries again.
        assert await refresh_feeds_task() == 0

    @respx.mock
    async def test_a_kev_feed_serving_garbage_does_not_kill_the_task(self):
        from app.config import get_settings

        respx.get(get_settings().kev_feed_url).mock(
            return_value=httpx.Response(200, content=b"<html>not json</html>")
        )
        assert await refresh_feeds_task() == 0

    @respx.mock
    async def test_a_mirror_outage_is_reported_not_raised(self):
        for ecosystem in MIRRORED_ECOSYSTEMS:
            respx.get(OSV_EXPORT_URL.format(ecosystem=str(ecosystem))).mock(
                return_value=httpx.Response(500)
            )

        stats = await sync_mirror_task()

        assert stats["failed"] == len(MIRRORED_ECOSYSTEMS)
        assert stats["stored"] == 0

    @respx.mock
    async def test_one_broken_ecosystem_does_not_cost_the_others(self, db):
        """Isolation is the point: a Go export outage must not stop npm and
        PyPI being refreshed, or one upstream hiccup ages the whole mirror."""
        import io
        import json
        import zipfile

        def export(name: str) -> bytes:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr(
                    "GHSA-x.json",
                    json.dumps(
                        {
                            "id": f"GHSA-{name}",
                            "affected": [
                                {
                                    "package": {"ecosystem": name, "name": "somepkg"},
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [{"introduced": "0"}, {"fixed": "1.0.0"}],
                                        }
                                    ],
                                }
                            ],
                        }
                    ),
                )
            return buffer.getvalue()

        respx.get(OSV_EXPORT_URL.format(ecosystem="npm")).mock(
            return_value=httpx.Response(200, content=export("npm"))
        )
        respx.get(OSV_EXPORT_URL.format(ecosystem="PyPI")).mock(
            return_value=httpx.Response(200, content=export("PyPI"))
        )
        respx.get(OSV_EXPORT_URL.format(ecosystem="Go")).mock(return_value=httpx.Response(500))
        # The remaining ecosystems get a real one-record export. Named
        # individually this test would break whenever one was added, for a
        # reason unrelated to the isolation it is checking — and an *empty*
        # export counts as a failure, which is correct behaviour and would
        # muddle the assertion below.
        for ecosystem in MIRRORED_ECOSYSTEMS:
            if str(ecosystem) in ("npm", "PyPI", "Go"):
                continue
            respx.get(OSV_EXPORT_URL.format(ecosystem=str(ecosystem))).mock(
                return_value=httpx.Response(200, content=export(str(ecosystem)))
            )

        stats = await sync_mirror_task()

        assert stats["failed"] == 1
        assert stats["stored"] == len(MIRRORED_ECOSYSTEMS) - 1, (
            "every ecosystem but the broken one stored its record"
        )
        assert stats["ecosystems"] == len(MIRRORED_ECOSYSTEMS)

    async def test_a_scan_cycle_with_nothing_due_is_not_an_error(self):
        stats = await run_scan_cycle()
        assert stats["failed"] == 0

    async def test_the_sweep_returns_rather_than_raising(self):
        assert await sweep_sessions_task() >= 0


class TestFailuresReachTheAdminPanel:
    """Recording a failure in the log is not the same as surfacing it.

    Logs are read when somebody already suspects a problem. The admin panel is
    read when they do not — which is exactly when a feed that stopped working
    three weeks ago needs to be noticed.
    """

    @respx.mock
    async def test_a_broken_mirror_feed_shows_as_failing(self, db):
        respx.get(OSV_EXPORT_URL.format(ecosystem="npm")).mock(return_value=httpx.Response(500))

        from app.core.types import Ecosystem
        from app.services.mirror_service import MirrorSyncError, sync_ecosystem

        with pytest.raises(MirrorSyncError):
            await sync_ecosystem(db, Ecosystem.NPM)
        await db.flush()

        feeds = {f.name: f for f in await feed_health(db)}
        npm = feeds[mirror_feed_name(Ecosystem.NPM)]

        assert npm.status == "failing"
        assert npm.is_healthy is False
        # The reason has to travel with the status, or the panel says something
        # is wrong without saying what.
        assert npm.last_error

    async def test_a_feed_that_stopped_updating_shows_as_stale(self, db):
        from app.core.types import Ecosystem

        await upsert_feed(
            db,
            name=mirror_feed_name(Ecosystem.NPM),
            last_success_at=utcnow() - timedelta(days=30),
            record_count=200_000,
            last_error=None,
        )

        feeds = {f.name: f for f in await feed_health(db)}
        assert feeds[mirror_feed_name(Ecosystem.NPM)].status == "stale"

    async def test_a_feed_erroring_on_every_attempt_reads_as_failing(self, db):
        """Not "never synced".

        A feed that has been tried and broke on every attempt since deployment
        is failing. Calling it never-synced reads like "not set up yet", which
        sends the reader to check configuration instead of the error.
        """
        from app.core.types import Ecosystem

        await upsert_feed(
            db,
            name=mirror_feed_name(Ecosystem.GO),
            last_attempt_at=utcnow(),
            last_error="HTTP 500 from the Go export",
        )

        feeds = {f.name: f for f in await feed_health(db)}
        assert feeds[mirror_feed_name(Ecosystem.GO)].status == "failing"

    async def test_the_overview_reports_the_failure(self, admin_client, db):
        """End to end: a broken feed reaches what the operator's page reads,
        not only the dataclass behind it.

        Against the endpoint rather than the rendered HTML, because the panel
        is React now — this is the boundary where "the service knows" becomes
        "the operator can see it"."""
        from app.core.types import Ecosystem

        await upsert_feed(
            db,
            name=mirror_feed_name(Ecosystem.NPM),
            last_attempt_at=utcnow(),
            last_error="HTTP 500 from the npm export",
        )
        await db.commit()

        response = await admin_client.get("/api/internal/admin/overview")
        assert response.status_code == 200

        feeds = {feed["name"]: feed for feed in response.json()["data"]["feeds"]}
        npm = feeds[mirror_feed_name(Ecosystem.NPM)]
        assert npm["status"] == "failing"
        # The reason travels with the status, or the panel says something is
        # wrong without saying what.
        assert npm["last_error"] == "HTTP 500 from the npm export"

    async def test_row_counts_are_shown(self, admin_client, db):
        """A feed can succeed and still be broken. If an export starts
        returning a handful of advisories instead of hundreds of thousands,
        every status field says "ok" and only the count gives it away."""
        from app.core.types import Ecosystem

        await upsert_feed(
            db,
            name=mirror_feed_name(Ecosystem.NPM),
            last_success_at=utcnow(),
            record_count=226887,
            last_error=None,
        )
        await db.commit()

        feeds = {
            feed["name"]: feed
            for feed in (await admin_client.get("/api/internal/admin/overview")).json()["data"][
                "feeds"
            ]
        }
        assert feeds[mirror_feed_name(Ecosystem.NPM)]["record_count"] == 226887


class TestReadinessReflectsTheMirror:
    async def test_an_empty_mirror_is_reported(self, client):
        """Scans refuse rather than reporting a false all-clear when the mirror
        is empty, so a deployment in that state is serving pages without doing
        its job. `/readyz` says so."""
        response = await client.get("/readyz")

        assert response.status_code == 200
        assert response.json()["checks"]["advisory_mirror"] == "empty"

    async def test_the_endpoint_leaks_no_internals(self, client):
        """Unauthenticated, so it reports states rather than details."""
        body = (await client.get("/readyz")).text.lower()

        for leak in ("postgresql", "psycopg", "password", "@db:", "weedout:weedout"):
            assert leak not in body, leak
