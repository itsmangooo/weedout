"""The local advisory mirror: syncing into it and reading back out.

The mirror is the single point where a silent failure turns into a false
all-clear, so most of what is asserted here is about *refusing* rather than
about matching: an empty export must not overwrite good data, a re-sync must
not multiply rows, and a dropped package must not linger.
"""

from __future__ import annotations

import io
import json
import zipfile

import httpx
import pytest
import respx
from sqlalchemy import func, select

from app.core.osv import normalize_osv_record
from app.core.types import Dependency, Ecosystem, Reachability
from app.models import FeedSync, VulnerabilityAffected, VulnerabilityRecord
from app.services.mirror_service import (
    OSV_EXPORT_URL,
    MirrorSyncError,
    find_local_vulnerabilities,
    mirror_feed_name,
    mirror_is_populated,
    sync_all_ecosystems,
    sync_ecosystem,
    upsert_vulnerability,
)

LODASH = {
    "id": "GHSA-lodash-1",
    "aliases": ["CVE-2020-8203"],
    "summary": "Prototype pollution in lodash",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "database_specific": {"cwe_ids": ["CWE-1321", "not-a-cwe"]},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}],
        }
    ],
}

#: Same advisory, revised: the fix moved and one package was dropped.
LODASH_REVISED = {
    "id": "GHSA-lodash-1",
    "aliases": ["CVE-2020-8203"],
    "summary": "Prototype pollution in lodash (revised)",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        }
    ],
}

#: An advisory covering two packages at once, which is common for monorepos.
MULTI_PACKAGE = {
    "id": "GHSA-multi-1",
    "summary": "Affects two packages",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "left-pad"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
        },
        {
            "package": {"ecosystem": "npm", "name": "right-pad"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
        },
    ],
}

PYPI_ADVISORY = {
    "id": "PYSEC-flask-1",
    "summary": "Something in Flask",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "Flask"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
        }
    ],
}


def dep(ecosystem: Ecosystem, name: str, version: str) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        version_spec=version,
        reachability=Reachability.RUNTIME_DIRECT,
    )


async def store(db, raw: dict) -> int:
    vulnerability = normalize_osv_record(raw)
    assert vulnerability is not None
    count = await upsert_vulnerability(db, vulnerability)
    await db.flush()
    return count


def export_zip(*records: dict) -> bytes:
    """Build an OSV ecosystem export the way the real endpoint serves it."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for record in records:
            archive.writestr(f"{record['id']}.json", json.dumps(record))
    return buffer.getvalue()


def mock_export(ecosystem: Ecosystem, body: bytes | int) -> None:
    url = OSV_EXPORT_URL.format(ecosystem=str(ecosystem))
    response = httpx.Response(body) if isinstance(body, int) else httpx.Response(200, content=body)
    respx.get(url).mock(return_value=response)


class TestUpsert:
    async def test_resyncing_the_same_advisory_does_not_duplicate_rows(self, db):
        for _ in range(3):
            await store(db, LODASH)

        assert await db.scalar(select(func.count()).select_from(VulnerabilityRecord)) == 1
        assert await db.scalar(select(func.count()).select_from(VulnerabilityAffected)) == 1

    async def test_a_revision_updates_in_place_rather_than_accumulating(self, db):
        await store(db, LODASH)
        await store(db, LODASH_REVISED)

        record = await db.get(VulnerabilityRecord, "GHSA-lodash-1")
        assert record.summary == "Prototype pollution in lodash (revised)"
        assert await db.scalar(select(func.count()).select_from(VulnerabilityRecord)) == 1

    async def test_a_package_dropped_by_a_revision_stops_matching(self, db):
        """A stale index row would keep flagging a package the advisory no
        longer covers — a false positive that no amount of re-syncing clears."""
        await store(db, MULTI_PACKAGE)
        assert await db.scalar(select(func.count()).select_from(VulnerabilityAffected)) == 2

        narrowed = dict(MULTI_PACKAGE)
        narrowed["affected"] = [MULTI_PACKAGE["affected"][0]]
        await store(db, narrowed)

        names = set((await db.scalars(select(VulnerabilityAffected.package_name))).all())
        assert names == {"left-pad"}

    async def test_package_names_are_indexed_lower_cased(self, db):
        # PyPI names are case-insensitive and manifests spell them either way;
        # if the index kept the publisher's casing, `flask` would miss `Flask`.
        await store(db, PYPI_ADVISORY)
        assert (await db.scalar(select(VulnerabilityAffected.package_name))) == "flask"

    async def test_an_advisory_listing_a_package_twice_indexes_it_once(self, db):
        doubled = dict(MULTI_PACKAGE)
        doubled["affected"] = [MULTI_PACKAGE["affected"][0], MULTI_PACKAGE["affected"][0]]
        await store(db, doubled)

        assert await db.scalar(select(func.count()).select_from(VulnerabilityAffected)) == 1

    async def test_cwe_ids_survive_the_round_trip(self, db):
        await store(db, LODASH)
        record = await db.get(VulnerabilityRecord, "GHSA-lodash-1")
        assert record.cwe_ids == ["CWE-1321"]  # the junk entry was dropped


class TestLookup:
    async def test_finds_candidates_for_a_dependency(self, db):
        await store(db, LODASH)
        dependency = dep(Ecosystem.NPM, "lodash", "4.17.15")

        found = await find_local_vulnerabilities(db, [dependency])
        assert [v.id for v in found[dependency.key]] == ["GHSA-lodash-1"]

    async def test_lookup_is_case_insensitive_on_the_query_side_too(self, db):
        await store(db, PYPI_ADVISORY)
        dependency = dep(Ecosystem.PYPI, "FLASK", "1.0")

        found = await find_local_vulnerabilities(db, [dependency])
        assert dependency.key in found

    async def test_an_advisory_for_another_ecosystem_is_not_returned(self, db):
        """`lodash` on npm and a hypothetical `lodash` on PyPI are different
        packages; matching across ecosystems would be a pure false positive."""
        await store(db, LODASH)
        dependency = dep(Ecosystem.PYPI, "lodash", "4.17.15")

        assert await find_local_vulnerabilities(db, [dependency]) == {}

    async def test_withdrawn_advisories_are_excluded(self, db):
        withdrawn = dict(LODASH)
        withdrawn["withdrawn"] = "2024-01-01T00:00:00Z"
        await store(db, withdrawn)

        dependency = dep(Ecosystem.NPM, "lodash", "4.17.15")
        assert await find_local_vulnerabilities(db, [dependency]) == {}

    async def test_a_dependency_with_no_advisories_is_absent_not_empty(self, db):
        await store(db, LODASH)
        dependency = dep(Ecosystem.NPM, "express", "4.18.0")

        assert await find_local_vulnerabilities(db, [dependency]) == {}

    async def test_no_dependencies_means_no_queries(self, db):
        assert await find_local_vulnerabilities(db, []) == {}

    async def test_an_empty_mirror_is_reported_as_unpopulated(self, db):
        assert await mirror_is_populated(db) is False
        await store(db, LODASH)
        assert await mirror_is_populated(db) is True


class TestSync:
    @respx.mock
    async def test_a_successful_sync_stores_advisories_and_records_the_count(self, db):
        mock_export(Ecosystem.NPM, export_zip(LODASH, MULTI_PACKAGE))

        report = await sync_ecosystem(db, Ecosystem.NPM)
        await db.flush()

        assert report.records_stored == 2
        assert report.affected_rows == 3  # lodash + left-pad + right-pad

        sync = await db.get(FeedSync, mirror_feed_name(Ecosystem.NPM))
        assert sync.last_error is None
        # The row count is the only thing that reveals a feed which starts
        # returning a fraction of its advisories while still returning 200.
        assert sync.record_count == 2

    @respx.mock
    async def test_resyncing_an_unchanged_export_leaves_the_row_count_stable(self, db):
        mock_export(Ecosystem.NPM, export_zip(LODASH, MULTI_PACKAGE))

        await sync_ecosystem(db, Ecosystem.NPM)
        await db.flush()
        await sync_ecosystem(db, Ecosystem.NPM)
        await db.flush()

        assert await db.scalar(select(func.count()).select_from(VulnerabilityRecord)) == 2
        assert await db.scalar(select(func.count()).select_from(VulnerabilityAffected)) == 3

    @respx.mock
    async def test_an_empty_export_fails_instead_of_wiping_the_signal(self, db):
        mock_export(Ecosystem.NPM, export_zip(LODASH))
        await sync_ecosystem(db, Ecosystem.NPM)
        await db.flush()

        # The next run serves an empty archive — a feed that has broken in the
        # worst way, because everything about it still looks like success.
        respx.mock.reset()
        mock_export(Ecosystem.NPM, export_zip())

        with pytest.raises(MirrorSyncError):
            await sync_ecosystem(db, Ecosystem.NPM)
        await db.flush()

        assert await db.scalar(select(func.count()).select_from(VulnerabilityRecord)) == 1
        sync = await db.get(FeedSync, mirror_feed_name(Ecosystem.NPM))
        assert "no usable advisories" in sync.last_error

    @respx.mock
    async def test_a_failed_download_is_recorded_and_raised(self, db):
        mock_export(Ecosystem.NPM, 503)

        with pytest.raises(MirrorSyncError):
            await sync_ecosystem(db, Ecosystem.NPM)
        await db.flush()

        sync = await db.get(FeedSync, mirror_feed_name(Ecosystem.NPM))
        assert sync.last_error
        assert sync.last_success_at is None

    @respx.mock
    async def test_one_broken_ecosystem_does_not_cost_the_others_their_refresh(self, db):
        mock_export(Ecosystem.NPM, export_zip(LODASH))
        mock_export(Ecosystem.PYPI, export_zip(PYPI_ADVISORY))
        mock_export(Ecosystem.GO, 500)

        reports = await sync_all_ecosystems(db)
        await db.flush()

        by_ecosystem = {str(r.ecosystem): r for r in reports}
        # Every ecosystem is reported on, including the one that failed —
        # omitting it would make a broken feed indistinguishable from one that
        # was never attempted.
        assert set(by_ecosystem) == {"npm", "PyPI", "Go"}
        assert by_ecosystem["npm"].records_stored == 1
        assert by_ecosystem["PyPI"].records_stored == 1
        assert by_ecosystem["Go"].errors

        assert (await db.get(FeedSync, mirror_feed_name(Ecosystem.GO))).last_error
        assert (await db.get(FeedSync, mirror_feed_name(Ecosystem.NPM))).last_error is None

    @respx.mock
    async def test_unparseable_entries_are_skipped_not_fatal(self, db):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("GHSA-lodash-1.json", json.dumps(LODASH))
            archive.writestr("broken.json", "{not json")
            archive.writestr("README.txt", "ignored")
        mock_export(Ecosystem.NPM, buffer.getvalue())

        report = await sync_ecosystem(db, Ecosystem.NPM)
        await db.flush()

        assert report.records_stored == 1
        assert report.skipped == 1
