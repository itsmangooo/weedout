"""The local advisory mirror: syncing it, and reading from it.

Before this existed, every scan asked OSV over HTTP which advisories affected
each dependency. That made an on-demand scan as slow as a network round trip
and as reliable as somebody else's uptime — unacceptable once a CI pipeline
blocks on the answer.

Now the worker pulls OSV's per-ecosystem exports into `vulnerabilities` and
`vulnerability_affected`, and a scan is a single indexed query. The scan path
performs **no outbound HTTP at all**.

The trade is explicit: results are as fresh as the last successful sync. That
is why `FeedSync` records both the timestamp and the row count of every sync,
and why the admin panel surfaces staleness — a mirror that silently stops
updating is the failure mode that matters here, and it is invisible unless
something is watching for it.
"""

from __future__ import annotations

import asyncio
import io
import json
import zipfile
from dataclasses import dataclass, field
from datetime import timedelta

import httpx
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.osv import normalize_osv_record, parse_osv_datetime
from app.core.types import Dependency, Ecosystem, Vulnerability
from app.logging_config import get_logger
from app.models import FeedSync, VulnerabilityAffected, VulnerabilityRecord, utcnow
from app.services.feed_service import record_to_vulnerability

log = get_logger(__name__)

__all__ = [
    "MirrorSyncError",
    "SyncReport",
    "find_local_vulnerabilities",
    "mirror_feed_name",
    "sync_all_ecosystems",
    "sync_ecosystem",
    "upsert_vulnerability",
]

#: OSV publishes a zip of every advisory per ecosystem, refreshed continuously.
#: This is the documented bulk-export path — far cheaper than walking the API.
OSV_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"

#: Ecosystems we parse manifests for. Mirroring anything else would be dead
#: weight — and an ecosystem we parse but do not mirror is worse than either,
#: because every project in it would scan clean. `test_mirror.py` asserts this
#: tuple covers every ecosystem a manifest kind maps to.
MIRRORED_ECOSYSTEMS = (
    Ecosystem.NPM,
    Ecosystem.PYPI,
    Ecosystem.GO,
    Ecosystem.CRATES_IO,
    Ecosystem.MAVEN,
)

#: Rows per upsert statement. Large enough to amortise round trips, small
#: enough that one statement does not hold locks for long or build a
#: multi-megabyte query.
UPSERT_CHUNK = 500


class MirrorSyncError(RuntimeError):
    """An ecosystem export could not be fetched or parsed."""


def mirror_feed_name(ecosystem: Ecosystem) -> str:
    """`FeedSync.name` for one ecosystem's mirror."""
    return f"osv_mirror_{str(ecosystem).lower()}"


@dataclass(slots=True)
class SyncReport:
    ecosystem: Ecosystem
    records_seen: int = 0
    records_stored: int = 0
    affected_rows: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Reading — the hot path
# ---------------------------------------------------------------------------


async def find_local_vulnerabilities(
    db: AsyncSession, dependencies: list[Dependency]
) -> dict[tuple[str, str, str], list[Vulnerability]]:
    """Candidate advisories for each dependency, from the local mirror.

    Returns a mapping keyed by `Dependency.key`, shaped exactly like the OSV
    client's batch response so `triage_all` consumes either without knowing
    which produced it.

    This returns *candidates* — every advisory that mentions the package in
    that ecosystem, regardless of version. Version-range evaluation stays in
    `app.core.matching`, which already does it and is tested against every
    ecosystem's rules. Filtering by version in SQL would mean two
    implementations of "affected" that have to agree forever.
    """
    if not dependencies:
        return {}

    # One query per ecosystem rather than per dependency: a 400-package
    # manifest is at most three round trips.
    by_ecosystem: dict[Ecosystem, set[str]] = {}
    for dep in dependencies:
        by_ecosystem.setdefault(dep.ecosystem, set()).add(dep.name.lower())

    # (ecosystem, lowercased package) -> advisories
    index: dict[tuple[Ecosystem, str], list[Vulnerability]] = {}

    for ecosystem, names in by_ecosystem.items():
        rows = (
            await db.execute(
                select(VulnerabilityAffected.package_name, VulnerabilityRecord)
                .join(
                    VulnerabilityRecord,
                    VulnerabilityRecord.id == VulnerabilityAffected.vulnerability_id,
                )
                .where(
                    VulnerabilityAffected.ecosystem == ecosystem,
                    VulnerabilityAffected.package_name.in_(names),
                    # A withdrawn advisory is retracted by its publisher. Triage
                    # would suppress it anyway; excluding it here keeps the
                    # candidate set smaller and the intent obvious.
                    VulnerabilityRecord.withdrawn.is_(False),
                )
            )
        ).all()

        for package_name, record in rows:
            index.setdefault((ecosystem, package_name), []).append(record_to_vulnerability(record))

    result: dict[tuple[str, str, str], list[Vulnerability]] = {}
    for dep in dependencies:
        candidates = index.get((dep.ecosystem, dep.name.lower()))
        if candidates:
            result[dep.key] = candidates
    return result


async def mirror_is_populated(db: AsyncSession) -> bool:
    """Has any ecosystem been mirrored yet?

    Scanning against an empty mirror would report every project clean, which is
    the most dangerous possible wrong answer. Callers check this and refuse
    rather than produce a falsely reassuring result.
    """
    return (await db.scalar(select(VulnerabilityAffected.id).limit(1))) is not None


# ---------------------------------------------------------------------------
# Writing — the worker path
# ---------------------------------------------------------------------------


#: Columns updated when an advisory already exists. `id` is the conflict key,
#: so it is deliberately absent.
_RECORD_UPDATE_COLUMNS = (
    "aliases",
    "cve_ids",
    "summary",
    "details",
    "severity",
    "cvss_score",
    "cvss_vector",
    "affected",
    "references",
    "cwe_ids",
    "withdrawn",
    "published",
    "fetched_at",
    "updated_at",
)


def _record_values(vulnerability: Vulnerability) -> dict:
    """One advisory as a `vulnerabilities` row.

    The version ranges stay in the JSONB blob rather than being split into
    columns. Range semantics live in `app.core.versions`, and expressing them
    in SQL as well would mean two implementations of "affected" that have to
    agree forever.
    """
    now = utcnow()
    return {
        "id": vulnerability.id,
        "aliases": list(vulnerability.aliases),
        "cve_ids": list(vulnerability.cve_ids),
        "summary": vulnerability.summary[:20000],
        "details": vulnerability.details[:60000],
        "severity": vulnerability.severity,
        "cvss_score": vulnerability.cvss_score,
        "cvss_vector": vulnerability.cvss_vector,
        "affected": [
            {
                "package": {"ecosystem": str(pkg.ecosystem), "name": pkg.name},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": _range_events(rng)} for rng in pkg.ranges
                ],
                "versions": list(pkg.versions),
            }
            for pkg in vulnerability.affected
        ],
        "references": list(vulnerability.references),
        "cwe_ids": list(vulnerability.cwe_ids),
        "withdrawn": vulnerability.withdrawn,
        "published": parse_osv_datetime(vulnerability.published),
        "fetched_at": now,
        "updated_at": now,
    }


def _affected_rows(vulnerability: Vulnerability) -> list[dict]:
    """The index rows for one advisory, deduplicated.

    An advisory may list the same package in several `affected` entries — one
    per version range. The index only answers "does this advisory mention this
    package", so one row is enough, and a second would violate the unique
    constraint.
    """
    seen: set[tuple[str, str]] = set()
    rows: list[dict] = []
    for pkg in vulnerability.affected:
        key = (str(pkg.ecosystem), pkg.name.lower())
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "vulnerability_id": vulnerability.id,
                "ecosystem": pkg.ecosystem,
                "package_name": pkg.name.lower(),
            }
        )
    return rows


async def upsert_vulnerabilities(db: AsyncSession, batch: list[Vulnerability]) -> int:
    """Store a batch of advisories and their index rows. Returns rows indexed.

    Set-based on purpose: **three statements per batch, not three per
    advisory.** npm's export alone is a few hundred thousand advisories, and a
    round trip each would make a full sync take hours instead of minutes.

    Upsert by primary key, so re-syncing the same export updates rows in place
    instead of duplicating them. The index rows are replaced wholesale rather
    than merged: an advisory that *drops* a package on revision must not leave
    a stale row behind still claiming it is affected.
    """
    if not batch:
        return 0

    # Deduplicate within the batch. Postgres raises "ON CONFLICT DO UPDATE
    # command cannot affect row a second time" if one statement carries the
    # same key twice, so a duplicated id in an export would abort the sync.
    # Last occurrence wins, matching the one-at-a-time behaviour.
    by_id: dict[str, Vulnerability] = {v.id: v for v in batch}
    unique = list(by_id.values())

    statement = pg_insert(VulnerabilityRecord).values([_record_values(v) for v in unique])
    await db.execute(
        statement.on_conflict_do_update(
            index_elements=[VulnerabilityRecord.id],
            set_={column: statement.excluded[column] for column in _RECORD_UPDATE_COLUMNS},
        )
    )

    await db.execute(
        delete(VulnerabilityAffected).where(VulnerabilityAffected.vulnerability_id.in_(list(by_id)))
    )

    rows = [row for vulnerability in unique for row in _affected_rows(vulnerability)]
    if rows:
        await db.execute(pg_insert(VulnerabilityAffected).values(rows))
    return len(rows)


async def upsert_vulnerability(db: AsyncSession, vulnerability: Vulnerability) -> int:
    """Store one advisory. A thin wrapper so there is one implementation."""
    return await upsert_vulnerabilities(db, [vulnerability])


def _range_events(rng) -> list[dict[str, str]]:
    events: list[dict[str, str]] = [{"introduced": rng.introduced or "0"}]
    if rng.fixed:
        events.append({"fixed": rng.fixed})
    elif rng.last_affected:
        events.append({"last_affected": rng.last_affected})
    return events


async def sync_ecosystem(db: AsyncSession, ecosystem: Ecosystem) -> SyncReport:
    """Download and store one ecosystem's advisories.

    A failure is recorded on the `FeedSync` row and re-raised. The previous
    mirror contents are left untouched — scanning against a half-written
    advisory table would silently under-report, and stale-but-complete beats
    fresh-but-partial every time.
    """
    settings = get_settings()
    report = SyncReport(ecosystem=ecosystem)
    sync = await _feed_row(db, mirror_feed_name(ecosystem))
    sync.last_attempt_at = utcnow()

    url = OSV_EXPORT_URL.format(ecosystem=str(ecosystem))
    try:
        payload = await _download(url, settings)
    except MirrorSyncError as exc:
        sync.last_error = str(exc)[:2000]
        log.error("mirror.download_failed", ecosystem=str(ecosystem), error=str(exc))
        raise

    pending: list[Vulnerability] = []
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for entry in archive.namelist():
                if not entry.endswith(".json"):
                    continue
                report.records_seen += 1
                try:
                    raw = json.loads(archive.read(entry))
                except (json.JSONDecodeError, KeyError):
                    report.skipped += 1
                    continue

                vulnerability = normalize_osv_record(raw)
                if vulnerability is None:
                    # No usable affected entry for an ecosystem we support.
                    report.skipped += 1
                    continue

                pending.append(vulnerability)
                if len(pending) >= UPSERT_CHUNK:
                    report.affected_rows += await _flush(db, pending)
                    report.records_stored += len(pending)
                    pending.clear()
    except zipfile.BadZipFile as exc:
        sync.last_error = f"export was not a valid zip: {exc}"
        raise MirrorSyncError(sync.last_error) from exc

    if pending:
        report.affected_rows += await _flush(db, pending)
        report.records_stored += len(pending)

    if report.records_stored == 0:
        # An export that parses but yields nothing means the feed changed shape
        # or served an empty file. Treating it as success would quietly wipe
        # the signal; the sync row records a failure and the mirror stands.
        sync.last_error = "export contained no usable advisories"
        raise MirrorSyncError(f"{ecosystem}: {sync.last_error}")

    sync.last_success_at = utcnow()
    sync.last_error = None
    sync.record_count = report.records_stored

    log.info(
        "mirror.synced",
        ecosystem=str(ecosystem),
        seen=report.records_seen,
        stored=report.records_stored,
        affected=report.affected_rows,
        skipped=report.skipped,
    )
    return report


async def _flush(db: AsyncSession, batch: list[Vulnerability]) -> int:
    """Write one chunk and commit it.

    Committing per chunk rather than holding the whole ecosystem in one
    transaction keeps a several-hundred-thousand-row sync from accumulating an
    enormous amount of WAL and a transaction that runs for many minutes.

    Safe to do mid-sync because these are upserts: a partial run leaves the
    mirror with *newer* data for the advisories it reached and untouched data
    for the rest. It never leaves it emptier, which is the state that would
    matter. The `FeedSync` row is only marked successful at the very end, so a
    run that dies halfway is still reported as the failure it was.
    """
    total = await upsert_vulnerabilities(db, batch)
    await db.commit()
    return total


async def _download(url: str, settings) -> bytes:
    async with httpx.AsyncClient(
        timeout=settings.mirror_timeout_seconds,
        headers={"User-Agent": settings.feed_user_agent},
        follow_redirects=True,
    ) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise MirrorSyncError(f"HTTP {exc.response.status_code} from {url}") from exc
        except httpx.HTTPError as exc:
            raise MirrorSyncError(f"request failed: {exc}") from exc

    if len(response.content) > settings.mirror_max_bytes:
        raise MirrorSyncError(
            f"export is {len(response.content)} bytes, above the {settings.mirror_max_bytes} cap"
        )
    return response.content


async def _feed_row(db: AsyncSession, name: str) -> FeedSync:
    sync = await db.get(FeedSync, name)
    if sync is None:
        sync = FeedSync(name=name)
        db.add(sync)
        await db.flush()
    return sync


async def sync_all_ecosystems(db: AsyncSession) -> list[SyncReport]:
    """Sync every mirrored ecosystem, isolating failures.

    One ecosystem's export being unavailable must not cost the others their
    refresh, so each is attempted independently and its error recorded on its
    own feed row.
    """
    reports: list[SyncReport] = []
    for ecosystem in MIRRORED_ECOSYSTEMS:
        try:
            reports.append(await sync_ecosystem(db, ecosystem))
        except MirrorSyncError as exc:
            log.error("mirror.ecosystem_failed", ecosystem=str(ecosystem), error=str(exc))
            reports.append(SyncReport(ecosystem=ecosystem, errors=[str(exc)]))
        except asyncio.CancelledError:
            raise
    return reports


async def mirror_is_stale(db: AsyncSession, max_age: timedelta) -> bool:
    """True when any mirrored ecosystem has no recent successful sync."""
    for ecosystem in MIRRORED_ECOSYSTEMS:
        sync = await db.get(FeedSync, mirror_feed_name(ecosystem))
        if sync is None or sync.is_stale(max_age):
            return True
    return False
