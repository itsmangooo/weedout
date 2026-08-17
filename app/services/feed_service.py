"""Keeping the local KEV catalog current, and reading advisories back out.

The KEV catalog is cached locally so that a scan is a database join rather than
a fan-out of network calls, and so a CISA outage degrades the product to
"working from slightly stale data" instead of "down". Advisories are mirrored
the same way by `mirror_service`, which owns writing them; this module only
converts a stored row back into a core `Vulnerability`.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.types import KevEntry, Vulnerability
from app.feeds.kev import KevClient, KevFeedError
from app.logging_config import get_logger
from app.models import FeedSync, KevRecord, VulnerabilityRecord, utcnow

log = get_logger(__name__)

KEV_FEED_NAME = "cisa_kev"

__all__ = [
    "load_kev_index",
    "record_to_vulnerability",
    "refresh_kev_catalog",
]


async def refresh_kev_catalog(db: AsyncSession, force: bool = False) -> int:
    """Pull the KEV catalog and upsert it. Returns the number of rows stored.

    Returns 0 without contacting CISA when the cached copy is still fresh.
    A fetch failure is recorded on the `FeedSync` row and re-raised; the
    previous snapshot is left in place, because scanning against a half-written
    KEV table would silently demote exploited vulnerabilities to ordinary ones.
    """
    settings = get_settings()
    sync = await db.get(FeedSync, KEV_FEED_NAME)
    if sync is None:
        sync = FeedSync(name=KEV_FEED_NAME)
        db.add(sync)
        await db.flush()

    max_age = timedelta(hours=settings.kev_refresh_hours)
    if not force and not sync.is_stale(max_age):
        log.debug("kev.refresh_skipped", last_success=str(sync.last_success_at))
        return 0

    sync.last_attempt_at = utcnow()

    try:
        async with KevClient(
            feed_url=settings.kev_feed_url,
            timeout=settings.feed_timeout_seconds,
            user_agent=settings.feed_user_agent,
        ) as client:
            catalog = await client.fetch()
    except KevFeedError as exc:
        sync.last_error = str(exc)[:2000]
        log.error("kev.refresh_failed", error=str(exc))
        raise

    rows = [
        {
            "cve_id": entry.cve_id,
            "vendor_project": entry.vendor_project,
            "product": entry.product,
            "vulnerability_name": entry.vulnerability_name,
            "short_description": entry.short_description,
            "required_action": entry.required_action,
            "date_added": entry.date_added,
            "due_date": entry.due_date,
            "known_ransomware_use": entry.known_ransomware_use,
            "updated_at": utcnow(),
        }
        for entry in catalog.entries
    ]

    # Upsert in chunks: a single statement with several thousand rows produces
    # an unnecessarily large query and holds locks longer than needed.
    for start in range(0, len(rows), 500):
        chunk = rows[start : start + 500]
        statement = pg_insert(KevRecord).values(chunk)
        await db.execute(
            statement.on_conflict_do_update(
                index_elements=[KevRecord.cve_id],
                set_={
                    column: statement.excluded[column]
                    for column in (
                        "vendor_project",
                        "product",
                        "vulnerability_name",
                        "short_description",
                        "required_action",
                        "date_added",
                        "due_date",
                        "known_ransomware_use",
                        "updated_at",
                    )
                },
            )
        )

    sync.last_success_at = utcnow()
    sync.last_error = None
    sync.record_count = len(rows)
    sync.catalog_version = catalog.catalog_version

    log.info("kev.refreshed", entries=len(rows), catalog_version=catalog.catalog_version)
    return len(rows)


async def load_kev_index(db: AsyncSession, cve_ids: list[str] | None = None) -> dict[str, KevEntry]:
    """Load KEV rows as core `KevEntry` objects, keyed by CVE ID.

    Pass `cve_ids` to fetch only the CVEs a scan actually encountered; omit it
    to load the whole catalog (a few thousand rows).
    """
    query = select(KevRecord)
    if cve_ids is not None:
        wanted = [c.upper() for c in cve_ids]
        if not wanted:
            return {}
        query = query.where(KevRecord.cve_id.in_(wanted))

    records = (await db.scalars(query)).all()
    return {
        record.cve_id: KevEntry(
            cve_id=record.cve_id,
            vendor_project=record.vendor_project,
            product=record.product,
            vulnerability_name=record.vulnerability_name,
            short_description=record.short_description,
            required_action=record.required_action,
            date_added=record.date_added,
            due_date=record.due_date,
            known_ransomware_use=record.known_ransomware_use,
        )
        for record in records
    }


def record_to_vulnerability(record: VulnerabilityRecord) -> Vulnerability:
    """Rehydrate a cached row into the core type triage operates on."""
    from app.core.osv import parse_affected  # local import: keeps core dependency one-way

    return Vulnerability(
        id=record.id,
        aliases=tuple(record.aliases or ()),
        summary=record.summary,
        details=record.details,
        severity=record.severity,
        cvss_score=record.cvss_score,
        cvss_vector=record.cvss_vector,
        affected=parse_affected(record.affected),
        references=tuple(record.references or ()),
        cwe_ids=tuple(record.cwe_ids or ()),
        withdrawn=record.withdrawn,
        published=record.published.isoformat() if record.published else None,
    )


# Advisories used to be fetched from OSV during a scan and cached here on the
# way past. That path is gone: `mirror_service` owns writing advisories now,
# because a write has to populate `vulnerability_affected` as well, and a second
# writer that forgot to would store advisories the matcher could never find.
