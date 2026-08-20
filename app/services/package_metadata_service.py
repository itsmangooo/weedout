"""Keeping the package-metadata cache filled.

The job here is the only thing in the application that talks to npm or PyPI,
and it exists so that scans do not. The rules it works to:

* **Only packages somebody is tracking.** There is no value in a warm cache for
  a package nobody depends on, and the registries are somebody else's
  infrastructure.
* **Only when stale.** Release cadence does not change hourly.
* **Bounded per run.** A batch limit keeps one sweep from turning into an
  afternoon of requests, and makes the job's cost predictable.
* **A failure is recorded, not retried in a loop.** The row is written with
  `fetch_error` set, which both spaces out the retry and lets the interface say
  "not checked" rather than implying "checked and fine".
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import distinct, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.supply_chain import PackageFacts
from app.core.types import Ecosystem
from app.feeds.registry import RegistryClient, RegistryError, supports_metadata
from app.logging_config import get_logger
from app.models import DependencyRecord, PackageMetadata, utcnow

log = get_logger(__name__)

__all__ = ["RefreshReport", "facts_for", "refresh_package_metadata"]

#: How many packages one sweep will fetch. The job runs on a schedule, so a
#: backlog drains over several runs rather than in one long burst against
#: somebody else's registry.
BATCH_LIMIT = 300

#: At most this many requests in flight. Polite, and enough that a 300-package
#: sweep is a minute rather than five.
CONCURRENCY = 8


@dataclass(slots=True)
class RefreshReport:
    fetched: int = 0
    failed: int = 0
    skipped: int = 0


async def refresh_package_metadata(db: AsyncSession, *, limit: int = BATCH_LIMIT) -> RefreshReport:
    """Fetch metadata for tracked packages whose cache entry is missing or old."""
    settings = get_settings()
    report = RefreshReport()

    ttl = timedelta(days=settings.package_metadata_ttl_days)
    cutoff = utcnow() - ttl

    tracked = (
        await db.execute(
            select(distinct(DependencyRecord.ecosystem), DependencyRecord.name).where(
                DependencyRecord.ecosystem.in_([eco for eco in Ecosystem if supports_metadata(eco)])
            )
        )
    ).all()

    cached = {
        (row.ecosystem, row.name): row
        for row in (await db.execute(select(PackageMetadata))).scalars()
    }

    wanted: list[tuple[Ecosystem, str]] = []
    for ecosystem, name in tracked:
        existing = cached.get((ecosystem, name))
        if existing is not None and existing.fetched_at > cutoff:
            report.skipped += 1
            continue
        wanted.append((ecosystem, name))
        if len(wanted) >= limit:
            break

    if not wanted:
        return report

    semaphore = asyncio.Semaphore(CONCURRENCY)

    async with RegistryClient(
        timeout=settings.feed_timeout_seconds, user_agent=settings.feed_user_agent
    ) as client:

        async def one(ecosystem: Ecosystem, name: str):
            async with semaphore:
                try:
                    return await client.fetch(ecosystem, name), None
                except RegistryError as exc:
                    return None, str(exc)
                except Exception as exc:
                    return None, f"{type(exc).__name__}: {exc}"

        results = await asyncio.gather(*(one(eco, name) for eco, name in wanted))

    now = utcnow()
    for (ecosystem, name), (facts, error) in zip(wanted, results, strict=True):
        row = cached.get((ecosystem, name))
        if row is None:
            row = PackageMetadata(ecosystem=ecosystem, name=name)
            db.add(row)

        row.fetched_at = now
        if facts is None:
            row.fetch_error = (error or "Unknown error")[:2000]
            report.failed += 1
            continue

        row.fetch_error = None
        row.latest_version = facts.latest_version
        row.days_since_release = facts.days_since_release
        row.maintainer_count = facts.maintainer_count
        row.has_provenance = facts.has_provenance
        row.deprecated = facts.deprecated
        report.fetched += 1

    await db.commit()
    log.info(
        "package_metadata.refreshed",
        fetched=report.fetched,
        failed=report.failed,
        skipped=report.skipped,
    )
    return report


async def facts_for(
    db: AsyncSession, packages: list[tuple[Ecosystem, str]]
) -> dict[tuple[Ecosystem, str], PackageFacts]:
    """Cached facts for the packages a scan is about to assess.

    Reads only. A package with no row, or a row whose last fetch failed, is
    simply absent -- the caller raises no signal for it, which is the correct
    answer to "we do not know" and is not the same as "nothing wrong".
    """
    if not packages:
        return {}

    names = {name for _, name in packages}
    rows = (
        await db.execute(select(PackageMetadata).where(PackageMetadata.name.in_(names)))
    ).scalars()

    wanted = set(packages)
    found: dict[tuple[Ecosystem, str], PackageFacts] = {}
    for row in rows:
        key = (row.ecosystem, row.name)
        if key not in wanted or row.fetch_error:
            continue
        found[key] = PackageFacts(
            ecosystem=row.ecosystem,
            name=row.name,
            latest_version=row.latest_version,
            days_since_release=row.days_since_release,
            maintainer_count=row.maintainer_count,
            has_provenance=row.has_provenance,
            deprecated=row.deprecated,
        )
    return found
