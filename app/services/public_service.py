"""Data shown on the public landing page.

Everything here is served to anonymous visitors, so the rule is absolute:
**nothing that identifies a user, an account or a project may leave this
module.** The queries below select package names, versions, CVE ids and
severities — facts about public open-source packages and public advisories,
which are already published by npm, PyPI, Go and OSV. They never select a user
id, an email, a project name or a manifest.

A short in-process cache sits in front of the query. The landing page is the
most-hit route on the site and its content changes on the scale of hours, so
re-running an aggregate across every account per visitor would be pure waste —
and a free way for anyone to load the database.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.types import AlertStatus, Severity, Verdict
from app.logging_config import get_logger
from app.models import CVEMatch, TrackedTarget, User, VulnerabilityRecord, utcnow

log = get_logger(__name__)

__all__ = [
    "PublicStats",
    "RecentFinding",
    "TrendingCve",
    "TrendingPackage",
    "clear_cache",
    "get_landing_data",
    "trending_cves",
    "trending_packages",
]

#: How long the landing snapshot is reused. Long enough that traffic spikes
#: cost one query; short enough that a newly-exploited CVE shows up the same
#: working session.
CACHE_TTL_SECONDS = 300

#: Windows the aggregates are computed over.
WINDOW_WEEK_DAYS = 7
WINDOW_MONTH_DAYS = 30

#: A row is published only if at least this many distinct accounts contributed
#: to it.
#:
#: A raw count would be safe on its own, but combined with the "recently
#: flagged" list it stops being: if exactly one customer is affected by an
#: unusual package, "seen in 1 project" says something specific about that
#: customer's stack. Requiring a cohort means every published row describes a
#: pattern rather than an account. The account count itself is never exposed —
#: it is only the gate.
MIN_COHORT = 2


@dataclass(frozen=True, slots=True)
class RecentFinding:
    """One anonymised finding.

    Every field is public information: the CVE id and summary come from OSV,
    the package name and version from a public registry. There is deliberately
    no field that could carry a project name or an account.
    """

    cve_id: str
    package: str
    version: str
    ecosystem: str
    severity: Severity
    is_kev: bool
    summary: str
    fixed_version: str | None
    seen_at: object  # datetime; kept loose so templates just format it

    @property
    def severity_label(self) -> str:
        return self.severity.label


@dataclass(slots=True)
class PublicStats:
    """Headline numbers, rounded so they cannot be used to count customers."""

    advisories_matched: int = 0
    filtered_out: int = 0
    dependencies_watched: int = 0
    kev_entries: int = 0

    @property
    def filtered_share(self) -> int:
        total = self.advisories_matched
        if total == 0:
            return 0
        return round(self.filtered_out / total * 100)


@dataclass(frozen=True, slots=True)
class TrendingCve:
    """One advisory, and how widely it turned up — counts only.

    `project_count` is a count of tracked projects, not of customers, and the
    number of accounts behind it is never exposed. See `MIN_COHORT`.
    """

    cve_id: str
    summary: str
    severity: Severity
    is_kev: bool
    project_count: int
    package_count: int

    @property
    def severity_label(self) -> str:
        return self.severity.label


@dataclass(frozen=True, slots=True)
class TrendingPackage:
    """One package and how often it was the source of a critical finding."""

    ecosystem: str
    name: str
    project_count: int
    advisory_count: int


@dataclass(slots=True)
class LandingData:
    findings: list[RecentFinding] = field(default_factory=list)
    stats: PublicStats = field(default_factory=PublicStats)
    trending_cves: list[TrendingCve] = field(default_factory=list)
    trending_packages: list[TrendingPackage] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def has_trends(self) -> bool:
        """False until enough distinct accounts exist to aggregate safely.

        The section is hidden rather than padded: an empty "this week" list is
        an honest "not enough data yet", and inventing rows to fill it would
        make the one genuinely factual thing on the page fiction.
        """
        return bool(self.trending_cves or self.trending_packages)


_cache: tuple[float, LandingData] | None = None


def clear_cache() -> None:
    """Drop the cached snapshot. Used by tests and after a seed."""
    global _cache
    _cache = None


async def get_landing_data(db: AsyncSession, ttl: int = CACHE_TTL_SECONDS) -> LandingData:
    """Recent critical findings and headline counts, cached briefly."""
    global _cache

    now = time.monotonic()
    if _cache is not None and now - _cache[0] < ttl:
        return _cache[1]

    data = LandingData(
        findings=await _recent_critical_findings(db),
        stats=await _public_stats(db),
        trending_cves=await trending_cves(db, days=WINDOW_WEEK_DAYS),
        trending_packages=await trending_packages(db, days=WINDOW_WEEK_DAYS),
    )
    _cache = (now, data)
    return data


def _anonymised_base(days: int):
    """The join and filters every aggregate below shares.

    Kept in one place so the privacy conditions — active accounts only, no
    suppressed noise, no withdrawn advisories — cannot drift apart between the
    two aggregates.
    """
    since = utcnow() - timedelta(days=days)
    return (
        select(CVEMatch)
        .join(TrackedTarget, TrackedTarget.id == CVEMatch.target_id)
        .join(User, User.id == TrackedTarget.user_id)
        .where(
            CVEMatch.first_seen_at >= since,
            CVEMatch.verdict == Verdict.ACTIONABLE,
            (CVEMatch.severity == Severity.CRITICAL) | (CVEMatch.is_kev.is_(True)),
            User.is_suspended.is_(False),
            User.is_active.is_(True),
        )
    )


async def trending_cves(
    db: AsyncSession, days: int = WINDOW_WEEK_DAYS, limit: int = 6
) -> list[TrendingCve]:
    """The critical advisories that turned up in the most projects lately.

    Ordered by reach rather than by severity: everything here already cleared
    the critical-or-exploited bar, so the useful ranking is "how many teams is
    this actually landing on".
    """
    rows = (
        await db.execute(
            _anonymised_base(days)
            .join(VulnerabilityRecord, VulnerabilityRecord.id == CVEMatch.vulnerability_id)
            .where(VulnerabilityRecord.withdrawn.is_(False))
            .with_only_columns(
                VulnerabilityRecord.cve_ids,
                VulnerabilityRecord.summary,
                # Severity and KEV status are properties of the advisory, not
                # of any one match, so they group rather than aggregate. An
                # aggregate would be wrong anyway: `max()` over the severity
                # column sorts alphabetically, which puts MEDIUM above CRITICAL.
                CVEMatch.severity,
                CVEMatch.is_kev,
                func.count(func.distinct(CVEMatch.target_id)).label("projects"),
                func.count(func.distinct(CVEMatch.package_name)).label("packages"),
            )
            .group_by(
                VulnerabilityRecord.cve_ids,
                VulnerabilityRecord.summary,
                CVEMatch.severity,
                CVEMatch.is_kev,
            )
            .having(func.count(func.distinct(TrackedTarget.user_id)) >= MIN_COHORT)
            .order_by(desc("projects"), desc("packages"))
            .limit(limit)
        )
    ).all()

    results: list[TrendingCve] = []
    for cve_ids, summary, severity, is_kev, projects, packages in rows:
        ids = cve_ids or []
        results.append(
            TrendingCve(
                cve_id=ids[0] if ids else "—",
                summary=(summary or "").strip(),
                severity=severity,
                is_kev=bool(is_kev),
                project_count=projects,
                package_count=packages,
            )
        )
    return results


async def trending_packages(
    db: AsyncSession, days: int = WINDOW_WEEK_DAYS, limit: int = 6
) -> list[TrendingPackage]:
    """The packages behind the most critical findings lately."""
    rows = (
        await db.execute(
            _anonymised_base(days)
            .with_only_columns(
                CVEMatch.ecosystem,
                CVEMatch.package_name,
                func.count(func.distinct(CVEMatch.target_id)).label("projects"),
                func.count(func.distinct(CVEMatch.vulnerability_id)).label("advisories"),
            )
            .group_by(CVEMatch.ecosystem, CVEMatch.package_name)
            .having(func.count(func.distinct(TrackedTarget.user_id)) >= MIN_COHORT)
            .order_by(desc("projects"), desc("advisories"))
            .limit(limit)
        )
    ).all()

    return [
        TrendingPackage(
            ecosystem=str(ecosystem),
            name=name,
            project_count=projects,
            advisory_count=advisories,
        )
        for ecosystem, name, projects, advisories in rows
    ]


async def _recent_critical_findings(db: AsyncSession, limit: int = 12) -> list[RecentFinding]:
    """The most recent critical or actively-exploited findings, anonymised.

    Scoped to matches that are actionable and open, on accounts that are active
    — a suspended account's findings are not advertising material.

    Deduplicated by (CVE, package) so one popular vulnerable package across
    many accounts appears once rather than filling the whole list, which would
    also make it obvious how many customers use it.
    """
    rows = (
        await db.execute(
            select(
                VulnerabilityRecord.cve_ids,
                CVEMatch.package_name,
                CVEMatch.package_version,
                CVEMatch.ecosystem,
                CVEMatch.severity,
                CVEMatch.is_kev,
                VulnerabilityRecord.summary,
                CVEMatch.fixed_version,
                func.max(CVEMatch.first_seen_at).label("seen_at"),
            )
            .select_from(CVEMatch)
            .join(VulnerabilityRecord, VulnerabilityRecord.id == CVEMatch.vulnerability_id)
            .join(TrackedTarget, TrackedTarget.id == CVEMatch.target_id)
            .join(User, User.id == TrackedTarget.user_id)
            .where(
                CVEMatch.verdict == Verdict.ACTIONABLE,
                CVEMatch.status == AlertStatus.OPEN,
                # Critical or exploited only — the landing page shows the
                # sharp end, not everything that cleared the bar.
                (CVEMatch.severity == Severity.CRITICAL) | (CVEMatch.is_kev.is_(True)),
                VulnerabilityRecord.withdrawn.is_(False),
                User.is_suspended.is_(False),
                User.is_active.is_(True),
            )
            .group_by(
                VulnerabilityRecord.cve_ids,
                CVEMatch.package_name,
                CVEMatch.package_version,
                CVEMatch.ecosystem,
                CVEMatch.severity,
                CVEMatch.is_kev,
                VulnerabilityRecord.summary,
                CVEMatch.fixed_version,
            )
            .order_by(desc("seen_at"))
            .limit(limit)
        )
    ).all()

    findings: list[RecentFinding] = []
    for row in rows:
        cve_ids = row[0] or []
        findings.append(
            RecentFinding(
                cve_id=cve_ids[0] if cve_ids else "—",
                package=row[1],
                version=row[2],
                ecosystem=str(row[3]),
                severity=row[4],
                is_kev=row[5],
                summary=(row[6] or "").strip(),
                fixed_version=row[7],
                seen_at=row[8],
            )
        )
    return findings


async def _public_stats(db: AsyncSession) -> PublicStats:
    """Aggregate counts across the platform.

    Totals only — never a per-account breakdown, and never a customer count.
    """
    match_row = (
        await db.execute(
            select(
                func.count(CVEMatch.id),
                func.count(CVEMatch.id).filter(CVEMatch.verdict == Verdict.SUPPRESSED),
            )
        )
    ).one()

    dependencies = (
        await db.scalar(select(func.coalesce(func.sum(TrackedTarget.dependency_count), 0)))
    ) or 0

    from app.models import KevRecord

    kev_entries = (await db.scalar(select(func.count(KevRecord.cve_id)))) or 0

    return PublicStats(
        advisories_matched=match_row[0] or 0,
        filtered_out=match_row[1] or 0,
        dependencies_watched=dependencies,
        kev_entries=kev_entries,
    )
