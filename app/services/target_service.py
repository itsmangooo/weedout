"""Creating, listing and removing tracked targets."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.manifests import ManifestParseError, detect_manifest_kind, parse_manifest
from app.core.types import AlertStatus, Ecosystem, Severity, Verdict
from app.logging_config import get_logger
from app.models import CVEMatch, TrackedTarget, User, utcnow
from app.security import content_hash
from app.tiers import can_add_target, target_limit_message

log = get_logger(__name__)

__all__ = [
    "TargetError",
    "TargetLimitReached",
    "UnsupportedManifest",
    "create_empty_target",
    "create_target",
    "delete_target",
    "get_target_for_user",
    "list_targets",
]


class TargetError(Exception):
    """Base class for target-management failures."""


class TargetLimitReached(TargetError):
    pass


class UnsupportedManifest(TargetError):
    pass


@dataclass(slots=True)
class TargetSummary:
    """A target plus the counts the dashboard renders."""

    target: TrackedTarget
    open_actionable: int = 0
    exploited: int = 0
    suppressed: int = 0
    dismissed: int = 0


async def count_targets(db: AsyncSession, user_id: int) -> int:
    return (
        await db.scalar(
            select(func.count(TrackedTarget.id)).where(TrackedTarget.user_id == user_id)
        )
    ) or 0


async def create_empty_target(
    db: AsyncSession,
    user: User,
    name: str,
    ecosystem: Ecosystem,
) -> TrackedTarget:
    """Create a project with no manifest yet.

    The file does not have to come first. A project has to exist before an API
    key can be scoped to it, and scoping keys to projects is what lets a CI
    runner push a scan — so requiring an upload at creation forced everyone
    through the browser once before they could use the CLI at all.

    The result is deliberately *not* a scanned project with no findings. It has
    no `manifest_content` and no `last_scanned_at`, so it reads as "no manifest
    yet" everywhere rather than as a clean bill of health.
    """
    current = await count_targets(db, user.id)
    if not can_add_target(user.tier, current):
        raise TargetLimitReached(target_limit_message(user.tier))

    clean = name.strip()
    if not clean:
        raise UnsupportedManifest("Give the project a name.")

    target = TrackedTarget(
        user_id=user.id,
        name=clean[:200],
        ecosystem=ecosystem,
        manifest_kind=None,
        manifest_content=None,
        content_hash=None,
        dependency_count=0,
        # Nothing to scan, so nothing to schedule. Set when a manifest arrives.
        next_scan_at=None,
    )
    db.add(target)
    await db.flush()

    log.info("target.created_empty", target_id=target.id, user_id=user.id, ecosystem=str(ecosystem))
    return target


async def create_target(
    db: AsyncSession,
    user: User,
    filename: str,
    content: str,
    display_name: str | None = None,
) -> TrackedTarget:
    """Register a manifest for tracking.

    The manifest is parsed immediately rather than deferred to the scheduler, so
    a file we cannot read is rejected while the user is still looking at the
    upload form instead of failing silently hours later.
    """
    current = await count_targets(db, user.id)
    if not can_add_target(user.tier, current):
        raise TargetLimitReached(target_limit_message(user.tier))

    kind = detect_manifest_kind(filename, content)
    if kind is None:
        raise UnsupportedManifest(
            "Could not recognise that file. Supported manifests are package.json, "
            "package-lock.json, requirements.txt and go.mod."
        )

    try:
        parsed = parse_manifest(kind, content)
    except ManifestParseError as exc:
        raise UnsupportedManifest(str(exc)) from exc

    if not parsed.dependencies:
        detail = f" ({parsed.warnings[0]})" if parsed.warnings else ""
        raise UnsupportedManifest(
            f"No dependencies with checkable versions were found in that file{detail}."
        )

    name = (display_name or "").strip() or parsed.project_name or filename or kind.value

    target = TrackedTarget(
        user_id=user.id,
        name=name[:200],
        manifest_kind=kind,
        ecosystem=parsed.ecosystem,
        manifest_content=content,
        content_hash=content_hash(content),
        dependency_count=len(parsed.dependencies),
        parse_warnings=parsed.warnings[:50],
        # Null means "due now", so the next scheduler tick picks it up.
        next_scan_at=None,
    )
    db.add(target)
    await db.flush()

    log.info(
        "target.created",
        target_id=target.id,
        user_id=user.id,
        kind=kind.value,
        dependencies=len(parsed.dependencies),
    )
    return target


async def replace_manifest(
    db: AsyncSession, target: TrackedTarget, content: str, filename: str | None = None
) -> bool:
    """Update a target's manifest in place. Returns False if nothing changed.

    Re-uploading identical content is a no-op rather than a re-scan, so a user
    clicking upload twice does not burn a scan cycle.

    Passing `filename` re-detects the manifest kind. A project that was
    registered from a `package.json` and later starts sending
    `package-lock.json` from CI is the same project with better data, and
    forcing the new file through the old parser would reject it as malformed.
    Without a filename the existing kind stands.

    Also the path a project created without a manifest takes when its first one
    arrives — there is no existing kind to fall back on then, so a filename is
    required.
    """
    digest = content_hash(content)
    if digest == target.content_hash:
        return False

    kind = target.manifest_kind
    if filename:
        detected = detect_manifest_kind(filename, content)
        if detected is None:
            raise UnsupportedManifest(
                "Could not recognise that file. Supported manifests are package.json, "
                "package-lock.json, requirements.txt and go.mod."
            )
        kind = detected

    if kind is None:
        # First manifest for a project created without one, and nothing said
        # what it is. Guessing from the contents alone would pick the wrong
        # parser for files that are all valid JSON.
        raise UnsupportedManifest(
            "Name the file so its format can be identified — package.json, "
            "package-lock.json, requirements.txt or go.mod."
        )

    try:
        parsed = parse_manifest(kind, content)
    except ManifestParseError as exc:
        raise UnsupportedManifest(str(exc)) from exc

    if not parsed.dependencies:
        detail = f" ({parsed.warnings[0]})" if parsed.warnings else ""
        raise UnsupportedManifest(
            f"No dependencies with checkable versions were found in that file{detail}."
        )

    # Switching ecosystem would silently reinterpret every stored finding, so
    # it is refused rather than applied. A Python project does not become a Go
    # project; a key pointed at the wrong repository does.
    if parsed.ecosystem != target.ecosystem:
        raise UnsupportedManifest(
            f"This project tracks {target.ecosystem} dependencies, but that file is "
            f"{parsed.ecosystem}. Add it as a separate project."
        )

    target.manifest_kind = kind
    target.manifest_content = content
    target.content_hash = digest
    target.dependency_count = len(parsed.dependencies)
    target.parse_warnings = parsed.warnings[:50]
    target.next_scan_at = None  # re-scan on the next tick
    target.updated_at = utcnow()
    return True


async def get_target_for_user(
    db: AsyncSession, user_id: int, target_id: int
) -> TrackedTarget | None:
    """Fetch a target, scoped to its owner.

    Ownership is part of the query rather than an assertion afterwards, so
    there is no path where a handler forgets the check.
    """
    return await db.scalar(
        select(TrackedTarget).where(TrackedTarget.id == target_id, TrackedTarget.user_id == user_id)
    )


async def list_targets(db: AsyncSession, user_id: int) -> list[TargetSummary]:
    """All of a user's targets with their finding counts, in one round trip."""
    targets = list(
        (
            await db.scalars(
                select(TrackedTarget)
                .where(TrackedTarget.user_id == user_id)
                .order_by(TrackedTarget.created_at.desc())
            )
        ).all()
    )
    if not targets:
        return []

    counts = await db.execute(
        select(
            CVEMatch.target_id,
            func.count(CVEMatch.id).filter(
                CVEMatch.verdict == Verdict.ACTIONABLE, CVEMatch.status == AlertStatus.OPEN
            ),
            func.count(CVEMatch.id).filter(
                CVEMatch.verdict == Verdict.ACTIONABLE,
                CVEMatch.status == AlertStatus.OPEN,
                CVEMatch.is_kev.is_(True),
            ),
            func.count(CVEMatch.id).filter(CVEMatch.verdict == Verdict.SUPPRESSED),
            func.count(CVEMatch.id).filter(CVEMatch.status == AlertStatus.DISMISSED),
        )
        .where(CVEMatch.target_id.in_([t.id for t in targets]))
        .group_by(CVEMatch.target_id)
    )
    by_target = {row[0]: row[1:] for row in counts}

    return [
        TargetSummary(
            target=target,
            open_actionable=by_target.get(target.id, (0, 0, 0, 0))[0],
            exploited=by_target.get(target.id, (0, 0, 0, 0))[1],
            suppressed=by_target.get(target.id, (0, 0, 0, 0))[2],
            dismissed=by_target.get(target.id, (0, 0, 0, 0))[3],
        )
        for target in targets
    ]


async def delete_target(db: AsyncSession, target: TrackedTarget) -> None:
    """Remove a target and everything hanging off it."""
    log.info("target.deleted", target_id=target.id, user_id=target.user_id)
    await db.delete(target)


@dataclass(slots=True)
class DashboardStats:
    targets: int = 0
    open_alerts: int = 0
    exploited: int = 0
    critical: int = 0
    suppressed: int = 0
    dismissed: int = 0
    resolved: int = 0
    dependencies: int = 0

    @property
    def noise_ratio(self) -> int:
        """Percentage of real matches that were filtered out.

        Shown on the dashboard because it is the product's whole argument: a
        high number here means the tool spared the user that much interruption.
        """
        total = self.open_alerts + self.suppressed
        if total == 0:
            return 0
        return round(self.suppressed / total * 100)


async def dashboard_stats(db: AsyncSession, user_id: int) -> DashboardStats:
    """Headline numbers for the dashboard, in two queries."""
    target_row = (
        await db.execute(
            select(
                func.count(TrackedTarget.id),
                func.coalesce(func.sum(TrackedTarget.dependency_count), 0),
            ).where(TrackedTarget.user_id == user_id)
        )
    ).one()

    match_row = (
        await db.execute(
            select(
                func.count(CVEMatch.id).filter(
                    CVEMatch.verdict == Verdict.ACTIONABLE, CVEMatch.status == AlertStatus.OPEN
                ),
                func.count(CVEMatch.id).filter(
                    CVEMatch.verdict == Verdict.ACTIONABLE,
                    CVEMatch.status == AlertStatus.OPEN,
                    CVEMatch.is_kev.is_(True),
                ),
                func.count(CVEMatch.id).filter(
                    CVEMatch.verdict == Verdict.ACTIONABLE,
                    CVEMatch.status == AlertStatus.OPEN,
                    CVEMatch.severity == Severity.CRITICAL,
                ),
                func.count(CVEMatch.id).filter(CVEMatch.verdict == Verdict.SUPPRESSED),
                func.count(CVEMatch.id).filter(CVEMatch.status == AlertStatus.DISMISSED),
                func.count(CVEMatch.id).filter(CVEMatch.status == AlertStatus.RESOLVED),
            )
            .select_from(CVEMatch)
            .join(TrackedTarget, TrackedTarget.id == CVEMatch.target_id)
            .where(TrackedTarget.user_id == user_id)
        )
    ).one()

    return DashboardStats(
        targets=target_row[0] or 0,
        dependencies=target_row[1] or 0,
        open_alerts=match_row[0] or 0,
        exploited=match_row[1] or 0,
        critical=match_row[2] or 0,
        suppressed=match_row[3] or 0,
        dismissed=match_row[4] or 0,
        resolved=match_row[5] or 0,
    )
