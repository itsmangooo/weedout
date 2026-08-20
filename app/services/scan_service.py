"""The scan pipeline.

    manifest text
        -> parse            (app.core.manifests)
        -> query OSV        (app.feeds.osv, cached in app.services.feed_service)
        -> cross-ref KEV    (app.services.feed_service)
        -> triage           (app.core.matching)
        -> reconcile with what we already knew
        -> queue alerts for anything genuinely new

Reconciliation is the part that keeps the product calm. A scan does not produce
"the alerts"; it produces the current truth, which is then diffed against
stored findings. A match already seen keeps its identity and its dismissal.
A match that has disappeared — because the user upgraded — is marked resolved
rather than deleted, so the history survives. Only genuinely new actionable
findings generate an email.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.core.manifests import ManifestParseError, parse_manifest
from app.core.matching import DEFAULT_POLICY, MatchPolicy, triage_all
from app.core.types import AlertStatus, Dependency, ScanResult, Verdict
from app.logging_config import get_logger
from app.models import CVEMatch, DependencyRecord, ScanRun, TrackedTarget, User, utcnow
from app.services.feed_service import load_epss_index, load_kev_index
from app.services.mirror_service import (
    find_local_vulnerabilities,
    mirror_is_populated,
    mirror_is_stale,
)
from app.services.rules_service import build_policy, record_overrides
from app.services.supply_chain_service import reconcile_signals
from app.tiers import can_use_custom_rules, scan_interval_for

log = get_logger(__name__)

__all__ = ["MirrorUnavailable", "ScanOutcome", "scan_target"]


class NoManifest(RuntimeError):
    """The project has nothing to scan yet.

    Not an error in the usual sense — it is the normal state of a project that
    was created before its first upload. Callers report it as a state rather
    than a failure.
    """


class MirrorUnavailable(RuntimeError):
    """The local advisory mirror is empty, so no scan can be trusted."""


@dataclass(slots=True)
class ScanOutcome:
    """What one scan changed, for logging and for the alerting step."""

    target_id: int
    dependencies_scanned: int = 0
    #: Packages the owner's plan did not reach. Surfaced so a Free project
    #: is told what was out of range rather than left to assume it was clean.
    unreached_by_depth: int = 0
    actionable_count: int = 0
    suppressed_count: int = 0
    #: Matches that are actionable and were never seen before — these alert.
    new_matches: list[CVEMatch] = field(default_factory=list)
    resolved_count: int = 0
    errors: list[str] = field(default_factory=list)
    failed: bool = False


async def scan_target(
    db: AsyncSession,
    target: TrackedTarget,
    policy: MatchPolicy = DEFAULT_POLICY,
) -> ScanOutcome:
    """Scan one target and reconcile the results into stored findings.

    Never raises for expected failures — an unparseable manifest or an empty
    mirror is recorded on the `ScanRun` and on the target, and the scheduler
    moves on to the next one.
    """
    outcome = ScanOutcome(target_id=target.id)
    run = ScanRun(target_id=target.id, status="running")
    db.add(run)
    await db.flush()

    # Resolve the owner's plan explicitly. Touching `target.user` lazily here
    # would raise MissingGreenlet under the async session.
    owner = await db.get(User, target.user_id)
    tier = owner.tier if owner else "free"

    # Depth, thresholds and ignore rules, assembled from the plan, the
    # project's settings and any .weedout.yml the pipeline pushed. Derived here
    # rather than stored, so a lapsed subscription stops honouring Pro rules on
    # the next scan without anybody editing a row.
    effective = await build_policy(db, target, owner, base=policy)
    policy = effective.policy

    try:
        result = await _run_pipeline(db, target, policy)
    except NoManifest as exc:
        # Not a failure: this is what a project looks like between being created
        # and receiving its first file. The run row is discarded rather than
        # recorded, so "Recent checks" does not fill with entries for checks
        # that never had anything to check — and `last_scanned_at` stays null,
        # which is what keeps the project out of the "scanned, clean" state.
        message = str(exc)
        log.info("scan.skipped_no_manifest", target_id=target.id)
        await db.delete(run)
        _schedule_next_scan(target, tier)
        outcome.errors.append(message)
        return outcome
    except ManifestParseError as exc:
        message = f"Could not parse manifest: {exc}"
        log.warning("scan.parse_failed", target_id=target.id, error=str(exc))
        _finish_run(run, status="failed", error=message)
        target.last_scan_error = message
        target.last_scanned_at = utcnow()
        _schedule_next_scan(target, tier)
        outcome.failed = True
        outcome.errors.append(message)
        return outcome
    except MirrorUnavailable as exc:
        message = str(exc)
        log.error("scan.mirror_unavailable", target_id=target.id)
        _finish_run(run, status="failed", error=message)
        target.last_scan_error = message
        # Retry sooner than the normal cadence: the mirror is expected back
        # shortly, and leaving the target unscanned for a full cycle is worse.
        target.next_scan_at = utcnow() + timedelta(minutes=30)
        outcome.failed = True
        outcome.errors.append(message)
        return outcome

    scan_result, dependencies = result

    new_matches, resolved_count = await _reconcile_matches(db, target, scan_result)

    # Supply-chain signals are Pro-only and separate from CVE matching. Gated
    # here rather than inside the assessment so that a lapsed subscription
    # stops raising them without deleting the ones already on the project --
    # the same shape as every other tier check.
    if can_use_custom_rules(tier):
        await reconcile_signals(db, target, dependencies)

    target.dependency_count = len(dependencies)
    target.unreached_by_depth = scan_result.unreached_by_depth
    target.last_scanned_at = utcnow()
    # A rule that did not apply is reported, not swallowed. The risk of this
    # whole feature is somebody believing a rule is in force when it is not.
    if effective.notes:
        scan_result = replace(scan_result, errors=(*scan_result.errors, *effective.notes))

    # A rule a KEV listing set aside gets marked, so the settings page can show
    # it stopped applying rather than leaving it looking effective.
    overridden = {
        decision.vulnerability.id
        for decision in scan_result.actionable
        if decision.ignore_overridden
    } | {
        cve
        for decision in scan_result.actionable
        if decision.ignore_overridden
        for cve in decision.vulnerability.cve_ids
    }
    await record_overrides(db, target.id, overridden)

    target.last_scan_error = "; ".join(scan_result.errors) if scan_result.errors else None
    _schedule_next_scan(target, tier)

    _finish_run(
        run,
        status="success",
        dependencies_scanned=scan_result.dependencies_scanned,
        actionable_count=scan_result.actionable_count,
        suppressed_count=scan_result.suppressed_count,
        new_actionable_count=len(new_matches),
        resolved_count=resolved_count,
        error="; ".join(scan_result.errors) if scan_result.errors else None,
    )

    outcome.dependencies_scanned = scan_result.dependencies_scanned
    outcome.unreached_by_depth = scan_result.unreached_by_depth
    outcome.actionable_count = scan_result.actionable_count
    outcome.suppressed_count = scan_result.suppressed_count
    outcome.new_matches = new_matches
    outcome.resolved_count = resolved_count
    outcome.errors = list(scan_result.errors)

    log.info(
        "scan.completed",
        target_id=target.id,
        dependencies=outcome.dependencies_scanned,
        actionable=outcome.actionable_count,
        suppressed=outcome.suppressed_count,
        new=len(new_matches),
        resolved=resolved_count,
    )
    return outcome


async def _run_pipeline(
    db: AsyncSession,
    target: TrackedTarget,
    policy: MatchPolicy,
) -> tuple[ScanResult, list[Dependency]]:
    """Parse, look up advisories locally, triage.

    Makes no outbound HTTP calls. Advisories come from the mirror the worker
    maintains, so a scan is bounded by database latency rather than by OSV's,
    and an OSV outage cannot fail or delay a CI pipeline waiting on this.
    """
    if not target.has_manifest or target.manifest_kind is None:
        # A project created without a file. Nothing to scan, and refusing here
        # keeps it out of the "scanned, clean" state it has not earned.
        raise NoManifest(
            "This project has no manifest yet. Upload one, or push a scan with "
            "the CLI using an API key for this project."
        )

    parsed = parse_manifest(target.manifest_kind, target.manifest_content)
    dependencies = parsed.dependencies
    target.parse_warnings = parsed.warnings[:50]

    await _sync_dependency_rows(db, target, dependencies)

    if not dependencies:
        return ScanResult(dependencies_scanned=0, errors=tuple(parsed.warnings[:5])), []

    errors: list[str] = []

    # An empty mirror would report every project clean — the most dangerous
    # wrong answer this system can give. Refuse rather than reassure.
    if not await mirror_is_populated(db):
        raise MirrorUnavailable(
            "The advisory mirror has not been populated yet. Run "
            "`python -m app.jobs.runner sync-mirror` or wait for the worker."
        )

    settings = get_settings()
    if await mirror_is_stale(db, timedelta(hours=settings.mirror_stale_after_hours)):
        # Served, but labelled. Silently returning stale results is how a
        # scanner stops being trustworthy without anyone noticing.
        errors.append(
            "Advisory data is more than "
            f"{settings.mirror_stale_after_hours}h old; results may be incomplete."
        )

    by_dependency = await find_local_vulnerabilities(db, dependencies)

    referenced_cves = [
        cve for vulns in by_dependency.values() for vuln in vulns for cve in vuln.cve_ids
    ]
    kev_index = await load_kev_index(db, referenced_cves)
    # Loaded for every scan, not only where the project gates on it: the score
    # is shown on every finding, and a number that appears only for people who
    # switched on a threshold would be a worse explanation than none.
    epss_index = await load_epss_index(db, referenced_cves)

    return (
        triage_all(
            dependencies,
            by_dependency,
            kev_index,
            policy,
            errors=tuple(errors),
            epss_index=epss_index,
        ),
        dependencies,
    )


async def _sync_dependency_rows(
    db: AsyncSession, target: TrackedTarget, dependencies: list[Dependency]
) -> None:
    """Replace the stored dependency list with the freshly parsed one.

    Wholesale replacement rather than a diff: the dependency table is a cache of
    the manifest for display, it carries no user-owned state, and the manifest
    is the authority. Findings survive because `CVEMatch` denormalises the
    package name and version instead of referencing these rows.
    """
    existing = (
        await db.scalars(select(DependencyRecord).where(DependencyRecord.target_id == target.id))
    ).all()
    for row in existing:
        await db.delete(row)
    await db.flush()

    for dep in dependencies:
        db.add(
            DependencyRecord(
                target_id=target.id,
                ecosystem=dep.ecosystem,
                name=dep.name,
                version=dep.version,
                version_spec=dep.version_spec[:200],
                reachability=dep.reachability,
                version_exact=dep.version_exact,
                depth=dep.depth,
                via=list(dep.via),
            )
        )
    await db.flush()


async def _reconcile_matches(
    db: AsyncSession, target: TrackedTarget, result: ScanResult
) -> tuple[list[CVEMatch], int]:
    """Merge this scan's findings with what is already stored.

    Returns the newly-created actionable matches (the ones worth emailing about)
    and the count of previously-open matches that no longer apply.
    """
    stored = (await db.scalars(select(CVEMatch).where(CVEMatch.target_id == target.id))).all()
    by_identity = {
        (row.package_name, row.package_version, row.vulnerability_id): row for row in stored
    }

    now = utcnow()
    seen: set[tuple[str, str, str]] = set()
    new_actionable: list[CVEMatch] = []

    for decision in (*result.actionable, *result.suppressed):
        identity = (
            decision.dependency.name,
            decision.dependency.version,
            decision.vulnerability.id,
        )
        seen.add(identity)
        existing = by_identity.get(identity)

        if existing is None:
            match = CVEMatch(
                target_id=target.id,
                vulnerability_id=decision.vulnerability.id,
                ecosystem=decision.dependency.ecosystem,
                package_name=decision.dependency.name,
                package_version=decision.dependency.version,
                version_spec=decision.dependency.version_spec[:200],
                version_exact=decision.dependency.version_exact,
                reachability=decision.dependency.reachability,
                depth=decision.dependency.depth,
                via=list(decision.dependency.via),
                ignore_overridden=decision.ignore_overridden,
                epss_score=decision.epss_score,
                epss_percentile=decision.epss_percentile,
                verdict=decision.verdict,
                severity=decision.severity,
                is_kev=decision.kev,
                fixed_version=decision.fixed_version,
                actionable_reason=decision.actionable_reason,
                suppression_reason=decision.suppression_reason,
                status=AlertStatus.OPEN,
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(match)
            if decision.verdict is Verdict.ACTIONABLE:
                new_actionable.append(match)
            continue

        # Refresh the assessment — severity gets revised, a fix gets published,
        # a CVE lands on the KEV list — while keeping first_seen_at and any
        # dismissal the user applied.
        was_suppressed = existing.verdict is Verdict.SUPPRESSED
        was_resolved = existing.status is AlertStatus.RESOLVED
        existing.last_seen_at = now
        existing.verdict = decision.verdict
        existing.severity = decision.severity
        existing.is_kev = decision.kev
        existing.fixed_version = decision.fixed_version
        existing.actionable_reason = decision.actionable_reason
        existing.suppression_reason = decision.suppression_reason
        existing.reachability = decision.dependency.reachability
        # The tree can be reshaped by an upgrade without the finding changing
        # identity, so the route to it is refreshed alongside everything else.
        existing.depth = decision.dependency.depth
        existing.via = list(decision.dependency.via)
        existing.ignore_overridden = decision.ignore_overridden
        # Re-scored daily, so this is refreshed on every scan rather than
        # frozen at whatever it was the day the finding first appeared.
        existing.epss_score = decision.epss_score
        existing.epss_percentile = decision.epss_percentile

        if existing.status is AlertStatus.RESOLVED:
            # It came back (a downgrade, or a manifest revert).
            existing.status = AlertStatus.OPEN
            existing.resolved_at = None
            existing.notified_at = None

        # Two cases deserve a notification even though the row is not new:
        # a suppressed finding promoted to actionable (how a CVE landing on the
        # KEV list reaches the user), and a resolved finding that has come back
        # (a downgrade, or a reverted upgrade). Both are news.
        if (
            (was_suppressed or was_resolved)
            and decision.verdict is Verdict.ACTIONABLE
            and existing.status is AlertStatus.OPEN
        ):
            existing.notified_at = None
            new_actionable.append(existing)

    resolved_count = 0
    for identity, row in by_identity.items():
        if identity in seen or row.status is AlertStatus.RESOLVED:
            continue
        row.status = AlertStatus.RESOLVED
        row.resolved_at = now
        resolved_count += 1

    await db.flush()
    return new_actionable, resolved_count


def _schedule_next_scan(target: TrackedTarget, tier) -> None:
    """Set the next due time from the owner's plan."""
    target.next_scan_at = utcnow() + scan_interval_for(tier)


def _finish_run(run: ScanRun, status: str, error: str | None = None, **counts: int) -> None:
    run.status = status
    run.finished_at = utcnow()
    run.error = error[:4000] if error else None
    for key, value in counts.items():
        setattr(run, key, value)


async def due_targets(db: AsyncSession, limit: int | None = None) -> list[TrackedTarget]:
    """Active targets whose next scan time has passed (or was never set).

    Targets belonging to suspended or deactivated accounts are excluded via the
    join, so suspension stops the work rather than merely blocking the login —
    otherwise a suspended account would keep consuming OSV quota and keep
    sending alert emails to someone who can no longer sign in to act on them.
    """
    settings = get_settings()
    now = utcnow()
    query = (
        select(TrackedTarget)
        .join(User, User.id == TrackedTarget.user_id)
        .options(selectinload(TrackedTarget.user))
        .where(
            User.is_suspended.is_(False),
            User.is_active.is_(True),
            TrackedTarget.is_active.is_(True),
            (TrackedTarget.next_scan_at.is_(None)) | (TrackedTarget.next_scan_at <= now),
        )
        .order_by(TrackedTarget.next_scan_at.asc().nulls_first())
        .limit(limit or settings.job_max_targets_per_tick)
    )
    return list((await db.scalars(query)).all())
