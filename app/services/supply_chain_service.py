"""Raising and reconciling supply-chain signals.

Reconciled the same way CVE matches are, and for the same reason: a signal has
to keep its identity across scans so that dismissing one sticks. Being told a
second time that you chose an oddly-named package on purpose is how a signal
gets switched off entirely, and a signal nobody reads protects nobody.

Signals that stop applying are deleted rather than marked resolved. A finding
that has gone away is history worth keeping -- somebody fixed it -- but a
package that is no longer in the manifest was never a fact about the project,
only about a version of it.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.supply_chain import (
    PackageFacts,
    SupplyChainSignal,
    assess_facts,
    check_typosquat,
)
from app.core.types import AlertStatus, Dependency
from app.feeds.registry import supports_metadata
from app.logging_config import get_logger
from app.models import SupplyChainFinding, TrackedTarget, utcnow
from app.services.package_metadata_service import facts_for

log = get_logger(__name__)

__all__ = ["SupplyChainOutcome", "assess", "reconcile_signals"]


@dataclass(slots=True)
class SupplyChainOutcome:
    raised: int = 0
    still_open: int = 0
    cleared: int = 0

    @property
    def total(self) -> int:
        return self.raised + self.still_open


def assess(dependency: Dependency, facts: PackageFacts | None = None) -> list[SupplyChainSignal]:
    """Every signal that applies to one package.

    Pure, and deliberately so: the checks that need the network -- how long ago
    the last release was, how many maintainers there are, whether the build has
    provenance -- read a cache that a job fills, never the registry itself. A
    scan that made a request per dependency would turn a 300-package manifest
    into 300 outbound calls on the request path.
    """
    signals: list[SupplyChainSignal] = []

    typosquat = check_typosquat(dependency.name, dependency.ecosystem)
    if typosquat is not None:
        signals.append(typosquat)

    # Absent facts produce no signals rather than reassuring ones. "We have not
    # asked the registry about this package" and "we asked and it is fine" are
    # different answers, and only one of them is safe to imply.
    if facts is not None:
        signals.extend(assess_facts(facts))

    return signals


async def reconcile_signals(
    db: AsyncSession, target: TrackedTarget, dependencies: list[Dependency]
) -> SupplyChainOutcome:
    """Bring the stored signals in line with what this scan found."""
    outcome = SupplyChainOutcome()
    now = utcnow()

    known = await facts_for(
        db, [(d.ecosystem, d.name) for d in dependencies if supports_metadata(d.ecosystem)]
    )

    existing = {
        (row.package_name, row.kind): row
        for row in (
            await db.execute(
                select(SupplyChainFinding).where(SupplyChainFinding.target_id == target.id)
            )
        ).scalars()
    }

    seen: set[tuple[str, object]] = set()

    for dependency in dependencies:
        for signal in assess(dependency, known.get((dependency.ecosystem, dependency.name))):
            key = (dependency.name, signal.kind)
            seen.add(key)

            row = existing.get(key)
            if row is None:
                db.add(
                    SupplyChainFinding(
                        target_id=target.id,
                        ecosystem=dependency.ecosystem,
                        package_name=dependency.name,
                        package_version=dependency.version,
                        kind=signal.kind,
                        level=signal.level,
                        detail=signal.detail,
                        data=signal.data or {},
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                )
                outcome.raised += 1
                continue

            # Refreshed, but the status is left alone: a dismissal is the
            # user's decision about this package and re-running a scan is not
            # new information that overturns it.
            row.package_version = dependency.version
            row.level = signal.level
            row.detail = signal.detail
            row.data = signal.data or {}
            row.last_seen_at = now
            outcome.still_open += 1

    for key, row in existing.items():
        if key not in seen:
            # The package left the manifest, or the signal stopped applying.
            # Deleted rather than resolved: it was a fact about a version of
            # this project, not about the project.
            await db.delete(row)
            outcome.cleared += 1

    if outcome.raised or outcome.cleared:
        log.info(
            "supply_chain.reconciled",
            target_id=target.id,
            raised=outcome.raised,
            cleared=outcome.cleared,
        )
    return outcome


async def open_signals(db: AsyncSession, target_id: int) -> list[SupplyChainFinding]:
    rows = (
        await db.execute(
            select(SupplyChainFinding)
            .where(
                SupplyChainFinding.target_id == target_id,
                SupplyChainFinding.status == AlertStatus.OPEN,
            )
            .order_by(SupplyChainFinding.level, SupplyChainFinding.package_name)
        )
    ).scalars()
    return list(rows)
