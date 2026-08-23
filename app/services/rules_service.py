"""Turning a project's rules into the policy one scan runs under.

Three sources, and a fixed order of precedence:

1. **The plan.** Scan depth, and whether custom rules apply at all.
2. **The project's settings**, set in the interface.
3. **`.weedout.yml`**, pushed from the repository.

The file wins. A rule about a codebase belongs beside the codebase: it goes
through review, it moves with a branch, and `git log` answers "who silenced
this and when". A settings page that could quietly override the file would make
a CI run depend on something not visible from the checkout, which is the
opposite of what a policy file is for.

Precedence is per setting rather than all-or-nothing. A file that only sets
thresholds does not wipe out ignores configured in the interface -- it says
nothing about them, and silence is not an instruction. Ignores from both
sources are unioned for the same reason.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.matching import (
    DEFAULT_POLICY,
    MatchPolicy,
    normalise_ids,
    normalise_packages,
)
from app.core.policy import parse_policy
from app.core.types import IgnoreKind
from app.logging_config import get_logger
from app.models import IgnoreRule, TrackedTarget, User, utcnow
from app.tiers import can_use_custom_rules, scan_depth_for

log = get_logger(__name__)

__all__ = ["EffectivePolicy", "build_policy", "list_rules", "record_overrides"]


@dataclass(slots=True)
class EffectivePolicy:
    """The policy for one scan, and how it was arrived at.

    `notes` is what the scan reports back to the user. A rule that did not
    apply, or a policy file that failed to parse, has to be visible -- the
    whole risk of this feature is somebody believing a rule is in force when it
    is not.
    """

    policy: MatchPolicy
    notes: tuple[str, ...] = ()
    #: Identifiers ignored, and where each came from, for the settings page.
    ignored_from_file: tuple[str, ...] = ()
    ignored_from_settings: tuple[str, ...] = ()
    #: The same, for package globs.
    packages_from_file: tuple[str, ...] = ()
    packages_from_settings: tuple[str, ...] = ()

    @property
    def has_custom_rules(self) -> bool:
        return bool(
            self.ignored_from_file
            or self.ignored_from_settings
            or self.packages_from_file
            or self.packages_from_settings
        )


async def build_policy(
    db: AsyncSession,
    target: TrackedTarget,
    owner: User | None,
    *,
    base: MatchPolicy = DEFAULT_POLICY,
) -> EffectivePolicy:
    """Assemble the policy this scan will run under."""
    tier = owner.tier if owner else "free"
    notes: list[str] = []

    policy = base
    depth = scan_depth_for(tier)
    if policy.max_depth is None and depth is not None:
        policy = replace(policy, max_depth=depth)

    if not can_use_custom_rules(tier):
        # The rows may exist -- from a lapsed subscription, or from a policy
        # file a Pro pipeline pushed earlier. They simply stop applying, which
        # is the same shape as every other tier check here: enforced at use,
        # not by deleting the user's configuration.
        if (
            target.policy_file
            or target.direct_threshold
            or target.transitive_threshold
            or target.dev_threshold
        ):
            notes.append("Custom scan rules are part of the Pro plan, so they were not applied.")
        return EffectivePolicy(policy=policy, notes=tuple(notes))

    parsed = parse_policy(target.policy_file)
    if parsed.error:
        # Failing open: every rule in the file stops applying, which can only
        # produce more alerts than intended, never fewer.
        notes.append(f"{parsed.error} The file was ignored and defaults applied.")
    notes.extend(parsed.warnings)

    rows = await list_rules(db, target.id)
    from_settings = tuple(row.identifier for row in rows if row.kind is IgnoreKind.ADVISORY)
    packages_from_settings = tuple(row.identifier for row in rows if row.kind is IgnoreKind.PACKAGE)
    from_file = parsed.ignored_ids
    packages_from_file = parsed.ignored_packages

    policy = replace(
        policy,
        # The file first, the project's own setting second, the default last.
        direct_threshold=(
            parsed.direct_threshold or target.direct_threshold or policy.direct_threshold
        ),
        transitive_threshold=(
            parsed.transitive_threshold
            or target.transitive_threshold
            or policy.transitive_threshold
        ),
        # No default to fall back on: unset means the coarse switch decides,
        # so `policy.dev_threshold` stays None rather than picking a floor
        # nobody asked for.
        dev_threshold=(parsed.dev_threshold or target.dev_threshold or policy.dev_threshold),
        # `or` is wrong for a float that can legitimately be 0-ish, so this is
        # explicit about which source spoke.
        epss_threshold=(
            parsed.epss_threshold if parsed.epss_threshold is not None else target.epss_threshold
        ),
        # Unioned rather than replaced: a file that says nothing about an
        # identifier is not asking for it to be un-ignored.
        ignored_ids=normalise_ids([*from_settings, *from_file]),
        ignored_packages=normalise_packages([*packages_from_settings, *packages_from_file]),
    )

    return EffectivePolicy(
        policy=policy,
        notes=tuple(notes),
        ignored_from_file=from_file,
        ignored_from_settings=from_settings,
        packages_from_file=packages_from_file,
        packages_from_settings=packages_from_settings,
    )


async def list_rules(db: AsyncSession, target_id: int) -> list[IgnoreRule]:
    rows = (
        await db.execute(
            select(IgnoreRule)
            .where(IgnoreRule.target_id == target_id)
            .order_by(IgnoreRule.created_at.desc())
        )
    ).scalars()
    return list(rows)


async def record_overrides(db: AsyncSession, target_id: int, identifiers: set[str]) -> int:
    """Mark rules that a KEV listing set aside during this scan.

    Recorded so the settings page can say a rule stopped applying. Somebody who
    wrote "ignore this, it is disputed" needs to see that it is now being
    exploited, and finding that out from the alert alone leaves the stale rule
    sitting there looking effective.
    """
    if not identifiers:
        return 0

    upper = {value.upper() for value in identifiers}
    marked = 0
    for rule in await list_rules(db, target_id):
        # Advisory rules only. A package glob is not overridden by one KEV
        # listing -- it still holds for every other advisory it covers -- so
        # marking it as set aside would be a false statement on the settings
        # page.
        if rule.kind is not IgnoreKind.ADVISORY:
            continue
        if rule.identifier.upper() in upper and rule.overridden_at is None:
            rule.overridden_at = utcnow()
            marked += 1
            log.info("rules.override_recorded", target_id=target_id, identifier=rule.identifier)
    return marked
