"""Turning a project's rules into the policy one scan runs under.

Four sources, and a fixed order of precedence:

1. **The plan.** Scan depth, and whether custom rules apply at all.
2. **A rule profile**, if one applies -- the account's shared standard.
3. **The project's settings**, set in the interface.
4. **`.weedout.yml`**, pushed from the repository.

The file wins. A rule about a codebase belongs beside the codebase: it goes
through review, it moves with a branch, and `git log` answers "who silenced
this and when". A settings page that could quietly override the file would make
a CI run depend on something not visible from the checkout, which is the
opposite of what a policy file is for.

The profile sits underneath the project rather than over it, because that is
what a shared standard is for: a baseline every project starts from, which any
one project may override where it needs something different. A profile that
beat the project's own settings would make the per-project controls decorative.

Precedence is per setting rather than all-or-nothing. A file that only sets
thresholds does not wipe out ignores configured in the interface -- it says
nothing about them, and silence is not an instruction. Ignores from every layer
are unioned for the same reason: no layer un-ignores what another ignored, and
the only way to stop ignoring something is to remove the rule that says so.

Which profile applies is decided by `profile_service.profile_for_scan`, and
always server-side. `--profile production` from a pipeline is a request; a name
that does not resolve is an error, never a quiet fall back to the defaults.
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
from app.core.policy import ParsedPolicy, parse_policy
from app.core.types import IgnoreKind
from app.logging_config import get_logger
from app.models import IgnoreRule, TrackedTarget, User, utcnow
from app.services.profile_service import profile_for_scan
from app.tiers import scan_depth_for

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
    #: And for the profile, if one applied. Named so the interface and the CLI
    #: can say which rules came from the shared standard rather than from this
    #: project -- a rule somebody cannot locate is a rule they cannot change.
    ignored_from_profile: tuple[str, ...] = ()
    packages_from_profile: tuple[str, ...] = ()
    #: The profile that applied, by name, or None.
    profile_name: str | None = None

    @property
    def has_custom_rules(self) -> bool:
        return bool(
            self.ignored_from_file
            or self.ignored_from_settings
            or self.ignored_from_profile
            or self.packages_from_file
            or self.packages_from_settings
            or self.packages_from_profile
        )


async def build_policy(
    db: AsyncSession,
    target: TrackedTarget,
    owner: User | None,
    *,
    base: MatchPolicy = DEFAULT_POLICY,
    requested_profile: str | None = None,
) -> EffectivePolicy:
    """Assemble the policy this scan will run under.

    `requested_profile` is a name a pipeline asked for. It is resolved against
    the account's own profiles, and a name that does not exist raises
    `NoSuchProfile` rather than falling back -- a CI job that believes it is
    running under stricter rules than it is would be worse than one that fails.
    """
    tier = owner.tier if owner else "free"
    notes: list[str] = []

    policy = base
    depth = scan_depth_for(tier)
    if policy.max_depth is None and depth is not None:
        policy = replace(policy, max_depth=depth)

    parsed = parse_policy(target.policy_file)
    if parsed.error:
        # Failing open: every rule in the file stops applying, which can only
        # produce more alerts than intended, never fewer.
        notes.append(f"{parsed.error} The file was ignored and defaults applied.")
    notes.extend(parsed.warnings)

    # The file may name a profile itself, which is how a repository says "these
    # are production rules" without every pipeline passing a flag. An explicit
    # request still wins: it is the more local statement, made at the moment
    # the scan was asked for.
    profile = await profile_for_scan(db, target, requested=requested_profile or parsed.profile)
    from_profile = parse_policy(profile.document) if profile is not None else ParsedPolicy()
    if profile is not None:
        if from_profile.error:
            # Refused at save time, so reaching here means the document was
            # written before that check existed, or by a route that bypassed
            # it. Reported rather than swallowed, because a profile that
            # applies nothing looks identical to one that applies something.
            notes.append(
                f"The {profile.name} profile could not be read, so none of it applied: "
                f"{from_profile.error}"
            )
        notes.extend(f"{profile.name} profile: {warning}" for warning in from_profile.warnings)

    rows = await list_rules(db, target.id)
    from_settings = tuple(row.identifier for row in rows if row.kind is IgnoreKind.ADVISORY)
    packages_from_settings = tuple(row.identifier for row in rows if row.kind is IgnoreKind.PACKAGE)
    from_file = parsed.ignored_ids
    packages_from_file = parsed.ignored_packages
    from_profile_ids = from_profile.ignored_ids
    from_profile_packages = from_profile.ignored_packages

    policy = replace(
        policy,
        # The file first, the project's own setting second, the profile third,
        # the product default last.
        direct_threshold=(
            parsed.direct_threshold
            or target.direct_threshold
            or from_profile.direct_threshold
            or policy.direct_threshold
        ),
        transitive_threshold=(
            parsed.transitive_threshold
            or target.transitive_threshold
            or from_profile.transitive_threshold
            or policy.transitive_threshold
        ),
        # No default to fall back on: unset means the coarse switch decides,
        # so `policy.dev_threshold` stays None rather than picking a floor
        # nobody asked for.
        dev_threshold=(
            parsed.dev_threshold
            or target.dev_threshold
            or from_profile.dev_threshold
            or policy.dev_threshold
        ),
        # `or` is wrong for a float that can legitimately be 0-ish, so each
        # source is asked explicitly whether it spoke.
        epss_threshold=_first_set(
            parsed.epss_threshold, target.epss_threshold, from_profile.epss_threshold
        ),
        # Unioned rather than replaced: a layer that says nothing about an
        # identifier is not asking for it to be un-ignored.
        ignored_ids=normalise_ids([*from_settings, *from_file, *from_profile_ids]),
        ignored_packages=normalise_packages(
            [*packages_from_settings, *packages_from_file, *from_profile_packages]
        ),
    )

    return EffectivePolicy(
        policy=policy,
        notes=tuple(notes),
        ignored_from_file=from_file,
        ignored_from_settings=from_settings,
        ignored_from_profile=from_profile_ids,
        packages_from_file=packages_from_file,
        packages_from_settings=packages_from_settings,
        packages_from_profile=from_profile_packages,
        profile_name=profile.name if profile is not None else None,
    )


def _first_set(*values: float | None) -> float | None:
    """The first source that expressed an opinion.

    `or` would be wrong: 0.0 is a legitimate EPSS threshold and a falsy one, so
    a project setting it to zero would silently inherit whatever the layer
    underneath said.
    """
    for value in values:
        if value is not None:
            return value
    return None


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
