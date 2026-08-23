"""Named rule profiles: an account's scan rules, reusable across projects.

A profile is a policy document under a name. The same YAML that goes in
`.weedout.yml`, stored on the account, so a team sets its standard once instead
of configuring eight projects identically and watching them drift.

Three things this module owns, and the third is the one that matters:

1. **CRUD**, with validation at save time. Unlike the repository file, an
   unparseable profile is refused rather than recorded -- somebody is standing
   there, and telling them now beats discarding the document at scan time.
2. **The default**, of which there is at most one per account.
3. **Resolution**: given a project, and possibly a name a pipeline asked for,
   which profile applies. Server-side, always. `--profile production` is a
   claim by the caller about which rules they would like; it is resolved
   against the account's own profiles, and a name that does not exist is an
   error rather than a silent fall back to the defaults. A CI job that believes
   it is running stricter rules than it is would be worse than one that fails.
"""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.policy import parse_policy
from app.logging_config import get_logger
from app.models import RuleProfile, TrackedTarget, User

log = get_logger(__name__)

__all__ = [
    "MAX_PROFILES",
    "NoSuchProfile",
    "ProfileError",
    "ProfileLimitReached",
    "ProfileNameTaken",
    "create_profile",
    "delete_profile",
    "get_profile",
    "list_profiles",
    "profile_for_scan",
    "set_default",
    "slugify_profile",
    "update_profile",
]

#: Enough for the shape of team this feature is for, and low enough that a
#: runaway script does not fill the table. Nobody has forty standards.
MAX_PROFILES = 20

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


class ProfileError(Exception):
    """Something a person did, phrased for the person who did it."""


class ProfileNameTaken(ProfileError):
    pass


class ProfileLimitReached(ProfileError):
    pass


class NoSuchProfile(ProfileError):
    """A name that does not resolve.

    Raised rather than swallowed. A pipeline passing `--profile production`
    against an account with no such profile is running under rules nobody
    chose, and it must find that out from a failure rather than from an
    incident six months later.
    """


def slugify_profile(name: str) -> str:
    """What `--profile` matches.

    A pipeline should not have to reproduce capitalisation or spacing, so
    "Production APIs", "production-apis" and "PRODUCTION_APIS" all resolve to
    the same profile.
    """
    return _SLUG_STRIP.sub("-", name.strip().lower()).strip("-")


async def list_profiles(db: AsyncSession, user_id: int) -> list[RuleProfile]:
    rows = await db.scalars(
        select(RuleProfile)
        .where(RuleProfile.user_id == user_id)
        # The default first, then alphabetically: the one that applies when
        # nobody said anything is the one people look for.
        .order_by(RuleProfile.is_default.desc(), RuleProfile.name)
    )
    return list(rows.all())


async def get_profile(db: AsyncSession, user_id: int, slug: str) -> RuleProfile | None:
    return await db.scalar(
        select(RuleProfile).where(
            RuleProfile.user_id == user_id,
            RuleProfile.slug == slugify_profile(slug),
        )
    )


async def create_profile(
    db: AsyncSession,
    owner: User,
    *,
    name: str,
    document: str = "",
    description: str = "",
    make_default: bool = False,
) -> RuleProfile:
    slug = slugify_profile(name)
    if not slug:
        raise ProfileError("Give the profile a name -- something like Production.")

    existing = await list_profiles(db, owner.id)
    if len(existing) >= MAX_PROFILES:
        raise ProfileLimitReached(
            f"That is {MAX_PROFILES} profiles, which is the limit. "
            "Edit one of the existing ones instead."
        )
    if any(profile.slug == slug for profile in existing):
        raise ProfileNameTaken(f"You already have a profile called {name.strip()}.")

    _validate(document)

    profile = RuleProfile(
        user_id=owner.id,
        name=name.strip()[:80],
        slug=slug,
        description=description.strip()[:300],
        document=document,
    )
    db.add(profile)
    await db.flush()

    # The first profile becomes the default unless told otherwise. Somebody who
    # creates exactly one profile means for it to apply; making them take a
    # second step to say so is a way to end up with a profile that does nothing.
    if make_default or not existing:
        await set_default(db, owner.id, profile)

    log.info("profile.created", user_id=owner.id, slug=slug, is_default=profile.is_default)
    return profile


async def update_profile(
    db: AsyncSession,
    profile: RuleProfile,
    *,
    name: str | None = None,
    document: str | None = None,
    description: str | None = None,
) -> RuleProfile:
    if document is not None:
        _validate(document)
        profile.document = document

    if name is not None:
        slug = slugify_profile(name)
        if not slug:
            raise ProfileError("Give the profile a name -- something like Production.")
        if slug != profile.slug:
            clash = await get_profile(db, profile.user_id, slug)
            if clash is not None:
                raise ProfileNameTaken(f"You already have a profile called {name.strip()}.")
            # Renaming changes what `--profile` matches, which can break a
            # pipeline. Refusing would be worse -- a name nobody can fix is its
            # own trap -- so it is allowed and logged.
            log.info(
                "profile.renamed",
                user_id=profile.user_id,
                was=profile.slug,
                now=slug,
            )
        profile.name = name.strip()[:80]
        profile.slug = slug

    if description is not None:
        profile.description = description.strip()[:300]

    await db.flush()
    return profile


async def set_default(db: AsyncSession, user_id: int, profile: RuleProfile | None) -> None:
    """Make one profile the account default, or clear the setting entirely.

    Clears the others in the same flush, because the partial unique index would
    otherwise refuse the second write -- and because two defaults would leave
    "which rules apply" without an answer.
    """
    for other in await list_profiles(db, user_id):
        other.is_default = False
    # Flushed before setting the new one so the index sees one default at a
    # time rather than two.
    await db.flush()

    if profile is not None:
        profile.is_default = True
        await db.flush()
        log.info("profile.default_set", user_id=user_id, slug=profile.slug)
    else:
        log.info("profile.default_cleared", user_id=user_id)


async def delete_profile(db: AsyncSession, profile: RuleProfile) -> None:
    """Remove a profile. Projects using it fall back to the account default.

    `ondelete="SET NULL"` on the foreign key rather than a refusal, because a
    profile nobody can delete until they have visited every project using it is
    a profile people work around by emptying its document instead -- which
    leaves a rule set that looks configured and does nothing.
    """
    log.info("profile.deleted", user_id=profile.user_id, slug=profile.slug)
    await db.delete(profile)
    await db.flush()


async def profile_for_scan(
    db: AsyncSession,
    target: TrackedTarget,
    *,
    requested: str | None = None,
) -> RuleProfile | None:
    """Which profile applies to this scan.

    Most specific first:

    1. A name the caller asked for -- `--profile production`, or a `profile:`
       key in the repository's `.weedout.yml`. Resolved here rather than
       trusted: the name is matched against the account's own profiles, and one
       that does not exist raises.
    2. The profile assigned to this project.
    3. The account default.
    4. Nothing, and the product defaults apply.
    """
    if requested and requested.strip():
        profile = await get_profile(db, target.user_id, requested)
        if profile is None:
            raise NoSuchProfile(
                f"There is no rule profile called {requested.strip()!r} on this account."
            )
        return profile

    if target.profile_id is not None:
        assigned = await db.get(RuleProfile, target.profile_id)
        # Ownership re-checked rather than assumed. The column is set through
        # an endpoint that verifies it, but this is the function whose answer
        # decides what gets reported, and it should not depend on that.
        if assigned is not None and assigned.user_id == target.user_id:
            return assigned

    return await db.scalar(
        select(RuleProfile).where(
            RuleProfile.user_id == target.user_id,
            RuleProfile.is_default.is_(True),
        )
    )


def _validate(document: str) -> None:
    """Refuse a document that cannot be read.

    The repository file is recorded with its error and discarded at scan time,
    because refusing a push is not something this service can do. Here it is:
    the author is waiting for a response, and a profile saved broken would sit
    on the account looking like a rule set while applying nothing.
    """
    parsed = parse_policy(document)
    if parsed.error:
        raise ProfileError(parsed.error)

    if parsed.profile is not None:
        # A profile naming a profile has no useful reading and an obvious bad
        # one: profiles that reference each other in a loop. `profile:` belongs
        # in a repository's own file, which is where the choice is made.
        raise ProfileError(
            "A profile cannot name another profile. Remove the `profile:` line -- "
            "that key belongs in a repository's .weedout.yml, where it chooses "
            "which profile to use."
        )
