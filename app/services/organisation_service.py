"""An account that is a company, and the gate on naming one in public.

Two separate things, and the second is the one worth being careful about.

**Account kind** is a label. An organisation account is a personal account that
has told us it is a company, so invoices and the interface can say the right
thing. The plan, the limits, and everything the account may do are identical.
It is not a team — one login, no members, no roles — and this module refuses to
imply otherwise.

**The showcase** is the landing page's "who uses this" section, and it needs
two independent things to be true before a name appears:

1. **They asked.** For an ordinary product a logo wall is a marketing asset.
   For this one, naming a company says publicly that they scan their
   dependencies with us, which is a fact about their security programme. That
   is theirs to disclose, not ours, so it is opt-in, off by default, and
   revocable in one click.

2. **We checked.** Consent alone would let anybody sign up as a well-known
   company and appear on our front page — impersonation with our own marketing
   as the vehicle. The check is a person looking at the name and the website,
   not a rule, because no rule distinguishes "Acme Ltd, three people" from
   "Acme Corp, whose name this is".

Either one missing means nothing is shown. `is_showcased` on the model is the
single place that decides, so no query can accidentally publish a name by
forgetting half the condition.
"""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.types import AccountKind
from app.logging_config import get_logger
from app.models import User, utcnow

log = get_logger(__name__)

__all__ = [
    "MAX_SHOWCASE",
    "OrganisationError",
    "approve_showcase",
    "become_organisation",
    "become_personal",
    "revoke_showcase",
    "set_showcase_opt_in",
    "showcased_organisations",
]

#: How many names the landing page will show.
#:
#: A cap rather than everything, because a wall of forty is a wall nobody
#: reads and because the section should stop growing before it starts looking
#: like a directory.
MAX_SHOWCASE = 12

#: A website, loosely. Not validated for reachability -- it exists so a person
#: reviewing a showcase request has something to look at, and refusing an
#: unusual but real URL would be worse than accepting a useless one.
_URL = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


class OrganisationError(Exception):
    """Something a person did, phrased for the person who did it."""


async def become_organisation(
    db: AsyncSession,
    user: User,
    *,
    name: str,
    website: str = "",
) -> User:
    """Record that this account is a company.

    Changes nothing about what the account can do. Deliberately: an account
    type that quietly altered limits would make "are you a company?" a question
    with a wrong answer, and people would learn to lie about it in whichever
    direction was cheaper.
    """
    cleaned = name.strip()
    if not cleaned:
        raise OrganisationError("What is the company called?")
    if len(cleaned) > 200:
        raise OrganisationError("That name is too long.")

    site = website.strip()
    if site and not _URL.match(site):
        raise OrganisationError("That does not look like a website. Include https://.")

    user.account_kind = AccountKind.ORGANIZATION
    user.organisation_name = cleaned
    user.organisation_website = site[:300] or None

    # A rename invalidates the approval. We checked that one name was theirs
    # to give; the next one is a different claim, and carrying the tick over
    # would let an approved account swap in any name it liked.
    if user.showcase_approved_at is not None:
        user.showcase_approved_at = None
        log.info("organisation.approval_reset_on_rename", user_id=user.id)

    await db.flush()
    log.info("organisation.set", user_id=user.id)
    return user


async def become_personal(db: AsyncSession, user: User) -> User:
    """Go back to a personal account.

    Clears the showcase along with the company details. An account with no
    company name has nothing to show, and leaving the opt-in set would mean a
    later rename re-published somebody who had stopped being a company.
    """
    user.account_kind = AccountKind.PERSONAL
    user.organisation_name = None
    user.organisation_website = None
    user.showcase_opt_in = False
    user.showcase_approved_at = None

    await db.flush()
    log.info("organisation.cleared", user_id=user.id)
    return user


async def set_showcase_opt_in(db: AsyncSession, user: User, *, opted_in: bool) -> User:
    """Ask to be named on the landing page, or stop being named.

    Turning it off takes effect immediately and does not need anybody's
    approval — withdrawing consent must never be slower than giving it.
    """
    if opted_in and user.account_kind is not AccountKind.ORGANIZATION:
        raise OrganisationError(
            "Only an organisation account can be listed. Add your company name first."
        )
    if opted_in and not user.organisation_name:
        raise OrganisationError("Add your company name first.")

    user.showcase_opt_in = opted_in
    await db.flush()

    log.info("organisation.showcase_opt_in", user_id=user.id, opted_in=opted_in)
    return user


async def approve_showcase(db: AsyncSession, user: User) -> User:
    """A person has checked that the name is theirs to give.

    Separate from consent, and an admin action. See the module docstring for
    why both are needed.
    """
    if user.account_kind is not AccountKind.ORGANIZATION or not user.organisation_name:
        raise OrganisationError("That account has no company name to approve.")

    user.showcase_approved_at = utcnow()
    await db.flush()
    log.info("organisation.showcase_approved", user_id=user.id)
    return user


async def revoke_showcase(db: AsyncSession, user: User) -> User:
    """Take a name off the landing page without touching their consent.

    The two are stored separately so this is possible: an approval withdrawn
    because the company turned out not to be who we thought is our decision,
    and clearing their opt-in as well would misrepresent it as theirs.
    """
    user.showcase_approved_at = None
    await db.flush()
    log.info("organisation.showcase_revoked", user_id=user.id)
    return user


async def showcased_organisations(db: AsyncSession, limit: int = MAX_SHOWCASE) -> list[User]:
    """The accounts the landing page may name.

    Every condition is in the query rather than filtered afterwards, so there
    is no path where a caller forgets one. Suspended accounts are excluded too:
    a name on the front page is an endorsement in both directions.
    """
    rows = await db.scalars(
        select(User)
        .where(
            User.account_kind == AccountKind.ORGANIZATION,
            User.organisation_name.is_not(None),
            User.showcase_opt_in.is_(True),
            User.showcase_approved_at.is_not(None),
            User.is_active.is_(True),
            User.is_suspended.is_(False),
        )
        # Oldest approval first, so the section is stable rather than
        # reshuffling on every deploy.
        .order_by(User.showcase_approved_at)
        .limit(max(1, limit))
    )
    return list(rows.all())
