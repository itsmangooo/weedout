"""Issuing, authenticating and revoking API keys.

Keys are opaque bearer tokens, stored only as a SHA-256 hash. The plaintext
exists exactly once — in the response that creates it — and there is
deliberately no code path anywhere that can recover it afterwards. "Show it
again" is not a feature that was left out; it is the property that makes a
database leak not also a credential leak.

A key is scoped to one project rather than to an account. A CI runner builds
one repository, so the credential it holds should be able to push results for
that repository and nothing else. It also removes a whole class of mistake from
the API: the client never names a destination project, so it cannot name the
wrong one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.logging_config import get_logger
from app.models import ApiKey, TrackedTarget, User, utcnow
from app.security import api_key_prefix, generate_api_key, hash_api_key

log = get_logger(__name__)

__all__ = [
    "IssuedKey",
    "authenticate_api_key",
    "issue_api_key",
    "keys_for_target",
    "keys_for_user",
    "revoke_api_key",
]

#: How long a key may go unrecorded before `last_used_at` is written again.
#:
#: Every authenticated request would otherwise mean a write, turning a
#: read-only scan into a row update and putting a hot lock on one row per busy
#: CI project. The column exists to answer "is this key still in use?", and an
#: answer accurate to the minute is entirely sufficient for that.
LAST_USED_THROTTLE = timedelta(minutes=1)

#: Ceiling on live keys per project. Not a billing limit — a blast-radius one:
#: a forgotten pile of active credentials is how a leaked key stays useful long
#: after the person who created it has left.
MAX_ACTIVE_KEYS_PER_TARGET = 5


class ApiKeyError(Exception):
    """A key could not be issued, for a reason worth showing the user."""


@dataclass(frozen=True, slots=True)
class IssuedKey:
    """A newly created key, with its plaintext — the only time it exists."""

    record: ApiKey
    token: str


async def issue_api_key(
    db: AsyncSession, user: User, target: TrackedTarget, name: str = ""
) -> IssuedKey:
    """Create a key for one of the user's projects.

    Ownership is re-checked here rather than trusted from the caller: this
    function mints a credential, and a mistake in a route handler must not be
    able to mint one against somebody else's project.
    """
    if target.user_id != user.id:
        raise ApiKeyError("That project does not belong to you.")

    active = await db.scalar(
        select(ApiKey)
        .where(ApiKey.target_id == target.id, ApiKey.revoked_at.is_(None))
        .limit(MAX_ACTIVE_KEYS_PER_TARGET)
        .offset(MAX_ACTIVE_KEYS_PER_TARGET - 1)
    )
    if active is not None:
        raise ApiKeyError(
            f"This project already has {MAX_ACTIVE_KEYS_PER_TARGET} active keys. "
            "Revoke one before creating another."
        )

    token = generate_api_key()
    record = ApiKey(
        user_id=user.id,
        target_id=target.id,
        token_hash=hash_api_key(token),
        prefix=api_key_prefix(token),
        name=name.strip()[:120],
    )
    db.add(record)
    await db.flush()

    log.info("api_key.issued", key_id=record.id, target_id=target.id, user_id=user.id)
    return IssuedKey(record=record, token=token)


async def revoke_api_key(db: AsyncSession, user: User, key_id: int) -> bool:
    """Revoke one of the user's keys. Returns False if it was not theirs.

    The row is kept rather than deleted so the Settings list can show that a
    key existed and when it stopped working. A revoked key is dead on the next
    request — authentication is a database lookup, not a signature check, which
    is the whole reason to prefer opaque tokens over self-contained ones here.
    """
    record = await db.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user.id))
    if record is None:
        return False
    if record.revoked_at is None:
        record.revoked_at = utcnow()
        log.info("api_key.revoked", key_id=record.id, user_id=user.id)
    return True


async def keys_for_user(db: AsyncSession, user: User) -> list[ApiKey]:
    """Every key the user has, newest first, with its project loaded."""
    return list(
        (
            await db.scalars(
                select(ApiKey)
                .where(ApiKey.user_id == user.id)
                .options(selectinload(ApiKey.target))
                .order_by(ApiKey.revoked_at.is_(None).desc(), ApiKey.created_at.desc())
            )
        ).all()
    )


async def keys_for_target(db: AsyncSession, target_id: int) -> list[ApiKey]:
    """Every key issued for one project, live ones first."""
    return list(
        (
            await db.scalars(
                select(ApiKey)
                .where(ApiKey.target_id == target_id)
                .order_by(ApiKey.revoked_at.is_(None).desc(), ApiKey.created_at.desc())
            )
        ).all()
    )


async def authenticate_api_key(db: AsyncSession, token: str | None) -> ApiKey | None:
    """Resolve a bearer token to a live key, or None.

    Returns None for every failure — absent, malformed, unknown, revoked, or
    belonging to a suspended account. The caller turns that into one
    indistinguishable 401: telling a caller that a key is *revoked* rather than
    *unrecognised* confirms it was once real, which is a free oracle for anyone
    testing a list of leaked strings.
    """
    if not token:
        return None

    record = await db.scalar(
        select(ApiKey)
        .where(ApiKey.token_hash == hash_api_key(token), ApiKey.revoked_at.is_(None))
        .options(selectinload(ApiKey.target), selectinload(ApiKey.user))
    )
    if record is None:
        return None

    # A suspended or deactivated owner must not keep pushing scans through a
    # credential issued before the suspension.
    if record.user is None or not record.user.can_sign_in:
        return None
    if record.target is None:
        return None

    # The call count is exact and unthrottled; the timestamp keeps its write
    # throttle. Counting every call is one integer increment on a row already
    # loaded, and a count that skipped writes would understate CI activity by
    # exactly the amount the throttle saved.
    record.call_count = (record.call_count or 0) + 1

    now = utcnow()
    if record.last_used_at is None or now - record.last_used_at > LAST_USED_THROTTLE:
        record.last_used_at = now

    return record


def parse_bearer_token(header: str | None) -> str | None:
    """Pull the token out of an `Authorization: Bearer <key>` header.

    Tolerant of the scheme's casing, since HTTP clients disagree about it, and
    strict about everything else — a header that is not a bearer credential is
    not quietly treated as one.
    """
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer":
        return None
    value = value.strip()
    return value or None
