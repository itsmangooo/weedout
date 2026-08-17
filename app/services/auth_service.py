"""Signup, login, and server-side session lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.types import Tier
from app.logging_config import get_logger
from app.models import Session, User, utcnow
from app.security import (
    check_password_strength,
    dummy_verify,
    generate_session_token,
    hash_password,
    hash_session_token,
    needs_rehash,
    verify_password,
)

log = get_logger(__name__)

__all__ = [
    "AuthError",
    "EmailAlreadyRegistered",
    "InvalidCredentials",
    "WeakPassword",
    "authenticate",
    "create_session",
    "register_user",
    "revoke_session",
    "session_user",
]


class AuthError(Exception):
    """Base class for authentication failures."""


class EmailAlreadyRegistered(AuthError):
    pass


class WeakPassword(AuthError):
    pass


class InvalidCredentials(AuthError):
    pass


def normalize_email(email: str) -> str:
    return email.strip().lower()


async def register_user(db: AsyncSession, email: str, password: str) -> User:
    """Create an account.

    The uniqueness check is advisory only — the database constraint is what
    actually prevents duplicates, since two concurrent signups can both pass a
    pre-check. `IntegrityError` is caught and translated rather than allowed to
    surface as a 500.
    """
    email = normalize_email(email)

    if problem := check_password_strength(password):
        raise WeakPassword(problem)

    existing = await db.scalar(select(User.id).where(User.email == email))
    if existing is not None:
        raise EmailAlreadyRegistered("That email address is already registered.")

    user = User(email=email, password_hash=hash_password(password), tier=Tier.FREE)
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise EmailAlreadyRegistered("That email address is already registered.") from exc

    # Also promoted here, not just in `authenticate`: signing up *is* the first
    # sign-in, and requiring the configured admin to log out and back in to get
    # their own panel would be a needless piece of folklore.
    await promote_configured_admin(db, user)

    log.info("auth.user_registered", user_id=user.id)
    return user


async def authenticate(db: AsyncSession, email: str, password: str) -> User:
    """Verify credentials and return the user.

    Raises `InvalidCredentials` for unknown addresses, wrong passwords,
    deactivated accounts and suspended accounts alike, so the response cannot
    be used to enumerate which addresses are registered — or which are
    suspended, which would tell an attacker their action had an effect.
    """
    email = normalize_email(email)
    user = await db.scalar(select(User).where(User.email == email))

    if user is None:
        dummy_verify()  # keep the timing indistinguishable from a wrong password
        raise InvalidCredentials("Incorrect email or password.")

    if not verify_password(password, user.password_hash):
        raise InvalidCredentials("Incorrect email or password.")

    if not user.can_sign_in:
        log.info(
            "auth.login_blocked",
            user_id=user.id,
            suspended=user.is_suspended,
            active=user.is_active,
        )
        raise InvalidCredentials("Incorrect email or password.")

    # Transparently upgrade hashes written under older Argon2 parameters.
    if user.password_hash and needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        log.info("auth.password_rehashed", user_id=user.id)

    await promote_configured_admin(db, user)

    user.last_login_at = utcnow()
    return user


async def promote_configured_admin(db: AsyncSession, user: User) -> bool:
    """Grant admin rights to the address named by `ADMIN_EMAIL`, once.

    This is how the single super-admin bootstraps: no seeded credential, no
    "become admin" UI, no hardcoded account. If `ADMIN_EMAIL` is unset nothing
    is promoted and `python -m app.manage promote-admin` remains the only route.

    Returns True when a promotion actually happened, so the caller can audit it.
    """
    admin_email = get_settings().admin_email
    if not admin_email or user.is_admin or user.email != admin_email:
        return False

    user.is_admin = True
    log.warning("auth.admin_promoted", user_id=user.id, email=user.email)

    # Recorded in the audit trail too — an admin appearing is exactly the kind
    # of event that must be visible in the log the panel itself displays.
    from app.models import AdminAuditLog

    db.add(
        AdminAuditLog(
            actor_user_id=user.id,
            actor_email=user.email,
            action="admin.self_promoted",
            target_user_id=user.id,
            target_email=user.email,
            details={"source": "ADMIN_EMAIL environment variable"},
        )
    )
    return True


async def create_session(
    db: AsyncSession,
    user: User,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> str:
    """Open a session and return the raw token to put in the cookie.

    Only the token's hash is persisted, so the plaintext exists solely in this
    return value and in the user's cookie.
    """
    settings = get_settings()
    token = generate_session_token()

    db.add(
        Session(
            user_id=user.id,
            token_hash=hash_session_token(token),
            expires_at=datetime.now(UTC) + timedelta(hours=settings.session_ttl_hours),
            user_agent=(user_agent or "")[:512] or None,
            ip_address=(ip_address or "")[:64] or None,
        )
    )
    await db.flush()

    log.info("auth.session_created", user_id=user.id)
    return token


async def session_user(db: AsyncSession, token: str | None) -> User | None:
    """Resolve a session cookie to its user, or None.

    Validated against the database on every request. That is the whole point of
    server-side sessions: a revoked or expired row stops working immediately,
    with no window during which a self-contained token remains honoured.
    """
    if not token:
        return None

    token_hash = hash_session_token(token)
    session = await db.scalar(select(Session).where(Session.token_hash == token_hash))
    if session is None or not session.is_valid:
        return None

    user = await db.get(User, session.user_id)
    if user is None or not user.can_sign_in:
        # Checked per request, so suspending an account logs it out of every
        # open browser tab immediately rather than at next login.
        return None

    # Throttle the write: updating on every request would make each page view a
    # write transaction for no useful gain in accuracy.
    now = utcnow()
    if (now - session.last_seen_at) > timedelta(minutes=5):
        session.last_seen_at = now

    return user


async def revoke_session(db: AsyncSession, token: str | None) -> None:
    """Log out. Idempotent — an unknown or already-revoked token is a no-op."""
    if not token:
        return
    await db.execute(
        update(Session)
        .where(Session.token_hash == hash_session_token(token), Session.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


async def revoke_all_sessions(db: AsyncSession, user_id: int) -> None:
    """Sign a user out everywhere — used after a password change."""
    await db.execute(
        update(Session)
        .where(Session.user_id == user_id, Session.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


async def purge_expired_sessions(db: AsyncSession, older_than_days: int = 30) -> int:
    """Delete long-dead session rows. Run from the scheduler."""
    cutoff = utcnow() - timedelta(days=older_than_days)
    result = await db.execute(delete(Session).where(Session.expires_at < cutoff))
    return result.rowcount or 0


async def change_password(db: AsyncSession, user: User, current: str, new: str) -> None:
    """Change a password and invalidate every other session."""
    if not verify_password(current, user.password_hash):
        raise InvalidCredentials("Your current password is incorrect.")
    if problem := check_password_strength(new):
        raise WeakPassword(problem)

    user.password_hash = hash_password(new)
    await revoke_all_sessions(db, user.id)
    log.info("auth.password_changed", user_id=user.id)
