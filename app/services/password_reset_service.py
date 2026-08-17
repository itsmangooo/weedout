"""Forgotten-password reset.

The whole flow is built around one rule: **an unauthenticated caller must learn
nothing about which addresses are registered.** `request_password_reset` never
raises, never varies its return value, and never tells the caller whether it
sent anything. The route renders the same page either way.

The token itself is treated as a bearer credential:

* 256 bits of entropy, generated with `secrets`.
* Only its SHA-256 hash is stored, so a database leak yields no working links.
* Single use — spent the moment it succeeds, before the response is sent.
* One hour to live.
* Using it revokes every session on the account and every other outstanding
  reset token, because "I forgot my password" and "someone else is in my
  account" are the same event often enough to assume the worse one.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.logging_config import get_logger
from app.mail import EmailError, send_email
from app.models import PasswordResetToken, User, utcnow
from app.security import (
    check_password_strength,
    generate_reset_token,
    hash_password,
    hash_reset_token,
)
from app.services.auth_service import WeakPassword, normalize_email, revoke_all_sessions

log = get_logger(__name__)

__all__ = [
    "InvalidResetToken",
    "complete_password_reset",
    "purge_expired_reset_tokens",
    "request_password_reset",
    "validate_reset_token",
]


class InvalidResetToken(Exception):
    """The token is unknown, expired, already used, or its account is unusable."""


async def request_password_reset(
    db: AsyncSession, email: str, ip_address: str | None = None
) -> None:
    """Send a reset link, if there is anything to send one to.

    Deliberately returns `None` in every case — success, unknown address,
    suspended account, throttled, or mail failure. Any return value or raised
    exception would become an oracle for whether an address is registered, and
    the caller has no legitimate use for the answer.
    """
    settings = get_settings()
    email = normalize_email(email)

    user = await db.scalar(select(User).where(User.email == email))

    if user is None:
        # Logged without the address so the audit trail does not become the
        # enumeration oracle the response refuses to be.
        log.info("password_reset.requested_unknown_address", domain=email.rsplit("@", 1)[-1])
        return

    if not user.can_sign_in:
        # A suspended account must not be resettable — that would hand back an
        # account an administrator deliberately closed.
        log.info("password_reset.requested_for_blocked_account", user_id=user.id)
        return

    recent = (
        await db.scalar(
            select(PasswordResetToken)
            .where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.created_at >= utcnow() - timedelta(hours=1),
            )
            .order_by(PasswordResetToken.created_at.desc())
            .offset(settings.password_reset_max_per_hour - 1)
            .limit(1)
        )
    ) is not None
    if recent:
        log.warning("password_reset.throttled", user_id=user.id)
        return

    token = generate_reset_token()
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hash_reset_token(token),
            expires_at=utcnow() + timedelta(minutes=settings.password_reset_ttl_minutes),
            requested_ip=(ip_address or "")[:64] or None,
        )
    )
    await db.flush()

    reset_url = f"{settings.base_url}/reset-password?token={token}"
    try:
        await send_email(
            to=user.email,
            subject="Reset your Weedout password",
            text=_render_email(reset_url, settings.password_reset_ttl_minutes),
            settings=settings,
        )
    except EmailError as exc:
        # The token stays valid; the user can request another. Surfacing this
        # to the caller would tell them the address exists.
        log.error("password_reset.email_failed", user_id=user.id, error=str(exc))
        return

    log.info("password_reset.email_sent", user_id=user.id)


def _render_email(reset_url: str, ttl_minutes: int) -> str:
    hours = ttl_minutes // 60
    window = f"{hours} hour{'s' if hours != 1 else ''}" if hours else f"{ttl_minutes} minutes"
    return "\n".join(
        [
            "Someone asked to reset the password for your Weedout account.",
            "",
            "To choose a new one, open this link:",
            "",
            f"  {reset_url}",
            "",
            f"The link works once and expires in {window}.",
            "",
            "If this wasn't you, you can ignore this email — your password has not",
            "changed and nobody can read this link but you. If you get these",
            "repeatedly, someone may know your email address; consider whether your",
            "password is used anywhere else.",
        ]
    )


async def validate_reset_token(db: AsyncSession, token: str) -> PasswordResetToken | None:
    """Look up a token and return it only if it is genuinely usable.

    Used by the GET handler to decide whether to render the form at all, so a
    dead link says so immediately rather than after the user has typed a new
    password twice.
    """
    if not token:
        return None

    record = await db.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_reset_token(token))
    )
    if record is None or not record.is_usable:
        return None

    user = await db.get(User, record.user_id)
    if user is None or not user.can_sign_in:
        return None

    return record


async def complete_password_reset(db: AsyncSession, token: str, new_password: str) -> User:
    """Spend the token and set the new password.

    Raises `InvalidResetToken` for anything unusable and `WeakPassword` for a
    password that fails the strength floor — the second only after the token
    has been proven good, so a bad password does not burn the link.

    The order matters: mark used, set password, then revoke. Every step is in
    the same transaction, so a failure anywhere leaves the token unspent rather
    than consumed-but-ineffective.
    """
    record = await validate_reset_token(db, token)
    if record is None:
        raise InvalidResetToken("That reset link is no longer valid.")

    if problem := check_password_strength(new_password):
        raise WeakPassword(problem)

    user = await db.get(User, record.user_id)
    if user is None:  # pragma: no cover - validate_reset_token already checked
        raise InvalidResetToken("That reset link is no longer valid.")

    now = utcnow()
    record.used_at = now
    user.password_hash = hash_password(new_password)

    # Flush explicitly: the session runs with autoflush off, so without this
    # the bulk UPDATE below would evaluate against a database that has not yet
    # seen this token being spent.
    await db.flush()

    # Any other outstanding link is now stale. Leaving them live would mean a
    # single reset request stays redeemable after the password has changed.
    await db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.id != record.id,
        )
        .values(used_at=now)
        # Explicit rather than relying on the default strategy: without it, a
        # token already loaded in this session keeps reporting `used_at = None`
        # in memory while the row says otherwise.
        .execution_options(synchronize_session="fetch")
    )

    # Sign out everywhere. Whoever knew the old password — including an
    # attacker who is the reason for the reset — loses their session.
    await revoke_all_sessions(db, user.id)

    log.info("password_reset.completed", user_id=user.id)
    return user


async def purge_expired_reset_tokens(db: AsyncSession, older_than_days: int = 7) -> int:
    """Delete long-dead reset tokens. Run from the scheduler."""
    cutoff = utcnow() - timedelta(days=older_than_days)
    result = await db.execute(
        delete(PasswordResetToken).where(PasswordResetToken.expires_at < cutoff)
    )
    return result.rowcount or 0
