"""Two-factor authentication: setup, confirmation, verification, removal.

The flow is deliberately two-phase. `begin_setup` writes a secret but leaves
`totp_confirmed_at` unset, so 2FA is not yet in force; `confirm_setup` only
turns it on once the user has produced a working code from the app they just
configured. Someone who scans a QR, closes the tab and comes back later is not
locked out of their own account, which is the failure mode a one-phase setup
has.

Codes are single-use within their step. `verify_code` records the counter it
accepted and refuses anything at or below it, so a code captured from a
shoulder, a screen share or a proxy log cannot be replayed for the remainder of
its thirty seconds.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import totp
from app.logging_config import get_logger
from app.models import BackupCode, User, utcnow

log = get_logger(__name__)

#: What appears in the authenticator app's list.
ISSUER = "Weedout"


class TwoFactorError(RuntimeError):
    """Something the user can read and act on."""


@dataclass(slots=True)
class SetupOffer:
    """Everything the setup screen needs, and nothing that outlives it."""

    secret: str
    uri: str


@dataclass(slots=True)
class BackupCodeSet:
    """Freshly generated recovery codes, in plaintext, exactly once."""

    codes: list[str]


async def begin_setup(db: AsyncSession, user: User) -> SetupOffer:
    """Generate (or regenerate) an unconfirmed secret for this account."""
    if user.two_factor_enabled:
        raise TwoFactorError("Two-factor authentication is already on for this account.")

    secret = totp.generate_secret()
    user.totp_secret = secret
    user.totp_confirmed_at = None
    user.totp_last_counter = None

    log.info("twofactor.setup_started", user_id=user.id)
    return SetupOffer(
        secret=secret,
        uri=totp.provisioning_uri(secret, account=user.email, issuer=ISSUER),
    )


async def confirm_setup(db: AsyncSession, user: User, code: str) -> BackupCodeSet:
    """Turn 2FA on, once the user proves the app is configured."""
    if user.two_factor_enabled:
        raise TwoFactorError("Two-factor authentication is already on for this account.")
    if not user.totp_secret:
        raise TwoFactorError("Start the setup again — there's no pending secret to confirm.")

    counter = totp.verify(user.totp_secret, code)
    if counter is None:
        raise TwoFactorError("That code isn't right. Check the app and try the current code.")

    user.totp_confirmed_at = utcnow()
    user.totp_last_counter = counter

    codes = await regenerate_backup_codes(db, user)
    log.info("twofactor.enabled", user_id=user.id)
    return codes


async def regenerate_backup_codes(db: AsyncSession, user: User) -> BackupCodeSet:
    """Replace every recovery code with a fresh set.

    Old codes are deleted rather than kept alongside: the point of regenerating
    is usually that the previous list is no longer trusted.
    """
    existing = (await db.scalars(select(BackupCode).where(BackupCode.user_id == user.id))).all()
    for row in existing:
        await db.delete(row)

    plaintext = [totp.generate_backup_code() for _ in range(totp.BACKUP_CODE_COUNT)]
    for code in plaintext:
        db.add(BackupCode(user_id=user.id, code_hash=totp.hash_backup_code(code)))

    log.info("twofactor.backup_codes_issued", user_id=user.id, count=len(plaintext))
    return BackupCodeSet(codes=plaintext)


async def verify_code(db: AsyncSession, user: User, code: str) -> bool:
    """Accept a TOTP code or a recovery code. Either one, once.

    Tried in that order because a six-digit numeric string cannot collide with
    the recovery-code alphabet, so there is no ambiguity about what was meant.
    """
    if not user.two_factor_enabled or not user.totp_secret:
        return False

    counter = totp.verify(user.totp_secret, code)
    if counter is not None:
        # Replay guard: a code is valid for its whole step, so accepting the
        # same counter twice would let a captured code back in.
        if user.totp_last_counter is not None and counter <= user.totp_last_counter:
            log.warning("twofactor.code_replayed", user_id=user.id)
            return False
        user.totp_last_counter = counter
        return True

    return await _consume_backup_code(db, user, code)


async def _consume_backup_code(db: AsyncSession, user: User, code: str) -> bool:
    normalised = totp.normalise_backup_code(code)
    if not normalised:
        return False

    row = await db.scalar(
        select(BackupCode).where(
            BackupCode.user_id == user.id,
            BackupCode.code_hash == totp.hash_backup_code(normalised),
            BackupCode.used_at.is_(None),
        )
    )
    if row is None:
        return False

    row.used_at = utcnow()
    log.info("twofactor.backup_code_used", user_id=user.id)
    return True


async def disable(db: AsyncSession, user: User) -> None:
    """Turn 2FA off and destroy everything that made it work."""
    user.totp_secret = None
    user.totp_confirmed_at = None
    user.totp_last_counter = None

    for row in (await db.scalars(select(BackupCode).where(BackupCode.user_id == user.id))).all():
        await db.delete(row)

    log.info("twofactor.disabled", user_id=user.id)


async def backup_code_status(db: AsyncSession, user: User) -> tuple[int, int]:
    """(unused, total) recovery codes, for the Settings page."""
    rows = (await db.scalars(select(BackupCode).where(BackupCode.user_id == user.id))).all()
    return sum(1 for r in rows if not r.is_used), len(rows)


def qr_svg(uri: str) -> str:
    """An inline SVG QR for a provisioning URI.

    Inline rather than an <img src>: the CSP allows no external images, and a
    data: URI in markup would still be a second thing to get past it. The SVG
    is generated with no XML declaration or doctype so it can be dropped
    straight into the page.
    """
    import io

    import segno

    # segno writes bytes even for SVG, so this is a BytesIO decoded afterwards
    # rather than a StringIO.
    buffer = io.BytesIO()
    segno.make(uri, error="m").save(
        buffer,
        kind="svg",
        xmldecl=False,
        svgns=True,
        # No width/height attributes: the size comes from CSS, so the QR scales
        # with the layout instead of being fixed at whatever segno picked.
        omitsize=True,
        dark="#000000",
        light=None,
        border=2,
    )
    return buffer.getvalue().decode("utf-8")
