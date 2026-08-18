"""Creating the first administrator on a fresh deployment.

A brand-new deployment has no way in: `/admin` needs an `is_admin` account, and
there is deliberately no "become admin" page — privilege escalation should
require shell access, not a browser. That leaves a chicken-and-egg problem the
first time the stack comes up somewhere nobody has an account yet.

This closes it once, and only once. Three outcomes:

* **An administrator already exists** — do nothing. Never regenerate a password,
  never re-send anything. This is the overwhelmingly common case, because it is
  true on every deploy after the first.
* **`ADMIN_EMAIL` exists but is not an admin** — promote it. No password is
  touched: that account's owner already has one.
* **Neither exists** — create the account with a generated password, store only
  its Argon2 hash, and mail the plaintext once to the operator.

The password is never written to a log. That constraint is what shapes the rest
of this module, and it is why `EMAIL_BACKEND=console` is refused outright: that
backend "delivers" by logging the message body, so using it here would put a
live admin credential into the log stream — where it is retained for months and
read by people who are not thinking about secrets.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.logging_config import get_logger
from app.mail import EmailError, send_email
from app.models import AdminAuditLog, User
from app.security import generate_password, hash_password
from app.services.auth_service import normalize_email

log = get_logger(__name__)

__all__ = ["BootstrapResult", "ensure_admin"]

#: Advisory lock key for the bootstrap.
#:
#: Two web containers starting at the same moment would otherwise both see "no
#: admin", both generate a password, and both send an email — leaving the
#: operator holding two credentials of which only one works. The unique index on
#: `users.email` would catch the duplicate insert, but only after the second
#: password had already been mailed.
#:
#: Same 64-bit namespace as the job locks in `app/jobs/tasks.py`, continuing the
#: sequence so the values cannot collide. Held here rather than imported,
#: because services must not depend on jobs.
LOCK_ADMIN_BOOTSTRAP = 0x4E4F495345_04


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    """What happened, in terms a caller can log without leaking anything."""

    action: str  # "created" | "promoted" | "noop" | "skipped" | "locked"
    email: str | None = None
    detail: str = ""

    @property
    def changed(self) -> bool:
        return self.action in ("created", "promoted")


async def _admin_exists(db: AsyncSession) -> bool:
    count = await db.scalar(select(func.count(User.id)).where(User.is_admin.is_(True)))
    return bool(count)


def _preflight(settings: Settings) -> str | None:
    """Why bootstrap cannot run, or None if it can.

    Checked before anything is written, so a misconfiguration never leaves a
    half-made admin account behind.
    """
    if not settings.admin_email:
        return "ADMIN_EMAIL is not set"

    if not settings.admin_bootstrap_notify_email:
        return (
            "ADMIN_BOOTSTRAP_NOTIFY_EMAIL is not set; refusing to generate a password "
            "with nowhere safe to send it"
        )

    if settings.email_backend == "console":
        # The console backend writes the message body to the log. Sending a
        # plaintext admin password through it would be the exact thing this
        # module promises not to do.
        return (
            "EMAIL_BACKEND=console would log the generated password. Configure smtp "
            "or resend, or create the admin manually with "
            "`python -m app.manage promote-admin <email>`"
        )

    return None


async def ensure_admin(db: AsyncSession, settings: Settings | None = None) -> BootstrapResult:
    """Make sure exactly one administrator exists. Idempotent.

    Takes a Postgres advisory lock for the duration, so concurrent deploys and
    restart loops cannot both create one. Commits nothing — the caller owns the
    transaction, which is what lets a failed email roll the whole thing back.
    """
    settings = settings or get_settings()

    # The cheap check first, and without the lock: on every deploy after the
    # first this is the only query that runs.
    if await _admin_exists(db):
        return BootstrapResult(action="noop", detail="an administrator already exists")

    reason = _preflight(settings)
    if reason:
        return BootstrapResult(action="skipped", detail=reason)

    acquired = bool(
        await db.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK_ADMIN_BOOTSTRAP})
    )
    if not acquired:
        # Another process is doing it right now. Declining is correct: it will
        # finish, and this process has nothing to add.
        return BootstrapResult(action="locked", detail="another process holds the lock")

    try:
        # Re-check under the lock. The window between the first check and
        # acquiring the lock is exactly where a racing process would have
        # created one.
        if await _admin_exists(db):
            return BootstrapResult(action="noop", detail="created by a concurrent process")

        email = normalize_email(settings.admin_email or "")
        existing = await db.scalar(select(User).where(User.email == email))

        if existing is not None:
            return await _promote(db, existing)

        return await _create(db, settings, email)
    finally:
        await db.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK_ADMIN_BOOTSTRAP})


async def _promote(db: AsyncSession, user: User) -> BootstrapResult:
    """Grant admin to an account that already exists.

    No password is generated or sent. Somebody already owns this account and
    knows how to get into it; replacing their password because the deployment
    happened to need an admin would be a lockout, not a bootstrap.
    """
    user.is_admin = True
    db.add(
        AdminAuditLog(
            actor_user_id=user.id,
            actor_email=user.email,
            action="admin.promoted",
            target_user_id=user.id,
            target_email=user.email,
            details={"source": "bootstrap", "reason": "matched ADMIN_EMAIL"},
        )
    )
    await db.flush()

    log.info("bootstrap.admin_promoted", user_id=user.id)
    return BootstrapResult(
        action="promoted",
        email=user.email,
        detail="existing account matching ADMIN_EMAIL was promoted; password unchanged",
    )


async def _create(db: AsyncSession, settings: Settings, email: str) -> BootstrapResult:
    """Create the first administrator and mail its password once.

    Order matters. The row is flushed but *not* committed before the email is
    attempted, so a delivery failure rolls the account back and the next deploy
    retries cleanly. The alternative — commit, then send — can leave an admin
    account whose password nobody will ever know, which is unrecoverable
    without a shell.
    """
    password = generate_password()

    user = User(
        email=email,
        password_hash=hash_password(password),
        is_admin=True,
        email_alerts_enabled=True,
    )
    db.add(user)

    try:
        await db.flush()
    except IntegrityError as exc:
        # The unique index on email is the backstop behind the advisory lock.
        await db.rollback()
        log.warning("bootstrap.admin_race_lost", error=str(exc))
        return BootstrapResult(action="noop", detail="another process created it first")

    db.add(
        AdminAuditLog(
            actor_user_id=user.id,
            actor_email=user.email,
            action="admin.bootstrapped",
            target_user_id=user.id,
            target_email=user.email,
            # No password, and no hash either: an audit row is not the place for
            # either half of a credential.
            details={
                "source": "bootstrap",
                "notified": settings.admin_bootstrap_notify_email,
            },
        )
    )
    await db.flush()

    notify_to = settings.admin_bootstrap_notify_email or ""
    try:
        await send_email(
            to=notify_to,
            subject="Weedout: your administrator account",
            text=_render_email(email, password, settings),
            settings=settings,
        )
    except EmailError as exc:
        # Roll back the account rather than keep one nobody can sign into. The
        # error text is logged; the password is not, and it is discarded here
        # along with the row.
        await db.rollback()
        log.error("bootstrap.email_failed", error=str(exc))
        return BootstrapResult(
            action="skipped",
            detail=f"could not deliver the password ({exc}); no account was created",
        )

    # Logged without the password, and without the recipient's mailbox contents.
    log.info("bootstrap.admin_created", user_id=user.id, notified=notify_to)
    return BootstrapResult(
        action="created",
        email=email,
        detail=f"password sent to {notify_to}",
    )


def _render_email(admin_email: str, password: str, settings: Settings) -> str:
    """The one and only place the plaintext password appears."""
    return "\n".join(
        [
            "A Weedout administrator account has been created for this deployment.",
            "",
            f"    Sign in at:  {settings.base_url}/login",
            f"    Email:       {admin_email}",
            f"    Password:    {password}",
            "",
            "This password was generated during deployment and is being sent once.",
            "It is not stored anywhere in readable form and cannot be shown again.",
            "",
            "Change it as soon as you have signed in:",
            f"    {settings.base_url}/settings",
            "",
            "If you did not deploy Weedout, someone else has administrative access",
            "to this instance. Sign in, change the password, and review",
            f"    {settings.base_url}/admin",
            "",
            "-- Weedout",
        ]
    )
