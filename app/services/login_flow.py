"""The sign-in decision, independent of how it is presented.

Written because the same flow now has two front doors: the server-rendered
form and the JSON endpoint the React application posts to. Sign-in carries the
rate limiting that keeps an expensive password hash from being a
memory-exhaustion lever, the failures-only accounting that stops a shared
office address being collectively punished, and the second-factor branch. Two
copies of that would be two doors that drift, and the weaker one is the one an
attacker uses.

So the decision lives here and returns a value. The routes decide what a value
looks like -- a rendered page, a redirect, a JSON body -- and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING

import structlog
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.schemas import LoginForm, first_error
from app.services.auth_service import InvalidCredentials, authenticate, create_session
from app.services.rate_limit_service import (
    RateLimit,
    bucket_for,
    check_rate_limit,
    record_attempt,
)

if TYPE_CHECKING:
    from app.models import User

log = structlog.get_logger(__name__)


class LoginResult(StrEnum):
    """What happened, in the vocabulary of the caller rather than the store."""

    #: Credentials accepted and a session exists. `token` is set.
    SESSION = "session"
    #: Credentials accepted, but the account has a second factor. No session
    #: yet -- the caller issues a challenge and asks for a code.
    CHALLENGE = "challenge"
    #: Too many attempts. Nothing was verified, so no password was hashed.
    RATE_LIMITED = "rate_limited"
    #: Wrong email or password. Deliberately one outcome, not two.
    INVALID = "invalid"
    #: The submission was not usable as a login at all.
    MALFORMED = "malformed"


@dataclass(frozen=True)
class LoginOutcome:
    """The result of one sign-in attempt."""

    result: LoginResult
    #: Set for SESSION and CHALLENGE. Never serialised by a caller directly.
    user: User | None = None
    #: The session token, set only for SESSION.
    token: str | None = None
    #: Wording for whoever is reading, safe to show.
    message: str = ""
    #: Where the user asked to end up, validated by LoginForm.
    next: str = "/dashboard"
    #: Present on RATE_LIMITED, so a caller can send Retry-After.
    decision: RateLimit | None = None

    @property
    def succeeded(self) -> bool:
        return self.result is LoginResult.SESSION

    @property
    def status_code(self) -> int:
        """The HTTP status this outcome deserves.

        Kept here so the two front doors cannot disagree about it. A caller
        rendering HTML may ignore it; one returning JSON must not invent its
        own, because a React client branches on the number.
        """
        return {
            LoginResult.SESSION: 200,
            LoginResult.CHALLENGE: 200,
            LoginResult.RATE_LIMITED: 429,
            LoginResult.INVALID: 401,
            LoginResult.MALFORMED: 400,
        }[self.result]


async def attempt_login(
    db: AsyncSession,
    settings: Settings,
    *,
    email: str,
    password: str,
    next_path: str,
    client_ip: str,
    user_agent: str | None,
) -> LoginOutcome:
    """Try to sign somebody in, without deciding how to tell them.

    The order of operations is the security-relevant part and is the reason
    this function exists rather than being inlined twice:

    1. Rate limits are checked *before* the password is verified. Argon2id is
       deliberately expensive -- 19 MiB and real CPU per call -- so an
       unlimited endpoint is a memory-exhaustion lever as much as it is a
       credential-stuffing target. A rejected attempt must cost one indexed
       count, not one hash.
    2. Only failures are recorded, so somebody signing in successfully all day
       is never throttled by their own traffic, and one person's typo does not
       lock out everyone behind the same address.
    3. A correct password on a 2FA account is not a session. The caller issues
       a short-lived challenge instead, so a stolen one is worth only the
       remaining minutes of a code prompt.
    """
    window = timedelta(minutes=settings.login_rate_limit_window_minutes)
    ip_bucket = bucket_for("login", "ip", client_ip)
    account_bucket = bucket_for("login", "account", email)

    for bucket, limit in (
        (ip_bucket, settings.login_rate_limit_per_ip),
        (account_bucket, settings.login_rate_limit_per_account),
    ):
        decision = await check_rate_limit(db, bucket, limit, window)
        if not decision.allowed:
            log.warning("auth.login_rate_limited", used=decision.used, limit=decision.limit)
            return LoginOutcome(
                result=LoginResult.RATE_LIMITED,
                message="Too many sign-in attempts.",
                next=next_path,
                decision=decision,
            )

    try:
        form = LoginForm(email=email, password=password, next=next_path)
    except ValidationError as exc:
        return LoginOutcome(
            result=LoginResult.MALFORMED,
            message=first_error(exc),
            next=next_path,
        )

    try:
        user = await authenticate(db, form.email, form.password)
    except InvalidCredentials as exc:
        await record_attempt(db, ip_bucket)
        await record_attempt(db, account_bucket)
        await db.commit()

        log.info("auth.login_failed", email_domain=form.email.rsplit("@", 1)[-1])
        return LoginOutcome(
            result=LoginResult.INVALID,
            message=str(exc),
            next=form.next,
        )

    if user.two_factor_enabled:
        await db.commit()
        log.info("auth.login_awaiting_second_factor", user_id=user.id)
        return LoginOutcome(
            result=LoginResult.CHALLENGE,
            user=user,
            message="Enter the code from your authenticator app.",
            next=form.next,
        )

    token = await create_session(db, user, user_agent, client_ip)
    await db.commit()

    return LoginOutcome(
        result=LoginResult.SESSION,
        user=user,
        token=token,
        next=form.next,
    )
