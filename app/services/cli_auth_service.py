"""`weedout auth`: getting a credential onto a laptop without pasting one.

The thing this replaces is worse than it looks. "Create a key in Settings, copy
it, paste it into your terminal" puts a live credential through a clipboard, a
terminal scrollback, a shell history, and — often enough — a chat window where
somebody asked a colleague for help. Every one of those outlives the moment.

So the CLI never sees a token it did not ask for, and the person never sees one
at all. The CLI starts a request, prints a short code and a URL, and waits. The
person opens the URL in a browser where they are already signed in, checks that
the code matches what their terminal is showing, and approves. The token then
travels from the server to the process that started the request, over the same
TLS connection the poll came in on.

This is RFC 8628's device flow in shape, and the properties that make it safe
are the ones worth stating out loud, because each of them is a way it could be
built wrong:

**Two secrets, doing different jobs.** The user code is short — a person reads
it — so it is guessable, and it is therefore *only* able to confirm a request
that already exists. The device code is 256 bits, held only by the waiting
process, and is what the poll authenticates with. Knowing the code someone read
over your shoulder does not let you collect their token.

**Approval is authenticated and CSRF-protected.** It happens on the internal
API with a session cookie, so approving is something a signed-in person does
deliberately, not something a link can do to them.

**Single use, in both directions.** A request can be approved once and
collected once. A device code replayed after collection gets nothing.

**Rate limited at both ends.** Starting requests, so the table cannot be filled
and the user-code space cannot be swept; and polling, so a client that ignores
the interval does not become a load problem.

**It expires.** Ten minutes, which is the honest window: long enough to switch
to a browser, sign in if you were not already, read the code and click; short
enough that an abandoned terminal does not leave a pending approval sitting
there all afternoon. A tighter window would mostly produce failed logins, and a
login flow people have to retry is a login flow people work around.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.models import CliAuthRequest, CliToken, User, utcnow
from app.security import (
    API_KEY_DISPLAY_CHARS,
    SESSION_TOKEN_BYTES,
    hash_opaque_token,
)

log = get_logger(__name__)

__all__ = [
    "APPROVAL_WINDOW",
    "MAX_TOKENS_PER_ACCOUNT",
    "POLL_INTERVAL_SECONDS",
    "TOKEN_LIFETIME",
    "AuthOutcome",
    "CliAuthError",
    "StartedRequest",
    "approve",
    "authenticate_cli_token",
    "collect",
    "deny",
    "find_pending",
    "list_tokens",
    "purge_expired_auth_requests",
    "revoke_token",
    "start_request",
]

#: How long a person has to open a browser and approve. See the module
#: docstring for why this is ten minutes and not thirty seconds.
APPROVAL_WINDOW = timedelta(minutes=10)

#: What the CLI is told to wait between polls. Long enough that a forgotten
#: terminal is not a load problem, short enough that approving feels immediate.
POLL_INTERVAL_SECONDS = 3

#: How long the resulting credential lasts. A developer machine credential that
#: never expires is one that outlives the laptop it was issued to.
TOKEN_LIFETIME = timedelta(days=180)

#: Enough for a laptop, a desktop and a spare. Past that it is more likely a
#: script in a loop than a person with many machines, and the list stops being
#: something anybody can audit.
MAX_TOKENS_PER_ACCOUNT = 10

#: The alphabet a person reads off a terminal and types into a browser.
#:
#: No 0/O, no 1/I/L, no 5/S, no 2/Z. Every pair that gets misread in a
#: sans-serif font at a glance is down to one member. 28 characters, so two
#: groups of four is a little over 38 bits -- comfortably beyond guessing at
#: the rate the limiter allows, and still short enough to say out loud.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRTUVWXY34679"

#: Prefix on the resulting credential, distinct from `wo_` so a leaked token is
#: identifiable as an account credential rather than a project key -- by us, and
#: by a secret scanner.
CLI_TOKEN_PREFIX = "woa_"  # noqa: S105 -- a display prefix, not a secret


class CliAuthError(Exception):
    """Something a person did, phrased for the person who did it."""


@dataclass(frozen=True, slots=True)
class StartedRequest:
    """What the CLI is told when it asks to be authorised."""

    user_code: str
    #: The 256-bit secret. Returned once, held only by the waiting process.
    device_code: str
    expires_in: int
    interval: int


@dataclass(frozen=True, slots=True)
class AuthOutcome:
    """The answer to one poll.

    `state` is what the CLI branches on, and the four values are deliberately
    distinguishable: waiting, refused, expired and done all mean different
    things to the person watching a terminal.
    """

    state: str  # "pending" | "approved" | "denied" | "expired"
    token: str | None = None
    email: str | None = None


def generate_user_code() -> str:
    """Two groups of four, hyphenated: `HXKR-2FQP`."""
    body = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(8))
    return f"{body[:4]}-{body[4:]}"


def normalise_user_code(raw: str) -> str:
    """What somebody typed, turned into what is stored.

    Case, spaces and a missing hyphen are all things a person does when copying
    eight characters between two windows. None of them should be a failed
    login.
    """
    cleaned = "".join(char for char in raw.upper() if char.isalnum())
    return f"{cleaned[:4]}-{cleaned[4:8]}" if len(cleaned) == 8 else cleaned


def generate_device_code() -> str:
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def generate_cli_token() -> str:
    return f"{CLI_TOKEN_PREFIX}{secrets.token_urlsafe(SESSION_TOKEN_BYTES)}"


async def start_request(
    db: AsyncSession,
    *,
    device_label: str = "",
    ip_address: str | None = None,
) -> StartedRequest:
    """Begin a confirmation. Unauthenticated: nobody has a credential yet.

    That is the whole point, and it is also why this endpoint is rate limited
    by the caller: an unauthenticated endpoint that writes a row is an
    unauthenticated endpoint somebody will try to fill a table with.
    """
    user_code = await _unused_code(db)
    device_code = generate_device_code()

    request = CliAuthRequest(
        user_code=user_code,
        device_code_hash=hash_opaque_token(device_code),
        device_label=device_label.strip()[:120],
        ip_address=(ip_address or "")[:64] or None,
        expires_at=utcnow() + APPROVAL_WINDOW,
    )
    db.add(request)
    await db.flush()

    # The code is not logged. It is short enough to be worth guessing, and a
    # log line is one more place it exists.
    log.info("cli_auth.started", request_id=request.id, device=request.device_label)

    return StartedRequest(
        user_code=user_code,
        device_code=device_code,
        expires_in=int(APPROVAL_WINDOW.total_seconds()),
        interval=POLL_INTERVAL_SECONDS,
    )


async def find_pending(db: AsyncSession, user_code: str) -> CliAuthRequest | None:
    """The request a person is about to look at, if it is still live.

    Returns None for expired, already-approved and already-denied alike. The
    page says "that code is no longer valid" for all three rather than
    distinguishing them, because the distinctions are only useful to somebody
    sweeping the code space.
    """
    code = normalise_user_code(user_code)
    if not code:
        return None

    request = await db.scalar(select(CliAuthRequest).where(CliAuthRequest.user_code == code))
    return request if request is not None and request.is_pending else None


async def approve(db: AsyncSession, request: CliAuthRequest, user: User) -> None:
    """A signed-in person says yes.

    The token is not minted here. It is minted when the waiting process
    collects it, so a credential never exists between the browser and the
    machine that asked for one -- and an approval nobody collects leaves
    nothing behind to revoke.
    """
    if not request.is_pending:
        raise CliAuthError("That request is no longer waiting for approval.")

    request.approved_by_user_id = user.id
    request.approved_at = utcnow()
    await db.flush()

    log.info("cli_auth.approved", request_id=request.id, user_id=user.id)


async def deny(db: AsyncSession, request: CliAuthRequest) -> None:
    """A signed-in person says no.

    Recorded distinctly from expiry so the waiting terminal can stop straight
    away and say it was refused. Somebody who denies a request they did not
    make should see it die, not watch it time out.
    """
    if not request.is_pending:
        raise CliAuthError("That request is no longer waiting for approval.")

    request.denied_at = utcnow()
    await db.flush()

    log.info("cli_auth.denied", request_id=request.id)


async def collect(db: AsyncSession, device_code: str) -> AuthOutcome:
    """The poll. Returns the token exactly once, to the process that asked.

    Authenticated by the device code alone, which is the only credential the
    waiting process has -- so it must be the 256-bit one, never the code a
    person read aloud.
    """
    request = await db.scalar(
        select(CliAuthRequest).where(
            CliAuthRequest.device_code_hash == hash_opaque_token(device_code)
        )
    )
    if request is None:
        # Indistinguishable from expiry on purpose. A caller probing device
        # codes learns nothing from the difference.
        return AuthOutcome(state="expired")

    if request.denied_at is not None:
        return AuthOutcome(state="denied")

    if request.collected_at is not None or request.expires_at <= utcnow():
        # Already collected counts as expired. A device code that could be
        # replayed would mint a second credential from one approval.
        return AuthOutcome(state="expired")

    if request.approved_at is None or request.approved_by_user_id is None:
        return AuthOutcome(state="pending")

    owner = await db.get(User, request.approved_by_user_id)
    if owner is None:
        # The account went away between approving and collecting. Nothing to
        # issue against.
        return AuthOutcome(state="expired")

    token = await _issue_token(db, owner, device_label=request.device_label)
    request.collected_at = utcnow()
    await db.flush()

    log.info("cli_auth.collected", request_id=request.id, user_id=owner.id)
    return AuthOutcome(state="approved", token=token, email=owner.email)


async def authenticate_cli_token(db: AsyncSession, token: str) -> CliToken | None:
    """Resolve a bearer token to the account credential it names, or None.

    Deliberately does not fall back to `ApiKey`. A project key must never
    authenticate an account-level operation, and the way to guarantee that is
    for the lookup to be unable to find one.
    """
    cleaned = (token or "").strip()
    if not cleaned.startswith(CLI_TOKEN_PREFIX):
        # Cheap rejection before touching the database, and it keeps project
        # keys out of this code path entirely.
        return None

    row = await db.scalar(select(CliToken).where(CliToken.token_hash == hash_opaque_token(cleaned)))
    if row is None or not row.is_active:
        return None

    # Throttled the same way `ApiKey.last_used_at` is: knowing it was used
    # today is worth a write, knowing the exact second is not.
    now = utcnow()
    if row.last_used_at is None or (now - row.last_used_at) > timedelta(minutes=1):
        row.last_used_at = now

    return row


async def list_tokens(db: AsyncSession, user_id: int) -> list[CliToken]:
    rows = await db.scalars(
        select(CliToken)
        .where(CliToken.user_id == user_id, CliToken.revoked_at.is_(None))
        .order_by(CliToken.created_at.desc())
    )
    return [row for row in rows.all() if row.is_active]


async def revoke_token(db: AsyncSession, user_id: int, token_id: int) -> bool:
    row = await db.get(CliToken, token_id)
    if row is None or row.user_id != user_id or row.revoked_at is not None:
        return False

    row.revoked_at = utcnow()
    await db.flush()
    log.info("cli_auth.revoked", user_id=user_id, token_id=token_id)
    return True


async def purge_expired_auth_requests(db: AsyncSession) -> int:
    """Remove requests nobody completed.

    They are useless once expired, and leaving them makes the user-code space
    smaller than it looks: `_unused_code` has to avoid colliding with rows that
    can never be used again.
    """
    result = await db.execute(
        delete(CliAuthRequest).where(CliAuthRequest.expires_at < utcnow() - timedelta(days=1))
    )
    return result.rowcount or 0


async def _issue_token(db: AsyncSession, owner: User, *, device_label: str) -> str:
    """Mint the credential, evicting the oldest if the account is at the cap.

    Evicting rather than refusing: somebody re-authorising a machine they have
    used before should not have to go and clean up first, and a login that
    fails with "you have too many logins" is a login people work around.
    """
    existing = await list_tokens(db, owner.id)
    for stale in existing[MAX_TOKENS_PER_ACCOUNT - 1 :]:
        stale.revoked_at = utcnow()
        log.info("cli_auth.evicted", user_id=owner.id, token_id=stale.id)

    token = generate_cli_token()
    db.add(
        CliToken(
            user_id=owner.id,
            token_hash=hash_opaque_token(token),
            prefix=token[:API_KEY_DISPLAY_CHARS],
            device_label=device_label,
            expires_at=utcnow() + TOKEN_LIFETIME,
        )
    )
    await db.flush()
    return token


async def _unused_code(db: AsyncSession, attempts: int = 5) -> str:
    """A code no live request is using.

    Collisions are vanishingly unlikely at 38 bits with a ten-minute window,
    but a collision would hand one person's approval page to another person's
    request, so it is checked rather than assumed.
    """
    for _ in range(attempts):
        candidate = generate_user_code()
        clash = await db.scalar(
            select(CliAuthRequest.id).where(CliAuthRequest.user_code == candidate)
        )
        if clash is None:
            return candidate

    raise CliAuthError("Could not start a login just now. Try again in a moment.")
