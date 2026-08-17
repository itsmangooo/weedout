"""Rate limiting for the endpoints an anonymous caller can reach.

Sign-in, sign-up and password-reset are the three routes that will be attacked,
because they are the only ones an unauthenticated stranger can drive. Sign-in
matters most: without a limit it is an open credential-stuffing target, and
because every attempt runs an Argon2id verification (19 MiB and real CPU by
design), it is also a memory-exhaustion lever pointed at the server. The check
therefore runs *before* the hash, so a rejected attempt costs a single indexed
count.

Counted in Postgres, not in process memory. The app can run as more than one
replica; an in-process counter would multiply every limit by the number of
processes and reset on every deploy — which is exactly when someone is most
likely to be probing.

Two design choices worth stating:

* **Only failures count for sign-in.** A legitimate user is never throttled by
  their own successful sign-ins, and an office behind a single NAT address is
  not collectively locked out because one person mistyped a password. Signup
  counts every attempt, because there the *success* is what is being abused.

* **Addresses are hashed into the bucket key.** A bucket of
  `login:account:<sha256>` is as useful for counting as the plaintext and does
  not turn this table into an enumerable list of who has an account here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.models import RateLimitHit, utcnow

log = get_logger(__name__)

__all__ = [
    "RateLimit",
    "check_rate_limit",
    "client_ip",
    "purge_expired_rate_limits",
    "record_attempt",
]

#: How long a hit stays countable at most. The sweep uses this to prune; it is
#: comfortably above every window configured in `Settings`.
MAX_RETENTION = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class RateLimit:
    """A decision, with enough context to explain it to the caller."""

    allowed: bool
    limit: int
    used: int
    retry_after_seconds: int

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


def _hash_identifier(value: str) -> str:
    """Stable, non-reversible key fragment for an email address or IP."""
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:32]


def bucket_for(action: str, kind: str, identifier: str) -> str:
    """Build the opaque bucket key for one actor and one action."""
    return f"{action}:{kind}:{_hash_identifier(identifier)}"


def client_ip(request, settings) -> str:
    """The client address to rate limit on.

    Behind a proxy the socket address is the proxy's, identical for every
    visitor, so a limit computed from it would be one global bucket — the first
    attacker would lock out the entire site. `trusted_client_ip_header` names
    the header that carries the real address (Cloudflare sets and overwrites
    `CF-Connecting-IP` at the edge, so a client cannot forge it).

    The header is consulted *only* when configured. Trusting one by default
    would let anyone spoof their way into a fresh bucket per request on a
    deployment that is not behind a proxy at all, which silently removes the
    limit rather than loosening it.

    Falls back to a constant when there is no address to be had, so an
    unidentifiable caller shares one bucket instead of escaping limits.
    """
    header = getattr(settings, "trusted_client_ip_header", None)
    if header:
        forwarded = request.headers.get(header)
        if forwarded:
            # A comma-separated chain can appear if the proxy appends rather
            # than replaces; the left-most entry is the originating client.
            candidate = forwarded.split(",")[0].strip()
            if candidate:
                return candidate

    if request.client and request.client.host:
        return request.client.host
    return "unknown"


async def check_rate_limit(
    db: AsyncSession, bucket: str, limit: int, window: timedelta
) -> RateLimit:
    """Has `bucket` used up its allowance? Records nothing.

    Separate from `record_attempt` on purpose: sign-in needs to check before
    doing the expensive work and record only if the attempt then fails, and one
    combined call could not express that.
    """
    if limit <= 0:
        return RateLimit(allowed=True, limit=limit, used=0, retry_after_seconds=0)

    since = utcnow() - window
    used = (
        await db.scalar(
            select(func.count(RateLimitHit.id)).where(
                RateLimitHit.bucket == bucket, RateLimitHit.created_at >= since
            )
        )
    ) or 0

    if used < limit:
        return RateLimit(allowed=True, limit=limit, used=used, retry_after_seconds=0)

    # Retry-After is measured from the oldest hit still inside the window: that
    # is the moment one slot frees up. Telling the caller to wait the full
    # window would be wrong for anyone who tripped the limit gradually.
    oldest = await db.scalar(
        select(func.min(RateLimitHit.created_at)).where(
            RateLimitHit.bucket == bucket, RateLimitHit.created_at >= since
        )
    )
    retry_after = int(window.total_seconds())
    if oldest is not None:
        retry_after = max(1, int((oldest + window - utcnow()).total_seconds()))

    return RateLimit(allowed=False, limit=limit, used=used, retry_after_seconds=retry_after)


async def record_attempt(db: AsyncSession, bucket: str) -> None:
    """Count one attempt against `bucket`.

    Never raises. Rate-limit bookkeeping failing is not a reason to fail the
    request the user actually made — but it *is* worth a warning, because a
    limiter that has quietly stopped recording is a limiter that has quietly
    stopped limiting.
    """
    try:
        db.add(RateLimitHit(bucket=bucket))
        await db.flush()
    except Exception as exc:
        log.warning("rate_limit.record_failed", error=str(exc))


async def purge_expired_rate_limits(db: AsyncSession) -> int:
    """Drop hits older than any window can reach. Returns rows removed."""
    result = await db.execute(
        delete(RateLimitHit).where(RateLimitHit.created_at < utcnow() - MAX_RETENTION)
    )
    return result.rowcount or 0
