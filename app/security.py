"""Password hashing, session tokens and webhook signature verification.

Design notes that matter:

* Passwords use Argon2id, with the verifier reporting whether the stored hash
  used outdated parameters so it can be transparently upgraded on login.
* Session tokens are 256 bits from `secrets.token_urlsafe`. The database stores
  only their SHA-256 hash — a plain lookup key, deliberately *not* a slow KDF,
  because the token is already high-entropy and it is checked on every request.
* Every comparison of a secret uses `hmac.compare_digest`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import time
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

__all__ = [
    "API_KEY_PREFIX",
    "api_key_prefix",
    "check_password_strength",
    "generate_api_key",
    "generate_reset_token",
    "generate_session_token",
    "hash_api_key",
    "hash_opaque_token",
    "hash_password",
    "hash_reset_token",
    "hash_session_token",
    "verify_dodo_signature",
    "verify_password",
]

# OWASP-recommended Argon2id baseline (19 MiB, 2 iterations, 1 lane).
_hasher = PasswordHasher(
    time_cost=2, memory_cost=19 * 1024, parallelism=1, hash_len=32, salt_len=16
)

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 1024  # bound the work an unauthenticated request can cause

SESSION_TOKEN_BYTES = 32


def hash_password(password: str) -> str:
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError("password exceeds maximum length")
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Check a password against its stored hash.

    A `None` hash (an OAuth-only account) still runs a dummy verification so
    that "no such user" and "wrong password" take indistinguishable time.
    """
    if len(password) > MAX_PASSWORD_LENGTH:
        return False
    if not password_hash:
        dummy_verify()
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def dummy_verify() -> None:
    """Burn roughly one hash's worth of time, to flatten the timing signal.

    Without this, an attacker can enumerate registered addresses by measuring
    how long a login attempt takes.
    """
    try:
        _hasher.verify(_DUMMY_HASH, "not-the-password")
    except Exception:  # noqa: S110 - only the elapsed time matters
        # Deliberately silent. This call exists to consume time; its result is
        # meaningless and always a mismatch. Logging it would emit a spurious
        # error on every failed login.
        pass


_DUMMY_HASH = _hasher.hash("weedout-timing-equalizer")


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def check_password_strength(password: str) -> str | None:
    """Return an error message, or None if acceptable.

    Deliberately minimal: a length floor catches the genuinely dangerous cases,
    while composition rules mostly push people toward `Password1!`.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return "Password is too long."
    if password.lower() in _COMMON_PASSWORDS:
        return "That password is too common. Please choose another."
    return None


_COMMON_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "12345678",
    "123456789",
    "1234567890",
    "qwertyuiop",
    "letmein123",
    "iloveyou1",
    "adminadmin",
    "welcome123",
    "changeme123",
}


def generate_session_token() -> str:
    """A fresh, unguessable session token (256 bits of entropy)."""
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def hash_opaque_token(token: str) -> str:
    """The database lookup key for a high-entropy bearer token.

    SHA-256 rather than a password KDF on purpose: the input is already 256
    random bits, so key stretching buys nothing against a brute-force attack
    that is already infeasible, and costs latency on every authenticated
    request. Passwords get Argon2 because they are low-entropy; these do not.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_session_token(token: str) -> str:
    """Lookup key for a session cookie token."""
    return hash_opaque_token(token)


def generate_reset_token() -> str:
    """A fresh, unguessable password-reset token (256 bits of entropy)."""
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def hash_reset_token(token: str) -> str:
    """Lookup key for a password-reset token.

    A distinct name from `hash_session_token` even though the algorithm is the
    same: the two token spaces must never be conflated, and a shared function
    name is how that mistake starts.
    """
    return hash_opaque_token(token)


#: Marks a string as a Weedout API key wherever it turns up — a CI log, a
#: committed `.weedout` file, a pasted snippet. Secret scanners key off exactly
#: this kind of fixed prefix, and a key that looks like anonymous base64 is one
#: nobody can flag on the way into a public repository.
API_KEY_PREFIX = "wo_"

#: Characters of the key kept in clear for display. Enough to tell two keys
#: apart in a list, far too few to guess the remaining 256 bits.
API_KEY_DISPLAY_CHARS = 8


def generate_api_key() -> str:
    """A fresh API key: a recognisable prefix plus 256 bits of entropy."""
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(SESSION_TOKEN_BYTES)}"


def hash_api_key(token: str) -> str:
    """Lookup key for an API key.

    Same construction as sessions and reset tokens, named separately because
    the three token spaces must never be confused for one another — sharing a
    function name is how a session token ends up accepted as an API key.
    """
    return hash_opaque_token(token.strip())


def api_key_prefix(token: str) -> str:
    """The display-only fragment stored alongside the hash."""
    return token.strip()[:API_KEY_DISPLAY_CHARS]


def session_expiry(hours: int) -> datetime:
    return datetime.now(UTC) + timedelta(hours=hours)


def content_hash(text: str) -> str:
    """Stable digest of manifest content, for change detection."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_dodo_signature(
    raw_body: bytes,
    webhook_id: str | None,
    webhook_timestamp: str | None,
    signature_header: str | None,
    secret: str,
    max_age_seconds: int = 5 * 60,
) -> bool:
    """Verify a Dodo Payments webhook, per the Standard Webhooks spec.

    Dodo signs with three headers:

        webhook-id:        msg_2abc...
        webhook-timestamp: 1717171717        (unix seconds)
        webhook-signature: v1,<base64>       (space-separated for key rotation)

    The signed content is ``{id}.{timestamp}.{body}`` and the key is the
    *base64-decoded* secret with its ``whsec_`` prefix stripped — decoding is
    part of the spec, and treating the printable form as the key produces a
    digest that never matches.

    The raw bytes must be used. Re-serialising parsed JSON changes whitespace
    and key order, and the signature is over the exact bytes sent.

    The timestamp is checked so a captured webhook cannot be replayed forever
    to, say, keep resetting a cancelled subscription back to active.
    """
    if not signature_header or not secret or not webhook_id or not webhook_timestamp:
        return False

    try:
        sent_at = int(webhook_timestamp.strip())
    except (ValueError, AttributeError):
        return False

    if abs(time.time() - sent_at) > max_age_seconds:
        return False

    key = _decode_webhook_secret(secret)
    if key is None:
        return False

    signed = b".".join(
        [webhook_id.encode("utf-8"), webhook_timestamp.strip().encode("utf-8"), raw_body]
    )
    expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()

    # The header may carry several space-separated versioned signatures while a
    # secret is being rotated; any valid v1 entry is enough.
    for part in signature_header.split():
        version, _, candidate = part.partition(",")
        if version != "v1" or not candidate:
            continue
        if hmac.compare_digest(expected, candidate):
            return True

    return False


def _decode_webhook_secret(secret: str) -> bytes | None:
    """Turn a `whsec_`-prefixed base64 secret into raw key bytes."""
    value = secret.strip()
    value = value.removeprefix("whsec_")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        # Some dashboards show the key already raw. Falling back to the literal
        # bytes keeps a correctly-configured deployment working rather than
        # failing every webhook with an opaque signature mismatch.
        return value.encode("utf-8") or None
