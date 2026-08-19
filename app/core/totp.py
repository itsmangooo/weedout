"""Time-based one-time passwords (RFC 6238) and recovery codes.

Pure: no database, no settings, no framework. Everything here is a function of
its arguments and the clock, which is what makes the drift window and the
constant-time comparison testable without standing anything up.

TOTP is implemented directly rather than pulled in, because it is a HMAC, a
truncation and a modulo — about twenty lines against a spec that has not moved
since 2011. The parts that are actually easy to get wrong are the ones a
library would not save us from anyway: accepting a code twice, and comparing it
in variable time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

#: Seconds per step. 30 is the near-universal default and every authenticator
#: app assumes it; making it configurable would only create ways to be wrong.
STEP_SECONDS = 30

#: Digits in a generated code.
DIGITS = 6

#: How many steps either side of now are accepted. One step allows for a phone
#: clock that is up to 30 seconds out and for the code being typed as it
#: rolls over. Two would be a 90-second window, which is more replay surface
#: than the convenience is worth.
DRIFT_STEPS = 1

#: Base32 alphabet, minus padding. 32 characters = 160 bits, the length RFC
#: 4226 recommends for the shared secret.
SECRET_LENGTH = 32

_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def generate_secret() -> str:
    """A fresh base32 shared secret, safe to show to the user once."""
    return "".join(secrets.choice(_BASE32_ALPHABET) for _ in range(SECRET_LENGTH))


def _decode_secret(secret: str) -> bytes:
    """Base32-decode a secret, tolerating lowercase and missing padding.

    Users retype these by hand off a screen, so the input is normalised rather
    than rejected for cosmetic differences.
    """
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()
    padding = "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned + padding, casefold=True)
    except Exception as exc:
        raise ValueError("That is not a valid base32 secret.") from exc


def code_at(secret: str, counter: int) -> str:
    """The HOTP code for a given counter, zero-padded to DIGITS."""
    digest = hmac.new(_decode_secret(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    # Dynamic truncation, RFC 4226 §5.3: the low nibble of the last byte picks
    # the offset of the 4 bytes to read.
    offset = digest[-1] & 0x0F
    (chunk,) = struct.unpack(">I", digest[offset : offset + 4])
    return str((chunk & 0x7FFFFFFF) % (10**DIGITS)).zfill(DIGITS)


def current_code(secret: str, *, now: float | None = None) -> str:
    """The code an authenticator app is showing right now."""
    moment = time.time() if now is None else now
    return code_at(secret, int(moment // STEP_SECONDS))


def verify(secret: str, submitted: str, *, now: float | None = None) -> int | None:
    """Check a submitted code, returning the counter it matched.

    The counter comes back rather than a bare ``True`` so the caller can record
    it and refuse to accept the same code a second time: within a 30-second
    step a code is valid repeatedly, and a code shoulder-surfed or captured
    from a log would otherwise be replayable for the rest of that window.

    Comparison is constant-time. The loop deliberately does not break early —
    returning as soon as a step matches would leak, through timing, which step
    it was.
    """
    cleaned = "".join(ch for ch in (submitted or "") if ch.isdigit())
    if len(cleaned) != DIGITS:
        return None

    moment = time.time() if now is None else now
    step = int(moment // STEP_SECONDS)

    matched: int | None = None
    for offset in range(-DRIFT_STEPS, DRIFT_STEPS + 1):
        counter = step + offset
        if hmac.compare_digest(code_at(secret, counter), cleaned):
            matched = counter
    return matched


def provisioning_uri(secret: str, *, account: str, issuer: str) -> str:
    """The otpauth:// URI an authenticator app scans.

    Issuer appears both in the label and as a parameter: the label is what old
    apps read, the parameter is what current ones read, and they have to agree
    or the entry shows up twice.
    """
    label = quote(f"{issuer}:{account}", safe="")
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1"
        f"&digits={DIGITS}"
        f"&period={STEP_SECONDS}"
    )


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------

#: How many are issued at setup. Ten is enough to survive a lost phone and few
#: enough that people actually store them.
BACKUP_CODE_COUNT = 10

#: Unambiguous alphabet: no O/0, no I/1/L. These get copied off a screen by
#: hand at the worst possible moment.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def generate_backup_code() -> str:
    """One recovery code, formatted in two groups for legibility."""
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


def normalise_backup_code(code: str) -> str:
    """Strip formatting so a code entered without its dash still matches."""
    return "".join(ch for ch in (code or "").upper() if ch in _CODE_ALPHABET)


def hash_backup_code(code: str) -> str:
    """SHA-256 of the normalised code.

    A plain hash rather than Argon2: these are 10 random characters from a
    31-character alphabet, about 49 bits, generated by us and never chosen by a
    human. There is no dictionary to attack and no password reuse to protect,
    so the slow KDF buys nothing that the entropy has not already bought — the
    same reasoning the session and API-key tokens use.
    """
    return hashlib.sha256(normalise_backup_code(code).encode("utf-8")).hexdigest()
