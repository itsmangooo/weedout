"""Posting to a Discord webhook.

The URL is validated by `app.core.discord.parse_webhook_url` before anything
here runs, and validated *again* on the way out. Checking at the boundary is
not enough on its own: the value has been sitting in a database in between, and
a row can be changed by a path that did not go through the form.

Nothing here raises at the caller. A webhook that fails is a webhook that
failed -- it must not take down the scan that produced the finding, and it must
not stop the email that carries the same news.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.config import Settings
from app.core.discord import parse_webhook_url
from app.core.webhooks import InvalidWebhookURL, WebhookKind, validate_custom_url
from app.logging_config import get_logger

log = get_logger(__name__)

__all__ = ["DeliveryResult", "post_webhook"]

#: Short. The caller is a scan loop with other projects waiting, and Discord
#: either answers quickly or is having an outage.
TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """What happened, in terms the caller can record and show.

    `permanent` is the field that matters. A 404 means the webhook was deleted
    in Discord and every future attempt will fail the same way, which is worth
    telling the user about on their settings page. A 503 means try later and
    saying anything at all would be noise.
    """

    ok: bool
    status: int | None = None
    error: str | None = None
    permanent: bool = False
    retry_after: float | None = None


#: Discord's answers, in the terms this module cares about. Anything not listed
#: is treated as transient, because guessing "permanent" wrongly means telling
#: somebody their integration is broken when it is not.
_PERMANENT = {
    400: "Discord rejected the message as malformed. This is a bug in Weedout, not in your setup.",
    401: "Discord rejected the webhook token. Create a new webhook and paste the new URL.",
    403: "Discord refused the post. Check the webhook still has access to that channel.",
    404: "That webhook no longer exists in Discord. It was probably deleted; create a new one.",
}


def _revalidate(url: str, kind: str) -> tuple[str, str]:
    """Check a stored URL again and return (url, an id safe to log).

    Re-validated on the way out, not just on the way in. Between the form and
    here the value has been through a database, and this is the last point at
    which an unexpected destination can be stopped. For a custom endpoint it is
    also the freshest DNS answer available, which is the narrowest the rebinding
    window can be made without pinning the address at connect time.
    """
    if kind == WebhookKind.CUSTOM:
        target = validate_custom_url(url)
        return target.url, target.host
    webhook = parse_webhook_url(url)
    return webhook.url, webhook.webhook_id


async def post_webhook(
    url: str,
    payload: dict,
    *,
    kind: str = WebhookKind.DISCORD,
    settings: Settings | None = None,
    client: httpx.AsyncClient | None = None,
) -> DeliveryResult:
    """Post one payload. Never raises."""
    # Accepted for symmetry with the other services and so a caller can pass a
    # test configuration; nothing in this function needs a setting today.
    _ = settings

    try:
        destination, safe_id = _revalidate(url, kind)
    except InvalidWebhookURL as exc:
        log.error("webhook.invalid_stored_url", kind=str(kind), reason=str(exc))
        return DeliveryResult(
            ok=False,
            error=f"The saved webhook URL is no longer usable: {exc}",
            permanent=True,
        )

    owned = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=TIMEOUT_SECONDS,
            # A redirect is how an allowlisted host becomes any host at all.
            follow_redirects=False,
        )

    try:
        response = await client.post(
            destination,
            json=payload,
            headers={"Content-Type": "application/json", "User-Agent": "weedout"},
        )
    except httpx.TimeoutException:
        return DeliveryResult(ok=False, error="Discord did not answer in time.")
    except httpx.HTTPError as exc:
        # The URL is never in the message: it is a credential, and this string
        # ends up in the database and on a page.
        return DeliveryResult(ok=False, error=f"Could not reach Discord: {type(exc).__name__}")
    finally:
        if owned:
            await client.aclose()

    status = response.status_code

    # Any 2xx. Discord documents 204; a custom endpoint might answer 200 or
    # 202, and guessing wrongly would report a delivered message as failed.
    if 200 <= status < 300:
        log.info("discord.sent", webhook_id=safe_id, status=status)
        return DeliveryResult(ok=True, status=status)

    if status == 429:
        retry_after = _retry_after(response)
        log.warning("discord.rate_limited", webhook_id=safe_id, retry=retry_after)
        return DeliveryResult(
            ok=False,
            status=status,
            error="Discord is rate limiting this webhook. The next scan will try again.",
            retry_after=retry_after,
        )

    if status in _PERMANENT:
        log.warning("webhook.rejected", webhook_id=safe_id, status=status)
        message = (
            _PERMANENT[status]
            if kind == WebhookKind.DISCORD
            else f"That endpoint answered {status} and rejected the message."
        )
        return DeliveryResult(ok=False, status=status, error=message, permanent=True)

    log.warning("discord.failed", webhook_id=safe_id, status=status)
    return DeliveryResult(
        ok=False,
        status=status,
        error=f"Discord answered {status}. The next scan will try again.",
    )


def _retry_after(response: httpx.Response) -> float | None:
    """Discord puts it in the body and in a header; either will do."""
    header = response.headers.get("retry-after")
    if header:
        try:
            return float(header)
        except ValueError:
            pass
    try:
        value = response.json().get("retry_after")
    except Exception:
        return None
    return float(value) if isinstance(value, int | float) else None
