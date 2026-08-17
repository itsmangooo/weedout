"""Email delivery.

Three interchangeable backends behind one function:

* ``console`` — logs the message. The local default, so development needs no
  mail server and no test message can escape to a real address.
* ``smtp``    — any SMTP submission service.
* ``resend``  — Resend's HTTP API, for environments where outbound SMTP is blocked.

`send_email` raises `EmailError` on failure. Callers record the failure against
the `Alert` row rather than losing it, so a bounced notification is visible
instead of silently absent.
"""

from __future__ import annotations

from email.message import EmailMessage
from email.utils import formataddr, parseaddr

import aiosmtplib
import httpx

from app.config import Settings, get_settings
from app.logging_config import get_logger

log = get_logger(__name__)

__all__ = ["EmailError", "send_email"]


class EmailError(RuntimeError):
    """The message could not be handed off for delivery."""


def _build_message(
    settings: Settings, to: str, subject: str, text: str, html: str | None
) -> EmailMessage:
    message = EmailMessage()
    name, address = parseaddr(settings.email_from)
    message["From"] = formataddr((name, address)) if name else address
    message["To"] = to
    message["Subject"] = subject
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    return message


async def send_email(
    to: str,
    subject: str,
    text: str,
    html: str | None = None,
    settings: Settings | None = None,
) -> None:
    settings = settings or get_settings()

    if not to or "@" not in to:
        raise EmailError(f"invalid recipient address: {to!r}")

    backend = settings.email_backend
    try:
        if backend == "console":
            await _send_console(to, subject, text)
        elif backend == "smtp":
            await _send_smtp(settings, to, subject, text, html)
        elif backend == "resend":
            await _send_resend(settings, to, subject, text, html)
        else:  # pragma: no cover - guarded by the settings validator
            raise EmailError(f"unknown email backend: {backend}")
    except EmailError:
        raise
    except Exception as exc:
        raise EmailError(f"{backend} delivery failed: {exc}") from exc


async def _send_console(to: str, subject: str, text: str) -> None:
    log.info("email.console", to=to, subject=subject, body=text)


async def _send_smtp(
    settings: Settings, to: str, subject: str, text: str, html: str | None
) -> None:
    message = _build_message(settings, to, subject, text, html)

    try:
        await aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username or None,
            password=settings.smtp_password or None,
            start_tls=settings.smtp_use_tls and not settings.smtp_use_ssl,
            use_tls=settings.smtp_use_ssl,
            timeout=30,
        )
    except aiosmtplib.SMTPException as exc:
        raise EmailError(f"SMTP delivery failed: {exc}") from exc

    log.info("email.sent", backend="smtp", to=to, subject=subject)


async def _send_resend(
    settings: Settings, to: str, subject: str, text: str, html: str | None
) -> None:
    payload: dict[str, object] = {
        "from": settings.email_from,
        "to": [to],
        "subject": subject,
        "text": text,
    }
    if html:
        payload["html"] = html

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            settings.resend_api_url,
            json=payload,
            headers={"Authorization": f"Bearer {settings.resend_api_key}"},
        )

    if response.status_code >= 400:
        raise EmailError(f"Resend returned HTTP {response.status_code}: {response.text[:300]}")

    log.info("email.sent", backend="resend", to=to, subject=subject)
