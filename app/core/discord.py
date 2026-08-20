"""Discord webhook payloads, and the rule for what counts as one.

Two jobs, both pure, so both are testable without a network or a database.

**Validating the URL is the security control.** A webhook destination is a URL
the *user* supplies and the *server* then makes a request to, which is the
textbook shape of a server-side request forgery. The defence here is an
allowlist of Discord's own hosts rather than a blocklist of private ranges:
a blocklist has to anticipate every way of spelling "localhost" --
``127.1``, ``0x7f000001``, ``[::1]``, a hostname that resolves to a private
address only on the second lookup -- and a single miss turns this feature into
a request proxy pointed at our own network. An allowlist has to be right once.

**Building the payload** is the other half. Discord enforces hard limits and
answers a payload that exceeds them with a 400, so the limits are applied here
rather than discovered in production: a truncated alert is a delivered alert.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

__all__ = [
    "DISCORD_HOSTS",
    "InvalidWebhookURL",
    "Webhook",
    "build_digest_payload",
    "build_test_payload",
    "mask_webhook_url",
    "parse_webhook_url",
]

#: The only hosts a webhook may point at. `discordapp.com` is the legacy domain
#: and still serves live webhooks created years ago; `canary` and `ptb` are
#: Discord's own release channels, which people on those builds are given.
DISCORD_HOSTS = frozenset(
    {
        "discord.com",
        "discordapp.com",
        "canary.discord.com",
        "ptb.discord.com",
    }
)

#: /api/webhooks/{id}/{token}, optionally under an /api/vN prefix.
_PATH = re.compile(r"^/api(?:/v\d{1,2})?/webhooks/(\d{5,25})/([A-Za-z0-9_-]{20,120})/?$")

# Discord's documented limits. Exceeding one is a 400, not a truncation.
MAX_TITLE = 256
MAX_DESCRIPTION = 4096
MAX_FIELDS = 25
MAX_FIELD_VALUE = 1024
MAX_FOOTER = 2048

#: Embed colours. Deliberately the same three the interface uses, so an alert in
#: Discord and the same finding on the dashboard do not disagree about how bad
#: it is.
COLOUR_EXPLOITED = 0xD42D20
COLOUR_CRITICAL = 0xF65E7C
COLOUR_HIGH = 0xFFB224
COLOUR_CALM = 0x6D4DE8


class InvalidWebhookURL(ValueError):
    """The URL is not a Discord webhook. Carries a message for the user."""


@dataclass(frozen=True, slots=True)
class Webhook:
    """A validated webhook destination."""

    url: str
    webhook_id: str
    host: str

    @property
    def masked(self) -> str:
        return mask_webhook_url(self.url)


def parse_webhook_url(raw: str) -> Webhook:
    """Validate a webhook URL. Raises `InvalidWebhookURL` with a usable message.

    Everything about this is deliberately strict. The failure mode of being
    lenient is not a broken alert, it is an authenticated request to an address
    of the submitter's choosing, made from inside our network.
    """
    candidate = (raw or "").strip()
    if not candidate:
        raise InvalidWebhookURL("Paste the webhook URL from Discord.")

    # Reject anything with whitespace or control characters before parsing:
    # a newline in a URL is how request-splitting starts.
    if any(ch.isspace() or ord(ch) < 0x20 for ch in candidate):
        raise InvalidWebhookURL("That URL contains spaces or line breaks.")

    if len(candidate) > 300:
        raise InvalidWebhookURL("That URL is too long to be a Discord webhook.")

    parts = urlsplit(candidate)

    if parts.scheme != "https":
        raise InvalidWebhookURL("The webhook URL has to start with https://.")

    # `hostname` lower-cases and strips any port and userinfo, so
    # `https://discord.com@evil.example/` cannot pass as discord.com.
    host = parts.hostname or ""
    if host not in DISCORD_HOSTS:
        raise InvalidWebhookURL(
            "That is not a Discord webhook URL. It should begin https://discord.com/api/webhooks/."
        )

    # A port is never part of a real Discord webhook, and allowing one would let
    # a URL on an allowed host reach a different service behind it.
    if parts.port is not None:
        raise InvalidWebhookURL("A Discord webhook URL does not have a port.")

    if parts.username or parts.password:
        raise InvalidWebhookURL("That URL should not contain a username or password.")

    if parts.query or parts.fragment:
        raise InvalidWebhookURL("Remove anything after the token — no ? or # parts.")

    match = _PATH.match(parts.path)
    if match is None:
        raise InvalidWebhookURL(
            "That looks like a Discord link but not a webhook. Copy it from "
            "Server Settings → Integrations → Webhooks → Copy Webhook URL."
        )

    return Webhook(url=candidate, webhook_id=match.group(1), host=host)


def mask_webhook_url(url: str) -> str:
    """A webhook URL with the token hidden.

    The token is the credential: anyone holding it can post to that channel as
    this integration. Once saved it is never shown again, the same way an API
    key is not, so the settings page shows enough to recognise which webhook it
    is and nothing that could be copied out of a screenshot.
    """
    try:
        webhook = parse_webhook_url(url)
    except InvalidWebhookURL:
        return "•" * 12
    parts = urlsplit(webhook.url)
    return f"{parts.scheme}://{parts.hostname}/api/webhooks/{webhook.webhook_id}/{'•' * 10}"


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


@dataclass(frozen=True, slots=True)
class DigestFinding:
    """What a webhook needs to know about one finding.

    A plain dataclass rather than the ORM row, so this module stays free of
    SQLAlchemy and the payload can be built in a test from three lines of
    literals.
    """

    package: str
    version: str
    cve: str
    severity: str
    exploited: bool
    fixed_version: str | None = None

    @property
    def headline(self) -> str:
        return f"{self.package} {self.version}"

    @property
    def detail(self) -> str:
        fix = f"Fixed in {self.fixed_version}" if self.fixed_version else "No fix published yet"
        label = "Exploited in the wild" if self.exploited else self.severity.capitalize()
        return f"{label} · {self.cve} · {fix}"


def build_digest_payload(
    *,
    project: str,
    findings: list[DigestFinding],
    dashboard_url: str,
    filtered_count: int = 0,
) -> dict:
    """One embed describing what a scan found.

    Ordered worst-first and capped, because a channel that receives a
    twenty-screen message for every scan is a channel somebody mutes -- which
    would defeat the entire premise of the product it is reporting for.
    """
    if not findings:
        raise ValueError("build_digest_payload needs at least one finding")

    ordered = sorted(
        findings,
        key=lambda f: (not f.exploited, _severity_rank(f.severity), f.package),
    )
    worst = ordered[0]

    if worst.exploited:
        colour = COLOUR_EXPLOITED
    elif worst.severity == "critical":
        colour = COLOUR_CRITICAL
    else:
        colour = COLOUR_HIGH

    exploited = sum(1 for f in ordered if f.exploited)
    count = len(ordered)
    noun = "finding" if count == 1 else "findings"

    if exploited:
        title = f"{exploited} actively exploited in {project}"
    else:
        title = f"{count} new {noun} in {project}"

    shown = ordered[:MAX_FIELDS]
    fields = [
        {
            "name": _clip(finding.headline, MAX_TITLE),
            "value": _clip(finding.detail, MAX_FIELD_VALUE),
            "inline": False,
        }
        for finding in shown
    ]

    description_parts = []
    if exploited:
        description_parts.append(
            f"**{exploited}** of these {'is' if exploited == 1 else 'are'} on CISA's "
            "known-exploited list. Attackers are using "
            f"{'it' if exploited == 1 else 'them'} now, not in theory."
        )
    if len(ordered) > len(shown):
        description_parts.append(f"{len(ordered) - len(shown)} more on the dashboard.")
    if filtered_count:
        # The number this product is proud of is the one it did not send.
        description_parts.append(
            f"{filtered_count} other advisories matched and were filtered out as noise."
        )

    return {
        "username": "Weedout",
        "embeds": [
            {
                "title": _clip(title, MAX_TITLE),
                "url": dashboard_url,
                "color": colour,
                "description": _clip("\n\n".join(description_parts), MAX_DESCRIPTION),
                "fields": fields,
                "footer": {"text": _clip("Weedout · weed out the noise", MAX_FOOTER)},
            }
        ],
    }


def build_test_payload(*, project: str) -> dict:
    """What "Send a test" posts.

    Says plainly that it is a test. A message indistinguishable from a real
    alert would train the channel to ignore the real ones.
    """
    return {
        "username": "Weedout",
        "embeds": [
            {
                "title": "Webhook connected",
                "color": COLOUR_CALM,
                "description": (
                    f"This is a test message for **{_clip(project, 100)}**.\n\n"
                    "Real alerts arrive here only when a finding is critical or "
                    "being exploited in the wild. Everything else is filed on the "
                    "dashboard with the reason attached."
                ),
                "footer": {"text": "Weedout · test message"},
            }
        ],
    }


def _severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(severity, 4)
