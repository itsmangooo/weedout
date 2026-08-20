"""Webhook destinations: Discord, and anything else.

Two kinds, and they are guarded differently because they can be.

**Discord** is an allowlist of four hostnames. An allowlist has to be right
once, which is why `app.core.discord` uses one.

**Custom** cannot be. The whole point is that the URL is somebody's own
endpoint, so the host is unknown by definition and the defence has to be a
deny-list of where a request must never go: loopback, private ranges, link-local
(including the cloud metadata address at 169.254.169.254), and every reserved
block. That is a weaker control than an allowlist and it is worth being honest
about why:

* A deny-list has to enumerate every private range, and IPv6 gives several ways
  to spell one. `ipaddress` is used rather than string matching, so `127.1`,
  `0x7f000001`, `::1` and `::ffff:127.0.0.1` all resolve to the same judgement.
* DNS is checked, not trusted. A hostname is resolved and *every* address it
  returns is examined, because a name with one public and one private A record
  passes any check that stops at the first answer.
* A name can still be re-pointed between this check and the request -- DNS
  rebinding. The window is narrow and the caller re-validates immediately
  before connecting, but it is not zero. Closing it completely means pinning
  the resolved address at connect time, which is a change to how the HTTP
  client makes connections rather than a change here.

Anyone deploying this behind a network that would suffer from a request to an
internal address should also keep egress rules on the container. Application
checks are the first layer, not the only one.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

__all__ = [
    "InvalidWebhookURL",
    "OutboundTarget",
    "WebhookKind",
    "describe_url",
    "validate_custom_url",
]


class InvalidWebhookURL(ValueError):
    """The URL cannot be used. Carries a message meant for the person."""


class WebhookKind(StrEnum):
    """How a destination is addressed and what shape it is sent."""

    DISCORD = "discord"
    CUSTOM = "custom"

    @property
    def label(self) -> str:
        return "Discord" if self is WebhookKind.DISCORD else "Custom endpoint"


@dataclass(frozen=True, slots=True)
class OutboundTarget:
    url: str
    host: str
    #: Every address the host resolved to, all of them checked public.
    addresses: tuple[str, ...]


def validate_custom_url(raw: str, *, resolve: bool = True) -> OutboundTarget:
    """Check a user-supplied endpoint. Raises `InvalidWebhookURL`.

    `resolve=False` skips the DNS lookup, for tests and for re-checking a
    syntactically-known-good value without a second round trip.
    """
    candidate = (raw or "").strip()
    if not candidate:
        raise InvalidWebhookURL("Paste the URL to post to.")

    if any(ch.isspace() or ord(ch) < 0x20 for ch in candidate):
        raise InvalidWebhookURL("That URL contains spaces or line breaks.")

    if len(candidate) > 500:
        raise InvalidWebhookURL("That URL is too long.")

    parts = urlsplit(candidate)

    # Plaintext is refused outright. This payload names the vulnerable packages
    # in somebody's product; putting that on the wire unencrypted is a finding
    # of its own.
    if parts.scheme != "https":
        raise InvalidWebhookURL("The URL has to start with https://.")

    if parts.username or parts.password:
        raise InvalidWebhookURL("That URL should not contain a username or password.")

    host = parts.hostname or ""
    if not host:
        raise InvalidWebhookURL("That URL has no hostname.")

    # A port other than 443 is usually somebody pointing at an internal service
    # on an otherwise public name.
    if parts.port not in (None, 443):
        raise InvalidWebhookURL("Only the standard https port is allowed.")

    addresses = _addresses_for(host, resolve=resolve)
    for address in addresses:
        _refuse_if_internal(address)

    return OutboundTarget(url=candidate, host=host, addresses=tuple(addresses))


def _addresses_for(host: str, *, resolve: bool) -> list[str]:
    """Every address this host answers to.

    An IP literal is checked as itself. A name is resolved and *all* of its
    answers are returned, because a name with one public and one private record
    passes any check that only looks at the first.
    """
    try:
        return [str(ipaddress.ip_address(host.strip("[]")))]
    except ValueError:
        pass

    if not resolve:
        return []

    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise InvalidWebhookURL(f"That hostname does not resolve: {host}") from exc

    found = {info[4][0] for info in infos}
    if not found:
        raise InvalidWebhookURL(f"That hostname does not resolve: {host}")
    return sorted(found)


def _refuse_if_internal(address: str) -> None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise InvalidWebhookURL("That URL resolves to something unusable.") from exc

    # IPv4-mapped IPv6 (::ffff:127.0.0.1) is unwrapped, or the checks below
    # would judge the wrapper rather than the address inside it.
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped

    if (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    ):
        raise InvalidWebhookURL(
            "That address is inside a private network. A webhook has to point "
            "somewhere reachable from the public internet."
        )


def describe_url(url: str) -> str:
    """A short label for a saved custom endpoint.

    Shows the host and the path shape without the query string, which is where
    people put tokens.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "an endpoint"
    host = parts.hostname or "an endpoint"
    path = parts.path or "/"
    if len(path) > 30:
        path = path[:29] + "…"
    return f"{host}{path}"


def build_custom_payload(
    *,
    project: str,
    findings: list,
    dashboard_url: str,
    filtered_count: int = 0,
) -> dict:
    """A plain JSON body, for an endpoint that is not Discord.

    Flat and boring on purpose: whoever receives this is writing a handler
    against it, and a shape that mirrors the scan API they already know is one
    less thing to learn.
    """
    return {
        "source": "weedout",
        "event": "findings.new",
        "project": project,
        "dashboard_url": dashboard_url,
        "filtered_count": filtered_count,
        "counts": {
            "total": len(findings),
            "exploited": sum(1 for f in findings if f.exploited),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
        },
        "findings": [
            {
                "package": f.package,
                "version": f.version,
                "cve": f.cve,
                "severity": f.severity,
                "exploited": f.exploited,
                "fixed_in": f.fixed_version,
            }
            for f in findings
        ],
    }
