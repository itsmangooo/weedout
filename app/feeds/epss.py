"""Fetching FIRST's daily EPSS scores.

One gzipped CSV, about two megabytes for roughly 280,000 CVEs, republished
every day. Downloaded whole rather than queried per CVE: the API takes a
hundred ids per request, and a scan that had to ask about its findings would be
making outbound calls from the request path, which is exactly what the advisory
mirror exists to avoid.
"""

from __future__ import annotations

import gzip

import httpx

from app.core.epss import EpssSnapshot, parse_epss_csv

__all__ = ["EPSS_FEED_URL", "EpssClient", "EpssFeedError"]

EPSS_FEED_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

#: The uncompressed file is about 14 MB. A cap an order of magnitude above that
#: stops a redirected or replaced URL filling the disk, while leaving room for
#: the catalogue to keep growing.
MAX_BYTES = 200 * 1024 * 1024


class EpssFeedError(RuntimeError):
    """The scores could not be fetched or made sense of."""


class EpssClient:
    def __init__(self, feed_url: str, timeout: float, user_agent: str) -> None:
        self._url = feed_url
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": user_agent, "Accept-Encoding": "gzip"},
            follow_redirects=True,
        )

    async def __aenter__(self) -> EpssClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._client.aclose()

    async def fetch(self) -> EpssSnapshot:
        try:
            response = await self._client.get(self._url)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise EpssFeedError(f"Could not reach the EPSS feed: {exc}") from exc

        payload = response.content
        if len(payload) > MAX_BYTES:
            raise EpssFeedError("The EPSS feed was larger than expected; refusing it.")

        # httpx transparently decompresses when the server sets
        # Content-Encoding, but this file is gzip *content* served as an
        # octet-stream, so it usually arrives still compressed. Sniff the magic
        # number rather than trusting either header.
        if payload[:2] == b"\x1f\x8b":
            try:
                payload = gzip.decompress(payload)
            except OSError as exc:
                raise EpssFeedError(f"The EPSS feed was not readable gzip: {exc}") from exc

        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EpssFeedError("The EPSS feed was not valid UTF-8.") from exc

        snapshot = parse_epss_csv(text)
        if not snapshot.entries:
            # An empty file would wipe every score on upsert and quietly turn
            # the signal off for everybody.
            raise EpssFeedError("The EPSS feed parsed to zero scores; refusing it.")
        return snapshot
