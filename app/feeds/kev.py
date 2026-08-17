"""CISA Known Exploited Vulnerabilities catalog client.

KEV is the signal that separates Weedout from a generic dependency scanner:
it is the published, evidence-backed list of vulnerabilities with observed
exploitation. It is small (a few thousand rows), changes slowly, and is fetched
whole rather than queried.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import httpx

from app.core.types import KevEntry
from app.logging_config import get_logger

log = get_logger(__name__)

__all__ = ["KevCatalog", "KevClient", "KevFeedError"]


class KevFeedError(RuntimeError):
    """The KEV catalog could not be fetched or parsed."""


class KevCatalog:
    """A parsed KEV catalog snapshot."""

    __slots__ = ("catalog_version", "entries", "title")

    def __init__(
        self, entries: list[KevEntry], catalog_version: str | None = None, title: str = ""
    ) -> None:
        self.entries = entries
        self.catalog_version = catalog_version
        self.title = title

    @property
    def cve_ids(self) -> set[str]:
        return {entry.cve_id for entry in self.entries}

    def __len__(self) -> int:
        return len(self.entries)


def _parse_date(raw: Any) -> date | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return date.fromisoformat(raw.strip()[:10])
    except ValueError:
        return None


def parse_kev_payload(payload: dict[str, Any]) -> KevCatalog:
    """Parse the KEV JSON document into entries.

    Rows without a CVE ID are skipped — the CVE ID is the only key we can join
    on, so a row lacking one cannot influence any decision.
    """
    if not isinstance(payload, dict):
        raise KevFeedError("KEV feed did not return a JSON object")

    raw_entries = payload.get("vulnerabilities")
    if not isinstance(raw_entries, list):
        raise KevFeedError("KEV feed is missing its 'vulnerabilities' array")

    entries: list[KevEntry] = []
    skipped = 0
    for row in raw_entries:
        if not isinstance(row, dict):
            skipped += 1
            continue
        cve_id = row.get("cveID")
        if not isinstance(cve_id, str) or not cve_id.strip():
            skipped += 1
            continue

        entries.append(
            KevEntry(
                cve_id=cve_id.strip().upper(),
                vendor_project=str(row.get("vendorProject") or "")[:200],
                product=str(row.get("product") or "")[:200],
                vulnerability_name=str(row.get("vulnerabilityName") or ""),
                short_description=str(row.get("shortDescription") or ""),
                required_action=str(row.get("requiredAction") or ""),
                date_added=_parse_date(row.get("dateAdded")),
                due_date=_parse_date(row.get("dueDate")),
                known_ransomware_use=str(row.get("knownRansomwareCampaignUse") or "")
                .strip()
                .lower()
                == "known",
            )
        )

    if skipped:
        log.warning("kev.rows_skipped", count=skipped)

    if not entries:
        # An empty catalog would silently disable the product's main signal, so
        # treat it as a fetch failure and keep the previous snapshot.
        raise KevFeedError("KEV feed contained no usable entries")

    version = payload.get("catalogVersion")
    return KevCatalog(
        entries=entries,
        catalog_version=str(version) if version is not None else None,
        title=str(payload.get("title") or ""),
    )


class KevClient:
    """Fetches the KEV catalog over HTTP."""

    def __init__(
        self,
        feed_url: str,
        timeout: float = 30.0,
        user_agent: str = "weedout/0.1",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._feed_url = feed_url
        self._timeout = timeout
        self._user_agent = user_agent
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> KevClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout, headers={"User-Agent": self._user_agent}
            )
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch(self) -> KevCatalog:
        """Download and parse the current catalog.

        Raises `KevFeedError` on any failure. Callers keep the last good
        snapshot rather than proceeding with a partial one — a scan run against
        an empty KEV set would quietly downgrade every exploited-in-the-wild
        finding to ordinary severity triage.
        """
        if self._client is None:
            raise RuntimeError("KevClient must be used as an async context manager")

        try:
            response = await self._client.get(self._feed_url)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise KevFeedError(f"KEV feed returned HTTP {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise KevFeedError(f"KEV feed request failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise KevFeedError("KEV feed returned invalid JSON") from exc

        catalog = parse_kev_payload(payload)
        log.info("kev.fetched", entries=len(catalog), catalog_version=catalog.catalog_version)
        return catalog
