"""OSV.dev client.

OSV aggregates the GitHub Advisory Database, PyPA, the Go vulnerability
database and others behind one schema, which is why it is the dependency-level
source here rather than querying each ecosystem separately.

Two calls are used:

* ``POST /v1/querybatch`` — many (package, version) pairs in one request,
  returning only advisory IDs. This keeps a 400-dependency manifest to a couple
  of round trips instead of 400.
* ``GET /v1/vulns/{id}`` — the full record for one advisory. Callers are
  expected to skip IDs they have already cached, so this runs for genuinely new
  advisories only.

Every network failure raises `OSVError`. Callers decide whether a partial
result is usable; this module never invents an empty result to paper over an
outage, because "no vulnerabilities found" and "we could not check" must not
look the same to a user.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from app.core.osv import normalize_osv_record
from app.core.types import Dependency, Vulnerability
from app.logging_config import get_logger

log = get_logger(__name__)

__all__ = ["OSVClient", "OSVError"]

#: OSV accepts up to 1000 queries per batch; a smaller chunk keeps individual
#: requests fast and makes a single failure cheaper to retry.
BATCH_SIZE = 200

#: Bound on concurrent detail fetches, to stay a polite client of a free API.
DETAIL_CONCURRENCY = 8

MAX_RETRIES = 3


class OSVError(RuntimeError):
    """An OSV request failed after exhausting retries."""


class OSVClient:
    def __init__(
        self,
        api_url: str = "https://api.osv.dev",
        timeout: float = 30.0,
        user_agent: str = "weedout/0.1",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout
        self._user_agent = user_agent
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> OSVClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout, headers={"User-Agent": self._user_agent}
            )
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("OSVClient must be used as an async context manager")
        return self._client

    async def _request_with_retry(
        self, method: str, url: str, *, json_body: dict[str, Any] | None = None
    ) -> httpx.Response:
        """Issue a request, retrying transient failures with exponential backoff.

        4xx responses other than 429 are not retried — they will not become
        correct by being repeated.
        """
        client = self._require_client()
        last_error: Exception | None = None

        for attempt in range(MAX_RETRIES):
            try:
                response = await client.request(method, url, json=json_body)
                if response.status_code < 400:
                    return response
                if response.status_code == 429 or response.status_code >= 500:
                    last_error = OSVError(f"OSV returned HTTP {response.status_code}")
                else:
                    raise OSVError(f"OSV returned HTTP {response.status_code} for {url}")
            except httpx.HTTPError as exc:
                last_error = OSVError(f"OSV request failed: {exc}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2**attempt)

        raise last_error or OSVError("OSV request failed")

    async def query_batch(
        self, dependencies: list[Dependency]
    ) -> dict[tuple[str, str, str], list[str]]:
        """Look up advisory IDs for many dependencies at once.

        Returns a mapping from `Dependency.key` to the advisory IDs affecting
        it. Dependencies with no advisories are absent from the mapping.

        OSV preserves the order of the submitted queries in its results array,
        which is the only way to associate a result with its input, so the
        response is rejected if the lengths disagree rather than risk pairing a
        package with another package's advisories.
        """
        results: dict[tuple[str, str, str], list[str]] = {}
        if not dependencies:
            return results

        for start in range(0, len(dependencies), BATCH_SIZE):
            chunk = dependencies[start : start + BATCH_SIZE]
            payload = {
                "queries": [
                    {
                        "package": {"name": dep.name, "ecosystem": str(dep.ecosystem)},
                        "version": dep.version,
                    }
                    for dep in chunk
                ]
            }

            response = await self._request_with_retry(
                "POST", f"{self._api_url}/v1/querybatch", json_body=payload
            )
            try:
                body = response.json()
            except ValueError as exc:
                raise OSVError("OSV querybatch returned invalid JSON") from exc

            entries = body.get("results")
            if not isinstance(entries, list):
                raise OSVError("OSV querybatch response is missing 'results'")
            if len(entries) != len(chunk):
                raise OSVError(
                    f"OSV returned {len(entries)} results for {len(chunk)} queries; "
                    "cannot safely associate them with packages"
                )

            for dep, entry in zip(chunk, entries, strict=True):
                if not isinstance(entry, dict):
                    continue
                vuln_ids = [
                    v["id"]
                    for v in (entry.get("vulns") or [])
                    if isinstance(v, dict) and isinstance(v.get("id"), str)
                ]
                if vuln_ids:
                    results[dep.key] = vuln_ids

        log.info(
            "osv.query_batch",
            dependencies=len(dependencies),
            with_advisories=len(results),
        )
        return results

    async def get_vulnerability(self, vuln_id: str) -> Vulnerability | None:
        """Fetch and normalise one advisory.

        A 404 yields ``None`` (the advisory was withdrawn or renamed upstream)
        rather than raising, since one missing record should not fail a scan.
        """
        client = self._require_client()
        url = f"{self._api_url}/v1/vulns/{vuln_id}"
        try:
            response = await self._request_with_retry("GET", url)
        except OSVError:
            probe = await client.get(url)
            if probe.status_code == 404:
                log.info("osv.vuln_not_found", vuln_id=vuln_id)
                return None
            raise

        try:
            record = response.json()
        except ValueError as exc:
            raise OSVError(f"OSV returned invalid JSON for {vuln_id}") from exc

        return normalize_osv_record(record)

    async def get_vulnerabilities(self, vuln_ids: list[str]) -> dict[str, Vulnerability]:
        """Fetch many advisories concurrently, bounded by `DETAIL_CONCURRENCY`.

        Individual failures are logged and skipped so that one bad record does
        not cost the caller every other advisory in the batch.
        """
        unique_ids = list(dict.fromkeys(vuln_ids))
        if not unique_ids:
            return {}

        semaphore = asyncio.Semaphore(DETAIL_CONCURRENCY)
        fetched: dict[str, Vulnerability] = {}

        async def fetch_one(vuln_id: str) -> None:
            async with semaphore:
                try:
                    vulnerability = await self.get_vulnerability(vuln_id)
                except OSVError as exc:
                    log.warning("osv.detail_failed", vuln_id=vuln_id, error=str(exc))
                    return
                if vulnerability is not None:
                    fetched[vuln_id] = vulnerability

        await asyncio.gather(*(fetch_one(vuln_id) for vuln_id in unique_ids))

        log.info("osv.details_fetched", requested=len(unique_ids), fetched=len(fetched))
        return fetched
