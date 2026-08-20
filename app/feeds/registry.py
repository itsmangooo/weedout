"""Asking npm and PyPI about a package.

Only ever called from the metadata refresh job, never from a scan. A manifest
with three hundred dependencies would otherwise become three hundred outbound
requests on the request path, which is the same mistake the advisory mirror
exists to avoid.

What each registry actually answers is not the same, and this module is careful
not to paper over the difference:

* **npm** gives publish times per version, a `maintainers` array, deprecation
  notices, and provenance attestations on recent releases. All four signals are
  available.
* **PyPI** gives upload times and a deprecation-ish `yanked` flag, but no
  maintainer *count* — `info.maintainer` is a free-text string that is usually
  empty and never a list. So single-maintainer is left unknown for PyPI rather
  than guessed from whether a name happens to contain a comma.

`None` means "not known". It never means zero, and it never means no.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from app.core.supply_chain import PackageFacts
from app.core.types import Ecosystem

__all__ = ["RegistryClient", "RegistryError", "supports_metadata"]

NPM_URL = "https://registry.npmjs.org/{name}"
PYPI_URL = "https://pypi.org/pypi/{name}/json"

#: Go modules are resolved from their source host rather than a registry with a
#: metadata API, so none of this applies. Saying so here beats a client that
#: quietly returns nothing.
_SUPPORTED = {Ecosystem.NPM, Ecosystem.PYPI}


def supports_metadata(ecosystem: Ecosystem) -> bool:
    return ecosystem in _SUPPORTED


class RegistryError(RuntimeError):
    """The registry could not be reached, or said something unusable."""


class RegistryClient:
    def __init__(self, timeout: float, user_agent: str) -> None:
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": user_agent, "Accept": "application/json"},
            follow_redirects=True,
        )

    async def __aenter__(self) -> RegistryClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._client.aclose()

    async def fetch(self, ecosystem: Ecosystem, name: str) -> PackageFacts:
        if ecosystem is Ecosystem.NPM:
            return await self._fetch_npm(name)
        if ecosystem is Ecosystem.PYPI:
            return await self._fetch_pypi(name)
        raise RegistryError(f"No metadata source for {ecosystem}")

    async def _get(self, url: str, name: str) -> dict:
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as exc:
            raise RegistryError(f"Could not reach the registry: {type(exc).__name__}") from exc

        if response.status_code == 404:
            # A package the registry has never heard of. Worth distinguishing
            # from an outage: it usually means a private or renamed package,
            # not a problem with the package.
            raise RegistryError(f"{name} is not published on this registry")
        if response.status_code != 200:
            raise RegistryError(f"The registry answered {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise RegistryError("The registry did not return JSON") from exc
        if not isinstance(payload, dict):
            raise RegistryError("The registry returned an unexpected shape")
        return payload

    async def _fetch_npm(self, name: str) -> PackageFacts:
        payload = await self._get(NPM_URL.format(name=name), name)

        latest = None
        dist_tags = payload.get("dist-tags")
        if isinstance(dist_tags, dict):
            latest = dist_tags.get("latest")

        # `time` maps version -> ISO timestamp, plus `created` and `modified`.
        # `modified` moves when metadata changes rather than when code ships,
        # so the latest version's own timestamp is the honest answer.
        days = None
        times = payload.get("time")
        if isinstance(times, dict):
            stamp = times.get(latest) if latest else None
            days = _days_since(stamp) if stamp else _days_since(times.get("modified"))

        maintainers = payload.get("maintainers")
        count = len(maintainers) if isinstance(maintainers, list) and maintainers else None

        versions = payload.get("versions")
        provenance = None
        deprecated = None
        if isinstance(versions, dict) and latest and isinstance(versions.get(latest), dict):
            entry = versions[latest]
            dist = entry.get("dist")
            if isinstance(dist, dict):
                # npm publishes attestations under dist.attestations. Absence
                # is a real "no" here, because every npm package could have one.
                provenance = bool(dist.get("attestations"))
            raw_deprecated = entry.get("deprecated")
            if isinstance(raw_deprecated, str) and raw_deprecated.strip():
                deprecated = raw_deprecated

        return PackageFacts(
            ecosystem=Ecosystem.NPM,
            name=name,
            latest_version=latest if isinstance(latest, str) else None,
            days_since_release=days,
            maintainer_count=count,
            has_provenance=provenance,
            deprecated=deprecated,
        )

    async def _fetch_pypi(self, name: str) -> PackageFacts:
        payload = await self._get(PYPI_URL.format(name=name), name)

        info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
        latest = info.get("version") if isinstance(info.get("version"), str) else None

        # `urls` is the file list for the latest release; the earliest upload
        # among them is when that version shipped.
        days = None
        urls = payload.get("urls")
        if isinstance(urls, list) and urls:
            stamps = [
                entry.get("upload_time_iso_8601")
                for entry in urls
                if isinstance(entry, dict) and entry.get("upload_time_iso_8601")
            ]
            if stamps:
                days = _days_since(min(stamps))

        deprecated = None
        if info.get("yanked") is True:
            reason = info.get("yanked_reason")
            deprecated = reason if isinstance(reason, str) and reason.strip() else "Release yanked"

        return PackageFacts(
            ecosystem=Ecosystem.PYPI,
            name=name,
            latest_version=latest,
            days_since_release=days,
            # PyPI's JSON API has no maintainer list -- `info.maintainer` is a
            # free-text string, usually empty. Left unknown rather than derived
            # from punctuation in somebody's name.
            maintainer_count=None,
            # PyPI has attestations in preview but not in this endpoint, so
            # there is nothing to report rather than a "no" that would read as
            # a finding.
            has_provenance=None,
            deprecated=deprecated,
        )


def _days_since(stamp: object) -> int | None:
    if not isinstance(stamp, str) or not stamp.strip():
        return None
    text = stamp.strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    delta = datetime.now(UTC) - moment
    # A future timestamp is a clock problem somewhere, not a package published
    # tomorrow. Clamped rather than returned negative.
    return max(0, delta.days)
