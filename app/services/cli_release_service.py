"""What the CLI page says about the CLI, fetched rather than hand-maintained.

Three things come from outside this repository and must never be retyped here:

* the dependency list, parsed from the CLI's own ``go.mod``
* the current version, from the latest GitHub release
* the download assets for that release

A hardcoded copy of any of them is a claim that goes stale silently, which on a
page whose whole argument is "we are honest about dependencies" would be the
worst possible thing to get wrong. So they are fetched and cached, and when the
fetch fails the page says the data is unavailable rather than showing something
that was true once.

Everything is cached in-process with a TTL. This is a marketing page: it can be
a few hours behind, and it must not put a network call on the critical path of
every request.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from app.logging_config import get_logger

log = get_logger(__name__)

REPO = "itsmangooo/weedout-cli"
GO_MOD_URL = f"https://raw.githubusercontent.com/{REPO}/main/go.mod"
LATEST_RELEASE_URL = f"https://api.github.com/repos/{REPO}/releases/latest"

#: How long a successful fetch is trusted. A release happens rarely; an hour of
#: staleness on a marketing page is invisible, and it keeps GitHub's
#: unauthenticated rate limit far away.
TTL_SECONDS = 3600

#: How long to wait before giving up. Short: the page renders without this
#: data rather than making a visitor wait on GitHub.
TIMEOUT_SECONDS = 4

USER_AGENT = "weedout.dev"


@dataclass(frozen=True, slots=True)
class GoDependency:
    """One line from the CLI's go.mod require block."""

    module: str
    version: str
    indirect: bool

    @property
    def is_stdlib(self) -> bool:
        """Standard-library imports never appear in go.mod at all.

        Kept as a property rather than a field so nothing can construct a
        dependency that claims to be stdlib — if it is in the require block, it
        is by definition not.
        """
        return False


@dataclass(frozen=True, slots=True)
class GoModule:
    """The parsed go.mod."""

    module_path: str
    go_version: str
    dependencies: tuple[GoDependency, ...] = ()
    #: False when the fetch failed, so the page can say so plainly instead of
    #: implying an empty require block.
    available: bool = True

    @property
    def direct(self) -> tuple[GoDependency, ...]:
        return tuple(d for d in self.dependencies if not d.indirect)

    @property
    def indirect(self) -> tuple[GoDependency, ...]:
        return tuple(d for d in self.dependencies if d.indirect)

    @property
    def third_party_count(self) -> int:
        return len(self.dependencies)

    @property
    def is_stdlib_only(self) -> bool:
        return self.available and not self.dependencies


@dataclass(frozen=True, slots=True)
class ReleaseAsset:
    name: str
    url: str
    size_bytes: int

    @property
    def platform(self) -> str:
        """`weedout-darwin-arm64` -> `darwin-arm64`."""
        stem = self.name.removeprefix("weedout-").removesuffix(".exe")
        return stem

    @property
    def size_label(self) -> str:
        return f"{self.size_bytes / 1_000_000:.1f} MB"


@dataclass(frozen=True, slots=True)
class Release:
    version: str
    published_at: str
    notes_url: str
    assets: tuple[ReleaseAsset, ...] = ()
    available: bool = True


@dataclass
class _Cached:
    value: Any = None
    fetched_at: float = 0.0
    lock_note: str = field(default="", repr=False)

    def fresh(self) -> bool:
        return self.value is not None and (time.time() - self.fetched_at) < TTL_SECONDS


_go_mod_cache = _Cached()
_release_cache = _Cached()


def _fetch(url: str, accept: str = "text/plain") -> str | None:
    request = urllib.request.Request(  # noqa: S310 - constant https URLs above
        url,
        headers={"User-Agent": USER_AGENT, "Accept": accept},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            return response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log.warning("cli_release.fetch_failed", url=url, error=str(exc))
        return None


# ---------------------------------------------------------------------------
# go.mod
# ---------------------------------------------------------------------------

_MODULE_RE = re.compile(r"^module\s+(\S+)", re.M)
_GO_RE = re.compile(r"^go\s+(\S+)", re.M)
_REQUIRE_BLOCK_RE = re.compile(r"^require\s*\((.*?)^\)", re.M | re.S)
_REQUIRE_LINE_RE = re.compile(r"^require\s+(\S+)\s+(\S+)(.*)$", re.M)


def parse_go_mod(text: str) -> GoModule:
    """Parse a go.mod. Pure, so the parsing is testable without the network.

    Handles both forms of require — the parenthesised block and the one-line
    version — because a file with a single dependency is usually written the
    short way and would otherwise be reported as having none.
    """
    module_match = _MODULE_RE.search(text)
    go_match = _GO_RE.search(text)

    seen: dict[str, GoDependency] = {}

    def add(module: str, version: str, trailer: str) -> None:
        module = module.strip()
        if not module or module.startswith("//"):
            return
        seen[module] = GoDependency(
            module=module,
            version=version.strip(),
            indirect="// indirect" in trailer,
        )

    for block in _REQUIRE_BLOCK_RE.findall(text):
        for raw in block.splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            add(parts[0], parts[1], parts[2] if len(parts) > 2 else "")

    for module, version, trailer in _REQUIRE_LINE_RE.findall(text):
        if module == "(":
            continue
        add(module, version, trailer)

    return GoModule(
        module_path=module_match.group(1) if module_match else "",
        go_version=go_match.group(1) if go_match else "",
        dependencies=tuple(sorted(seen.values(), key=lambda d: (d.indirect, d.module))),
    )


def go_module(*, refresh: bool = False) -> GoModule:
    """The CLI's parsed go.mod, cached."""
    if not refresh and _go_mod_cache.fresh():
        return _go_mod_cache.value

    text = _fetch(GO_MOD_URL)
    if text is None:
        # Serve a stale value rather than nothing: an hour-old dependency list
        # is far more useful than an error, and it is still not hand-written.
        if _go_mod_cache.value is not None:
            return _go_mod_cache.value
        return GoModule(module_path="", go_version="", available=False)

    parsed = parse_go_mod(text)
    _go_mod_cache.value = parsed
    _go_mod_cache.fetched_at = time.time()
    return parsed


# ---------------------------------------------------------------------------
# Releases
# ---------------------------------------------------------------------------


def parse_release(payload: dict) -> Release:
    assets = tuple(
        ReleaseAsset(
            name=asset.get("name", ""),
            url=asset.get("browser_download_url", ""),
            size_bytes=int(asset.get("size") or 0),
        )
        for asset in payload.get("assets", [])
        # checksums.txt is published for the install script to verify against,
        # not for a person to download from a table of binaries.
        if asset.get("name", "").startswith("weedout-")
    )
    return Release(
        version=payload.get("tag_name", ""),
        published_at=payload.get("published_at", ""),
        notes_url=payload.get("html_url", f"https://github.com/{REPO}/releases"),
        assets=tuple(sorted(assets, key=lambda a: a.name)),
    )


def latest_release(*, refresh: bool = False) -> Release:
    """The most recent published release, cached."""
    if not refresh and _release_cache.fresh():
        return _release_cache.value

    raw = _fetch(LATEST_RELEASE_URL, accept="application/vnd.github+json")
    if raw is None:
        if _release_cache.value is not None:
            return _release_cache.value
        return Release(
            version="",
            published_at="",
            notes_url=f"https://github.com/{REPO}/releases",
            available=False,
        )

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("cli_release.bad_json")
        return Release(
            version="",
            published_at="",
            notes_url=f"https://github.com/{REPO}/releases",
            available=False,
        )

    release = parse_release(payload)
    _release_cache.value = release
    _release_cache.fetched_at = time.time()
    return release


def reset_cache() -> None:
    """Drop both caches. Used by tests, and by `manage.py` after a release."""
    _go_mod_cache.value = None
    _go_mod_cache.fetched_at = 0.0
    _release_cache.value = None
    _release_cache.fetched_at = 0.0
