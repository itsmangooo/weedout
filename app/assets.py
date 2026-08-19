"""Cache-busting URLs for static files, keyed on content.

The previous scheme appended the application version, which is a number nobody
remembers to bump. `weedout.css?v=0.1.0` stayed the same URL across every
change to the stylesheet, so a browser that had loaded it once kept serving the
old one from cache — and a page whose styles arrived in a later release
rendered completely unstyled.

Keying on a hash of the bytes makes that impossible by construction: change the
file, change the URL. Nothing to remember, and nothing to get wrong.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"

#: path -> (mtime_ns, size, digest). Keyed on both mtime and size because mtime
#: alone has second granularity on some filesystems, and a file rewritten
#: within the same second is exactly the case this has to catch.
_cache: dict[str, tuple[int, int, str]] = {}


def digest(relative_path: str) -> str:
    """A short content hash for a file under app/static.

    Reads the file at most once per change. In production the files never
    change after the image is built, so this is one read per file for the life
    of the process.
    """
    path = STATIC_DIR / relative_path.lstrip("/")
    try:
        stat = path.stat()
    except OSError:
        # A missing asset is a broken page either way; returning an empty
        # version keeps the URL usable so the 404 is about the file rather
        # than about this function.
        return ""

    cached = _cache.get(relative_path)
    if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return cached[2]

    try:
        value = hashlib.sha256(path.read_bytes()).hexdigest()[:10]
    except OSError:
        return ""

    _cache[relative_path] = (stat.st_mtime_ns, stat.st_size, value)
    return value


def asset(relative_path: str) -> str:
    """`/static/css/weedout.css?v=<hash>`, for use in templates."""
    clean = relative_path.lstrip("/")
    version = digest(clean)
    url = f"/static/{clean}"
    return f"{url}?v={version}" if version else url
