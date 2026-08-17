"""Markdown rendering for documentation pages.

**Raw HTML is disabled.** Only the administrator can author docs, so this is
not the last line of defence — but a CMS that renders arbitrary HTML turns any
future compromise of one admin account, or one careless paste from an external
source, into stored XSS across the whole public site. Turning it off costs
nothing here, because Markdown already expresses everything a docs page needs.

That decision also means no HTML sanitiser dependency: there is no untrusted
HTML to sanitise, because none is ever produced.

Rendering is a pure function of its input, so it is testable without a database
and cheap enough to run per request at this scale.
"""

from __future__ import annotations

import re
from functools import lru_cache

from markdown_it import MarkdownIt

__all__ = ["extract_summary", "render_markdown", "slugify"]


def _build_parser() -> MarkdownIt:
    parser = MarkdownIt(
        "commonmark",
        {
            # The setting that matters. With html=False, raw tags in the source
            # are escaped and rendered as visible text rather than markup.
            "html": False,
            "linkify": True,
            "typographer": True,
            "breaks": False,
        },
    )
    parser.enable(["table", "strikethrough", "linkify"])
    return parser


#: One parser instance; MarkdownIt is stateless between `render` calls.
_PARSER = _build_parser()

#: External links open in a new tab and drop the referrer. Internal links —
#: docs cross-referencing each other — stay in place.
_EXTERNAL_LINK = re.compile(r'<a href="(https?://[^"]*)"')


@lru_cache(maxsize=256)
def render_markdown(source: str) -> str:
    """Render Markdown to HTML.

    Cached on the source text: docs change rarely and are read often, so the
    same handful of pages would otherwise be re-parsed on every request. The
    cache key is the content itself, so an edit invalidates it automatically
    with no explicit busting to forget.
    """
    if not source or not source.strip():
        return ""

    html = _PARSER.render(source)
    return _EXTERNAL_LINK.sub(r'<a rel="noopener noreferrer" target="_blank" href="\1"', html)


_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


def slugify(value: str, fallback: str = "page") -> str:
    """Turn a title into a URL segment.

    Deliberately aggressive: anything outside `[a-z0-9-]` becomes a hyphen, so
    a slug can never need escaping in a URL or be mistaken for a path segment.
    """
    slug = _SLUG_STRIP.sub("-", (value or "").strip().lower()).strip("-")
    return (slug or fallback)[:120].strip("-") or fallback


_MARKDOWN_NOISE = re.compile(r"[#*_`>\[\]()!]|\n+")


def extract_summary(source: str, limit: int = 200) -> str:
    """First meaningful sentence of a document, for index cards and meta tags.

    Used only when the author has not written a summary — a hand-written one is
    always better, so this never overwrites it.
    """
    for block in (source or "").split("\n\n"):
        text = block.strip()
        if not text or text.startswith(("#", "```", "|", "-", "*", ">")):
            continue
        cleaned = _MARKDOWN_NOISE.sub(" ", text)
        cleaned = " ".join(cleaned.split())
        if cleaned:
            return cleaned[:limit].rstrip() + ("…" if len(cleaned) > limit else "")
    return ""
