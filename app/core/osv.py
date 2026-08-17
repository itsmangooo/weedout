"""Normalise raw OSV advisory JSON into the core `Vulnerability` type.

Kept pure and separate from the HTTP client so the awkward parts — pairing
range events into intervals, reconciling three different severity encodings,
skipping git-commit ranges — can be tested against captured fixtures without a
network call.

OSV schema reference: https://ossf.github.io/osv-schema/
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from app.core.cvss import normalize_severity
from app.core.types import AffectedPackage, AffectedRange, Ecosystem, Severity, Vulnerability

__all__ = ["normalize_osv_record", "parse_affected", "parse_osv_datetime"]

#: OSV ecosystem identifiers we can act on. Others (Debian, Alpine, Maven, …)
#: are skipped rather than guessed at.
_SUPPORTED: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "pypi": Ecosystem.PYPI,
    "go": Ecosystem.GO,
}

#: Range types expressible as version comparisons. GIT ranges are commit
#: hashes, which have no ordering we can evaluate, so they are ignored.
_VERSION_RANGE_TYPES = {"SEMVER", "ECOSYSTEM"}


def parse_ecosystem(raw: str | None) -> Ecosystem | None:
    """Map an OSV ecosystem string to ours.

    OSV qualifies some ecosystems with a release (``"Alpine:v3.10"``), so only
    the portion before the colon is significant.
    """
    if not raw:
        return None
    return _SUPPORTED.get(raw.split(":", maxsplit=1)[0].strip().lower())


def parse_osv_datetime(raw: str | None) -> datetime | None:
    """Parse an RFC 3339 timestamp, tolerating the ``Z`` suffix."""
    if not raw or not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _pair_range_events(events: list[dict[str, Any]]) -> list[AffectedRange]:
    """Fold a flat OSV event list into ``[introduced, fixed)`` intervals.

    Events arrive as a sequence like::

        [{"introduced": "0"}, {"fixed": "1.5.0"},
         {"introduced": "2.0.0"}, {"last_affected": "2.4.0"}]

    An ``introduced`` opens a window; a ``fixed`` or ``last_affected`` closes
    the most recently opened one. A window left open at the end of the list
    means "affected in every version from there on", which is a real and common
    state — the advisory has no fix yet.

    The schema does not guarantee ordering, so a stray closing event with no
    open window is dropped rather than allowed to invent an interval starting
    at zero.
    """
    ranges: list[AffectedRange] = []
    current_introduced: str | None = None
    open_window = False

    for event in events:
        if not isinstance(event, dict):
            continue

        if "introduced" in event:
            if open_window:
                # Two introductions in a row: close the previous unbounded one.
                ranges.append(AffectedRange(introduced=current_introduced, fixed=None))
            current_introduced = str(event["introduced"])
            open_window = True
            continue

        if "fixed" in event:
            if not open_window:
                continue
            ranges.append(AffectedRange(introduced=current_introduced, fixed=str(event["fixed"])))
            open_window = False
            current_introduced = None
            continue

        if "last_affected" in event:
            if not open_window:
                continue
            ranges.append(
                AffectedRange(
                    introduced=current_introduced,
                    fixed=None,
                    last_affected=str(event["last_affected"]),
                )
            )
            open_window = False
            current_introduced = None
            continue

        # "limit" events belong to GIT ranges and carry no version meaning.

    if open_window:
        ranges.append(AffectedRange(introduced=current_introduced, fixed=None))

    return ranges


def parse_affected(raw_affected: list[dict[str, Any]] | None) -> tuple[AffectedPackage, ...]:
    """Extract the affected-package entries we can evaluate."""
    result: list[AffectedPackage] = []

    for entry in raw_affected or []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if not isinstance(package, dict):
            continue

        ecosystem = parse_ecosystem(package.get("ecosystem"))
        name = package.get("name")
        if ecosystem is None or not isinstance(name, str) or not name:
            continue

        ranges: list[AffectedRange] = []
        for raw_range in entry.get("ranges") or []:
            if not isinstance(raw_range, dict):
                continue
            if raw_range.get("type") not in _VERSION_RANGE_TYPES:
                continue
            events = raw_range.get("events")
            if isinstance(events, list):
                ranges.extend(_pair_range_events(events))

        versions = tuple(v for v in (entry.get("versions") or []) if isinstance(v, str) and v)

        if not ranges and not versions:
            # Nothing to compare against; treating this as "affects everything"
            # would flag every user of the package.
            continue

        result.append(
            AffectedPackage(ecosystem=ecosystem, name=name, ranges=tuple(ranges), versions=versions)
        )

    return tuple(result)


def _extract_references(raw: Any) -> tuple[str, ...]:
    urls: list[str] = []
    for reference in raw or []:
        if isinstance(reference, dict):
            url = reference.get("url")
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                urls.append(url)
        elif isinstance(reference, str) and reference.startswith(("http://", "https://")):
            urls.append(reference)
    return tuple(dict.fromkeys(urls))[:20]


_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)


def _extract_cwe_ids(record: dict[str, Any]) -> tuple[str, ...]:
    """Pull CWE classifications out of the publisher-specific block.

    OSV has no first-class CWE field, so publishers put it in
    `database_specific` under keys that differ between them. Anything not
    shaped like `CWE-<number>` is dropped rather than stored as-is — a
    free-text weakness description in a field named `cwe_ids` would poison any
    grouping built on it later.
    """
    found: list[str] = []

    def collect(container: Any) -> None:
        if not isinstance(container, dict):
            return
        for key in ("cwe_ids", "cweIds", "cwes"):
            value = container.get(key)
            if isinstance(value, str):
                value = [value]
            if not isinstance(value, list):
                continue
            for item in value:
                # GitHub nests {"cweId": "CWE-79", "name": "..."}.
                candidate = item.get("cweId") if isinstance(item, dict) else item
                if isinstance(candidate, str) and _CWE_RE.match(candidate.strip()):
                    found.append(candidate.strip().upper())

    collect(record.get("database_specific"))
    for entry in record.get("affected") or []:
        if isinstance(entry, dict):
            collect(entry.get("database_specific"))

    return tuple(dict.fromkeys(found))[:10]


def _qualitative_label(record: dict[str, Any]) -> str | None:
    """Find a severity label wherever this publisher happened to put it."""
    database_specific = record.get("database_specific")
    if isinstance(database_specific, dict):
        label = database_specific.get("severity")
        if isinstance(label, str):
            return label

    # GitHub-sourced records sometimes carry it per affected entry instead.
    for entry in record.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        entry_specific = entry.get("database_specific")
        if isinstance(entry_specific, dict):
            label = entry_specific.get("severity")
            if isinstance(label, str):
                return label
    return None


def normalize_osv_record(record: dict[str, Any]) -> Vulnerability | None:
    """Convert one OSV JSON record into a `Vulnerability`.

    Returns ``None`` when the record has no identifier or no affected entry we
    can evaluate — there is nothing useful to store or match against.
    """
    if not isinstance(record, dict):
        return None

    vuln_id = record.get("id")
    if not isinstance(vuln_id, str) or not vuln_id:
        return None

    affected = parse_affected(record.get("affected"))
    if not affected:
        return None

    severity, score, vector = normalize_severity(
        record.get("severity") if isinstance(record.get("severity"), list) else None,
        _qualitative_label(record),
    )

    aliases = tuple(a for a in (record.get("aliases") or []) if isinstance(a, str) and a)

    summary = record.get("summary")
    details = record.get("details")

    return Vulnerability(
        id=vuln_id,
        aliases=aliases,
        summary=summary if isinstance(summary, str) else "",
        details=details if isinstance(details, str) else "",
        severity=severity if isinstance(severity, Severity) else Severity.UNKNOWN,
        cvss_score=score,
        cvss_vector=vector,
        affected=affected,
        references=_extract_references(record.get("references")),
        cwe_ids=_extract_cwe_ids(record),
        # Presence of the field at all means withdrawn; its value is the date.
        withdrawn=bool(record.get("withdrawn")),
        published=record.get("published") if isinstance(record.get("published"), str) else None,
    )
