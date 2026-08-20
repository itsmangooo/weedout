"""EPSS — the probability that a vulnerability will be exploited.

FIRST publishes a score between 0 and 1 for nearly every CVE, refreshed daily:
the modelled chance of exploitation being observed in the next thirty days. It
answers a different question from everything else here, and the difference is
the point.

* **CVSS** says how bad it would be if someone exploited it.
* **KEV** says someone already has.
* **EPSS** says how likely it is that someone will.

Most advisories score close to zero. A handful score above 0.5, and those are
worth knowing about before they reach KEV -- which is the whole appeal, and
also the reason it is off by default.

**It does not move anything into an alert unless you ask.** A probability is
not a fact, the model is retrained, and a score that drifts over a threshold
overnight would wake somebody up for a number that changed rather than for a
vulnerability that did. So EPSS is shown on every finding and gates nothing
until a project sets a threshold deliberately. That was a judgement call and it
is written down here rather than buried in a diff.

Parsing lives here, away from HTTP and the database, so the format can be
tested against a literal.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

__all__ = [
    "EpssEntry",
    "EpssSnapshot",
    "band_label",
    "parse_epss_csv",
]


@dataclass(frozen=True, slots=True)
class EpssEntry:
    cve_id: str
    #: Probability of exploitation in the next 30 days, 0.0 to 1.0.
    score: float
    #: Where this sits against every other scored CVE, 0.0 to 1.0.
    percentile: float

    @property
    def percent(self) -> float:
        return round(self.score * 100, 2)


@dataclass(frozen=True, slots=True)
class EpssSnapshot:
    entries: tuple[EpssEntry, ...] = ()
    #: The day FIRST scored this run, from the header comment.
    scored_on: date | None = None
    model_version: str = ""

    def __len__(self) -> int:
        return len(self.entries)


def parse_epss_csv(text: str) -> EpssSnapshot:
    """Read FIRST's daily CSV.

    The file starts with a comment line carrying the model version and score
    date, then a header, then one row per CVE:

        #model_version:v2025.03.14,score_date:2025-03-14T00:00:00+0000
        cve,epss,percentile
        CVE-1999-0001,0.01234,0.78901

    Malformed rows are skipped rather than failing the batch. This is a
    280,000-row file from a third party, and discarding the whole day's scores
    because one line is short would lose far more than it protects.
    """
    scored_on: date | None = None
    model_version = ""
    entries: list[EpssEntry] = []
    seen: set[str] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith("#"):
            scored_on, model_version = _read_header(line, scored_on, model_version)
            continue

        parts = line.split(",")
        if len(parts) < 3:
            continue

        cve = parts[0].strip().upper()
        if not cve.startswith("CVE-") or cve in seen:
            continue

        try:
            score = float(parts[1])
            percentile = float(parts[2])
        except ValueError:
            # The header row lands here, which is exactly right.
            continue

        # A probability outside [0, 1] is a corrupt row, not a very likely CVE.
        if not (0.0 <= score <= 1.0) or not (0.0 <= percentile <= 1.0):
            continue

        seen.add(cve)
        entries.append(EpssEntry(cve_id=cve, score=score, percentile=percentile))

    return EpssSnapshot(entries=tuple(entries), scored_on=scored_on, model_version=model_version)


def _read_header(line: str, scored_on: date | None, model_version: str):
    for field in line.lstrip("#").split(","):
        key, _, value = field.partition(":")
        key = key.strip().lower()
        if key == "model_version" and not model_version:
            model_version = value.strip()[:32]
        elif key == "score_date" and scored_on is None:
            # score_date carries a full timestamp; the date is the useful part.
            try:
                scored_on = date.fromisoformat(value.strip()[:10])
            except ValueError:
                scored_on = None
    return scored_on, model_version


#: Bands for the interface. Deliberately not named like severities -- "high
#: EPSS" and "high severity" mean different things, and a reader who has to
#: work out which one a word refers to will eventually get it wrong.
_BANDS = (
    (0.50, "Very likely"),
    (0.10, "Likely"),
    (0.01, "Possible"),
)


def band_label(score: float | None) -> str:
    """A phrase for a score, for people who do not read probabilities fluently.

    The number is always shown alongside; this is the gloss, not a replacement.
    """
    if score is None:
        return "Not scored"
    for floor, label in _BANDS:
        if score >= floor:
            return label
    return "Unlikely"
