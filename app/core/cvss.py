"""CVSS vector scoring and severity normalisation.

Advisories describe severity in at least four incompatible ways: a CVSS v3
vector string, a CVSS v4 vector string, a bare numeric score, or a qualitative
label whose vocabulary differs per publisher (GitHub says ``MODERATE``, Red Hat
says ``IMPORTANT``, everyone else says ``MEDIUM``/``HIGH``). Triage needs one
comparable ladder, so everything is funnelled into `Severity` here.

The CVSS v3.1 base-score formula is implemented in full because severity drives
whether a user gets interrupted, and a wrong score is a wrong decision. CVSS v4
scoring depends on a 270-entry MacroVector lookup table that is not worth
vendoring; v4 vectors are parsed only for their qualitative hints, and we fall
back to another source when one is available.
"""

from __future__ import annotations

import math
import re

from app.core.types import Severity

__all__ = ["Severity", "normalize_severity", "score_cvss_vector", "score_to_severity"]

# --- CVSS v3.x base metric weights (spec section 8.1) ----------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

_METRIC_RE = re.compile(r"([A-Z]+):([A-Z]+)")


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A `Roundup`: round up to one decimal place.

    Implemented on integers as the spec requires — plain `math.ceil(x * 10) / 10`
    misrounds values like 8.6 that are not exactly representable in binary
    floating point.
    """
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (math.floor(scaled / 10_000) + 1) / 10


def score_cvss_vector(vector: str) -> float | None:
    """Compute the CVSS v3.0/v3.1 base score for ``vector``.

    Returns ``None`` for vectors that are not v3.x, or that are missing a
    required base metric — a partial vector cannot be scored, and inventing a
    number would be worse than admitting we do not have one.
    """
    if not vector:
        return None

    text = vector.strip().upper()
    if not text.startswith("CVSS:3"):
        return None

    metrics = dict(_METRIC_RE.findall(text))
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        conf = _CIA[metrics["C"]]
        integ = _CIA[metrics["I"]]
        avail = _CIA[metrics["A"]]
        scope_changed = metrics["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
    except KeyError:
        return None

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08

    return _roundup(min(combined, 10.0))


def score_to_severity(score: float | None) -> Severity:
    """Map a CVSS base score onto the standard qualitative bands."""
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.UNKNOWN


#: Publisher-specific severity vocabularies, folded into our ladder.
_LABELS: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "IMPORTANT": Severity.HIGH,  # Red Hat
    "MEDIUM": Severity.MEDIUM,
    "MODERATE": Severity.MEDIUM,  # GitHub Advisory Database
    "LOW": Severity.LOW,
    "MINOR": Severity.LOW,
    "NEGLIGIBLE": Severity.LOW,
    "NONE": Severity.UNKNOWN,
    "UNKNOWN": Severity.UNKNOWN,
    "UNSPECIFIED": Severity.UNKNOWN,
}


def label_to_severity(label: str | None) -> Severity:
    if not label:
        return Severity.UNKNOWN
    return _LABELS.get(label.strip().upper(), Severity.UNKNOWN)


def normalize_severity(
    severity_entries: list[dict] | None = None,
    qualitative_label: str | None = None,
) -> tuple[Severity, float | None, str | None]:
    """Reduce an OSV record's severity information to (severity, score, vector).

    ``severity_entries`` is OSV's ``severity`` array, e.g.
    ``[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/..."}]``.
    ``qualitative_label`` is the ``database_specific.severity`` string, which is
    often the only signal present on GitHub-sourced records.

    A computed CVSS v3 score wins, because it is precise and comparable. A
    qualitative label is used when no scorable vector exists. When both are
    absent the result is ``UNKNOWN``, which triage treats as below every
    threshold — such an advisory only surfaces if it is KEV-listed.
    """
    best_score: float | None = None
    best_vector: str | None = None
    fallback_vector: str | None = None

    for entry in severity_entries or []:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("score")
        if not isinstance(raw, str) or not raw:
            continue

        if raw.upper().startswith("CVSS:3"):
            computed = score_cvss_vector(raw)
            if computed is not None and (best_score is None or computed > best_score):
                best_score, best_vector = computed, raw
            continue

        if raw.upper().startswith("CVSS:"):
            # v2/v4 vector: keep it for display, but we do not score it.
            fallback_vector = fallback_vector or raw
            continue

        # Some feeds put a bare numeric score in this field.
        try:
            numeric = float(raw)
        except ValueError:
            continue
        if 0.0 <= numeric <= 10.0 and (best_score is None or numeric > best_score):
            best_score, best_vector = numeric, None

    if best_score is not None:
        return score_to_severity(best_score), best_score, best_vector or fallback_vector

    return label_to_severity(qualitative_label), None, fallback_vector
