"""Shared domain vocabulary.

These enums are the contract between the pure core, the ORM models and the
templates. They are plain `str` enums so SQLAlchemy can persist them as native
values and Jinja can compare them to string literals without adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum


class Ecosystem(StrEnum):
    """Package ecosystems we can parse and query OSV for.

    The values match OSV's ecosystem identifiers exactly so they can be sent
    over the wire without a translation table.
    """

    NPM = "npm"
    PYPI = "PyPI"
    GO = "Go"

    @property
    def label(self) -> str:
        return {"npm": "npm", "PyPI": "PyPI", "Go": "Go"}[self.value]


class ManifestKind(StrEnum):
    """Supported manifest file formats."""

    PACKAGE_JSON = "package.json"
    PACKAGE_LOCK_JSON = "package-lock.json"
    REQUIREMENTS_TXT = "requirements.txt"
    GO_MOD = "go.mod"

    @property
    def ecosystem(self) -> Ecosystem:
        return _MANIFEST_ECOSYSTEM[self]

    @property
    def is_lockfile(self) -> bool:
        """Lockfiles pin exact installed versions, so their matches are certain."""
        return self is ManifestKind.PACKAGE_LOCK_JSON


_MANIFEST_ECOSYSTEM: dict[ManifestKind, Ecosystem] = {
    ManifestKind.PACKAGE_JSON: Ecosystem.NPM,
    ManifestKind.PACKAGE_LOCK_JSON: Ecosystem.NPM,
    ManifestKind.REQUIREMENTS_TXT: Ecosystem.PYPI,
    ManifestKind.GO_MOD: Ecosystem.GO,
}


class Reachability(StrEnum):
    """How exposed a dependency is in the deployed application.

    This is the honest, manifest-level definition of "reachable" that Weedout
    can actually support without doing source analysis:

    * ``RUNTIME_DIRECT``     — declared by the project itself and shipped to prod.
    * ``RUNTIME_TRANSITIVE`` — shipped to prod, but pulled in by something else.
    * ``DEV_ONLY``           — build/test tooling that never reaches production.

    It is deliberately NOT a claim about whether the vulnerable function is
    called. See ``docs/reachability.md``.
    """

    RUNTIME_DIRECT = "runtime_direct"
    RUNTIME_TRANSITIVE = "runtime_transitive"
    DEV_ONLY = "dev_only"

    @property
    def ships_to_production(self) -> bool:
        return self is not Reachability.DEV_ONLY

    @property
    def label(self) -> str:
        return {
            "runtime_direct": "Direct runtime dependency",
            "runtime_transitive": "Transitive runtime dependency",
            "dev_only": "Development-only dependency",
        }[self.value]


class Severity(StrEnum):
    """Normalised severity ladder.

    ``UNKNOWN`` is a real, common state — plenty of OSV records carry no CVSS
    vector and no qualitative label — and is treated as strictly less urgent
    than ``LOW`` when triaging.
    """

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    @property
    def label(self) -> str:
        return self.value.capitalize()


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Verdict(StrEnum):
    """Outcome of triaging one (dependency, vulnerability) pair."""

    #: Surfaced to the user as an actionable alert.
    ACTIONABLE = "actionable"
    #: A genuine version match, deliberately not shown. Counted as suppressed noise.
    SUPPRESSED = "suppressed"
    #: Not a match at all — the installed version is outside every affected range.
    NOT_AFFECTED = "not_affected"


class ActionableReason(StrEnum):
    """Why an alert was worth interrupting someone for."""

    EXPLOITED_IN_WILD = "exploited_in_wild"
    CRITICAL_IN_PRODUCTION = "critical_in_production"
    HIGH_SEVERITY_DIRECT = "high_severity_direct"

    @property
    def label(self) -> str:
        return {
            "exploited_in_wild": "Actively exploited (CISA KEV)",
            "critical_in_production": "Critical severity, ships to production",
            "high_severity_direct": "High severity, direct dependency",
        }[self.value]


class SuppressionReason(StrEnum):
    """Why a real version match was filtered out instead of alerted on."""

    WITHDRAWN = "withdrawn"
    DEV_ONLY_DEPENDENCY = "dev_only_dependency"
    TRANSITIVE_NOT_DIRECT = "transitive_not_direct"
    BELOW_SEVERITY_THRESHOLD = "below_severity_threshold"

    @property
    def label(self) -> str:
        return {
            "withdrawn": "Advisory withdrawn by its publisher",
            "dev_only_dependency": "Dev-only dependency — never ships to production",
            "transitive_not_direct": "Transitive dependency, not exploited in the wild",
            "below_severity_threshold": "Below severity threshold and not exploited",
        }[self.value]


class AlertStatus(StrEnum):
    OPEN = "open"
    DISMISSED = "dismissed"
    RESOLVED = "resolved"

    @property
    def label(self) -> str:
        return self.value.capitalize()


class Tier(StrEnum):
    FREE = "free"
    PRO = "pro"

    @property
    def label(self) -> str:
        return self.value.capitalize()


@dataclass(frozen=True, slots=True)
class Dependency:
    """One resolved dependency of a tracked target.

    ``version`` is the version we will actually test against advisory ranges.
    When the manifest pins an exact version (``lodash: "4.17.20"``, ``go.mod``,
    ``foo==1.2.3``) that is the real installed version and ``version_exact`` is
    True. When the manifest only gives a range (``^4.17.20``, ``>=1.2``) we
    resolve the *lowest* version the range permits and set ``version_exact``
    False — the conservative floor, flagged in the UI so nobody mistakes it for
    a lockfile-grade fact.
    """

    ecosystem: Ecosystem
    name: str
    version: str
    version_spec: str
    reachability: Reachability
    version_exact: bool = True

    @property
    def key(self) -> tuple[str, str, str]:
        return (str(self.ecosystem), self.name, self.version)


@dataclass(frozen=True, slots=True)
class AffectedRange:
    """A half-open ``[introduced, fixed)`` interval from an OSV advisory."""

    introduced: str | None
    fixed: str | None
    last_affected: str | None = None


@dataclass(frozen=True, slots=True)
class AffectedPackage:
    """The subset of an OSV ``affected`` entry that drives matching."""

    ecosystem: Ecosystem
    name: str
    ranges: tuple[AffectedRange, ...] = ()
    versions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Vulnerability:
    """A normalised advisory, independent of which feed produced it."""

    id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    details: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected: tuple[AffectedPackage, ...] = ()
    references: tuple[str, ...] = ()
    #: CWE identifiers, e.g. ("CWE-1321",). Classification of the weakness,
    #: not its severity — useful for grouping advisories by kind.
    cwe_ids: tuple[str, ...] = ()
    withdrawn: bool = False
    published: str | None = None

    @property
    def cve_ids(self) -> tuple[str, ...]:
        ids = [a for a in self.aliases if a.upper().startswith("CVE-")]
        if self.id.upper().startswith("CVE-"):
            ids.insert(0, self.id)
        # Preserve order, drop duplicates.
        return tuple(dict.fromkeys(i.upper() for i in ids))

    @property
    def primary_cve(self) -> str | None:
        cves = self.cve_ids
        return cves[0] if cves else None


@dataclass(frozen=True, slots=True)
class KevEntry:
    """One row of the CISA Known Exploited Vulnerabilities catalog."""

    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    short_description: str = ""
    required_action: str = ""
    date_added: date | None = None
    due_date: date | None = None
    known_ransomware_use: bool = False


@dataclass(frozen=True, slots=True)
class MatchDecision:
    """The triage result for one (dependency, vulnerability) pair."""

    dependency: Dependency
    vulnerability: Vulnerability
    verdict: Verdict
    severity: Severity
    kev: bool
    fixed_version: str | None = None
    actionable_reason: ActionableReason | None = None
    suppression_reason: SuppressionReason | None = None

    @property
    def is_actionable(self) -> bool:
        return self.verdict is Verdict.ACTIONABLE

    @property
    def is_suppressed(self) -> bool:
        return self.verdict is Verdict.SUPPRESSED


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one scan of one target produced.

    ``suppressed`` is kept rather than discarded: the count of noise Weedout
    did *not* interrupt you with is the product's whole pitch, and users can
    open the list to audit the filter.
    """

    actionable: tuple[MatchDecision, ...] = ()
    suppressed: tuple[MatchDecision, ...] = ()
    dependencies_scanned: int = 0
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def actionable_count(self) -> int:
        return len(self.actionable)

    @property
    def suppressed_count(self) -> int:
        return len(self.suppressed)
