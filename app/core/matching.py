"""CVE triage: decide what is worth interrupting someone for.

This is the product. Every other module exists to feed this one.

The premise is that the overwhelming majority of advisories touching a project's
dependency tree will never be exploited against that project, and that a tool
which reports all of them trains its users to ignore it. So a match is only
promoted to an alert when at least one of these holds:

1. **It is being exploited right now.** The CVE is in CISA's Known Exploited
   Vulnerabilities catalog. This overrides everything else — including severity
   and dev-only scope, because "we only use it in CI" is thin comfort against a
   vulnerability with working public exploitation.
2. **It is critical and it ships.** Critical severity in code that reaches
   production.
3. **It is high severity and it is yours.** High severity in a dependency the
   project declared itself, rather than something four levels down a tree.

Everything else is recorded as suppressed, with the reason attached. Suppressed
matches are kept, counted, and browsable — the number of alerts Weedout did
*not* send is the evidence that the filter is working, and users must be able
to audit it rather than take it on faith.

All functions here are pure. They take dataclasses and return dataclasses, so
the policy can be tested exhaustively without a database, an HTTP client, or a
web request.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from app.core.types import (
    ActionableReason,
    Dependency,
    KevEntry,
    MatchDecision,
    Reachability,
    ScanResult,
    Severity,
    SuppressionReason,
    Verdict,
    Vulnerability,
)
from app.core.versions import first_fixed_version, version_matches

__all__ = ["DEFAULT_POLICY", "MatchPolicy", "normalise_ids", "triage", "triage_all"]


@dataclass(frozen=True, slots=True)
class MatchPolicy:
    """Tunable thresholds for triage.

    Kept as data rather than hardcoded branches so the policy can be varied per
    user or per tier later (a paid "show me everything" toggle, say) without
    rewriting the decision logic or invalidating its tests.
    """

    #: KEV-listed CVEs always alert, whatever their severity or scope.
    always_alert_on_kev: bool = True

    #: Minimum severity to alert on for a dependency the project declares itself.
    direct_threshold: Severity = Severity.HIGH

    #: Minimum severity to alert on for a dependency pulled in indirectly.
    #: Higher than `direct_threshold` on purpose: transitive advisories are the
    #: single largest source of unactionable noise.
    transitive_threshold: Severity = Severity.CRITICAL

    #: Whether non-KEV findings in dev-only dependencies can alert at all.
    #:
    #: The coarse switch. `dev_threshold` is the precise one and wins when set;
    #: this remains the answer when nobody has expressed a preference.
    alert_on_dev_dependencies: bool = False

    #: Severity floor for a dependency that never reaches production — a
    #: linter, a test runner, a build plugin.
    #:
    #: None means "use `alert_on_dev_dependencies`", which is what every
    #: project starts with. Setting it is the more honest instrument: a
    #: critical in a linter is not a critical in a web framework, but it is
    #: not nothing either, and switching dev findings off entirely hides a
    #: genuinely compromised build tool.
    #:
    #: Only reachable on Pro, and only meaningful where the manifest says
    #: which dependencies are dev-only — npm's devDependencies, Maven's
    #: `test` and `provided` scopes, Gradle's test classpaths. Cargo.lock does
    #: not record it, so nothing there is ever classified dev-only.
    dev_threshold: Severity | None = None

    #: How far down the dependency tree to look. `None` means all the way.
    #:
    #: 0 would be direct dependencies only; 1 adds their dependencies. This is
    #: a *product* limit, set from the owner's plan, and it is applied by
    #: excluding packages before they are looked up rather than by suppressing
    #: what it finds. The difference matters: a suppressed finding is one we
    #: examined and set aside, and reporting something as filtered when it was
    #: never checked would be a lie in the direction that makes the product
    #: look better.
    max_depth: int | None = None

    #: Gate on EPSS above this probability, or None to gate on nothing.
    #:
    #: Off by default, and that is a decision rather than an oversight. EPSS is
    #: a model output that is retrained and re-scored daily; a finding drifting
    #: over a threshold overnight would interrupt somebody because a number
    #: moved, not because a vulnerability did. Shown on every finding, gating
    #: only where a project has asked for it.
    epss_threshold: float | None = None

    #: CVE and advisory ids this project has chosen not to hear about.
    #:
    #: Compared case-insensitively; `normalise_ids` is what callers should use
    #: to build it. Matched against every alias an advisory carries, so
    #: ignoring CVE-2021-23337 also silences the GHSA that aliases it -- a rule
    #: that only worked if you happened to name the same identifier the feed
    #: did would be a rule that quietly stopped working.
    ignored_ids: frozenset[str] = frozenset()

    def within_depth(self, dependency: Dependency) -> bool:
        return self.max_depth is None or dependency.depth <= self.max_depth

    def ignores(self, vulnerability: Vulnerability) -> bool:
        if not self.ignored_ids:
            return False
        candidates = {vulnerability.id, *vulnerability.aliases, *vulnerability.cve_ids}
        return any(candidate.upper() in self.ignored_ids for candidate in candidates)

    def threshold_for(self, reachability: Reachability) -> Severity:
        if reachability is Reachability.RUNTIME_DIRECT:
            return self.direct_threshold
        if reachability is Reachability.DEV_ONLY and self.dev_threshold is not None:
            return self.dev_threshold
        return self.transitive_threshold


def normalise_ids(ids: object) -> frozenset[str]:
    """Upper-case, de-duplicated, whitespace-free advisory identifiers.

    Callers hand this whatever came out of a database column or a policy file,
    so it tolerates None and non-strings rather than making every caller guard.
    """
    if not ids:
        return frozenset()
    cleaned = set()
    for value in ids:  # type: ignore[union-attr]
        if isinstance(value, str) and value.strip():
            cleaned.add(value.strip().upper())
    return frozenset(cleaned)


DEFAULT_POLICY = MatchPolicy()


def triage(
    dependency: Dependency,
    vulnerability: Vulnerability,
    kev_index: dict[str, KevEntry] | set[str] | None = None,
    policy: MatchPolicy = DEFAULT_POLICY,
    epss_index: dict[str, tuple[float, float]] | None = None,
) -> MatchDecision:
    """Decide the fate of one (dependency, vulnerability) pair.

    ``kev_index`` may be a mapping of CVE ID to `KevEntry` or a bare set of CVE
    IDs; only membership is used here.

    The version check is repeated locally even though OSV was queried with a
    version, because the version we hold may be an assumed floor derived from a
    range rather than something OSV was asked about, and because re-deriving the
    verdict from the advisory data keeps this decision reproducible offline.
    """
    kev_ids = _kev_id_set(kev_index)
    is_kev = any(cve in kev_ids for cve in vulnerability.cve_ids)

    affected_entry = _matching_affected(dependency, vulnerability)
    if affected_entry is None:
        return MatchDecision(
            dependency=dependency,
            vulnerability=vulnerability,
            verdict=Verdict.NOT_AFFECTED,
            severity=vulnerability.severity,
            kev=is_kev,
        )

    fixed_version = first_fixed_version(dependency.ecosystem, dependency.version, affected_entry)
    epss_score, epss_percentile = _epss_for(vulnerability, epss_index)
    base = MatchDecision(
        dependency=dependency,
        vulnerability=vulnerability,
        verdict=Verdict.SUPPRESSED,
        severity=vulnerability.severity,
        kev=is_kev,
        fixed_version=fixed_version,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
    )

    # A withdrawn advisory is retracted by its own publisher. Never alert on it,
    # not even when KEV-listed, or we would be acting on data known to be wrong.
    if vulnerability.withdrawn:
        return replace(base, suppression_reason=SuppressionReason.WITHDRAWN)

    # Before everything except withdrawal.
    #
    # A malicious-package advisory carries no CVSS score, because there is
    # nothing to score: the package is malware and the fix is to remove it. Run
    # through the severity ladder below it lands as UNKNOWN, falls under every
    # threshold, and gets filed as "below severity threshold and not exploited"
    # -- which is how a product whose entire pitch is telling you what matters
    # would file a package that steals your environment variables as noise.
    #
    # Not gated on reachability either. Malware in a dev-only dependency runs
    # on developer machines and in CI, which is where the credentials are.
    #
    # And not silenceable by a local rule, for the same reason a KEV listing is
    # not: an ignore is a judgement about a risk, and this is not the risk it
    # was a judgement about.
    if vulnerability.is_malicious:
        return replace(
            base,
            verdict=Verdict.ACTIONABLE,
            actionable_reason=ActionableReason.MALICIOUS_PACKAGE,
            ignore_overridden=policy.ignores(vulnerability),
        )

    if is_kev and policy.always_alert_on_kev:
        # Deliberately before the ignore check. An ignore rule is a judgement
        # about a risk, made at a moment in time; a KEV listing is new
        # information about that same risk, so the judgement is out of date
        # rather than binding. Flagged, not silent -- the person who wrote the
        # rule needs to see that it was set aside and why.
        return replace(
            base,
            verdict=Verdict.ACTIONABLE,
            actionable_reason=ActionableReason.EXPLOITED_IN_WILD,
            ignore_overridden=policy.ignores(vulnerability),
        )

    if policy.ignores(vulnerability):
        # Filed, not deleted. It stays on the Filtered tab with the rule named
        # as the reason, so "what am I not being told about?" has an answer.
        return replace(base, suppression_reason=SuppressionReason.IGNORED_BY_RULE)

    # Only where the project asked. See MatchPolicy.epss_threshold for why this
    # is not on by default.
    if (
        policy.epss_threshold is not None
        and epss_score is not None
        and epss_score >= policy.epss_threshold
    ):
        return replace(
            base,
            verdict=Verdict.ACTIONABLE,
            actionable_reason=ActionableReason.LIKELY_TO_BE_EXPLOITED,
        )

    reachability = dependency.reachability

    if not reachability.ships_to_production:
        # A floor of its own, where the project set one: judged like anything
        # else, just held to a higher bar. Without one, the coarse switch
        # decides — and off means every dev finding is filed rather than
        # raised.
        if policy.dev_threshold is None and not policy.alert_on_dev_dependencies:
            return replace(base, suppression_reason=SuppressionReason.DEV_ONLY_DEPENDENCY)
        if policy.dev_threshold is not None and vulnerability.severity < policy.dev_threshold:
            # Below the dev floor specifically, which is a different sentence
            # from "below the production floor" and a different one again from
            # "we do not report dev dependencies".
            return replace(base, suppression_reason=SuppressionReason.DEV_ONLY_DEPENDENCY)

    threshold = policy.threshold_for(reachability)
    if vulnerability.severity >= threshold:
        if reachability is Reachability.RUNTIME_DIRECT:
            reason = (
                ActionableReason.CRITICAL_IN_PRODUCTION
                if vulnerability.severity is Severity.CRITICAL
                else ActionableReason.HIGH_SEVERITY_DIRECT
            )
        else:
            reason = ActionableReason.CRITICAL_IN_PRODUCTION
        return replace(base, verdict=Verdict.ACTIONABLE, actionable_reason=reason)

    # Below threshold. Distinguish "not severe enough" from "severe enough for a
    # direct dependency, but this one is buried in the tree" — the second is the
    # more common case and the more useful explanation.
    if (
        reachability is Reachability.RUNTIME_TRANSITIVE
        and vulnerability.severity >= policy.direct_threshold
    ):
        return replace(base, suppression_reason=SuppressionReason.TRANSITIVE_NOT_DIRECT)

    return replace(base, suppression_reason=SuppressionReason.BELOW_SEVERITY_THRESHOLD)


def _epss_for(
    vulnerability: Vulnerability, index: dict[str, tuple[float, float]] | None
) -> tuple[float | None, float | None]:
    """The highest EPSS among this advisory's CVEs.

    An advisory can alias several. Taking the highest rather than the first is
    the conservative reading: if any of the vulnerabilities it describes is
    likely to be exploited, the advisory is.
    """
    if not index:
        return None, None
    best: tuple[float, float] | None = None
    for cve in vulnerability.cve_ids:
        found = index.get(cve.upper())
        if found and (best is None or found[0] > best[0]):
            best = found
    return best if best else (None, None)


def triage_all(
    dependencies: list[Dependency],
    vulnerabilities_by_dependency: dict[tuple[str, str, str], list[Vulnerability]],
    kev_index: dict[str, KevEntry] | set[str] | None = None,
    policy: MatchPolicy = DEFAULT_POLICY,
    errors: tuple[str, ...] = (),
    epss_index: dict[str, tuple[float, float]] | None = None,
) -> ScanResult:
    """Triage every dependency against its candidate advisories.

    ``vulnerabilities_by_dependency`` is keyed by ``Dependency.key``. Results are
    ordered most urgent first so the caller can render them directly.
    """
    actionable: list[MatchDecision] = []
    suppressed: list[MatchDecision] = []
    unreached = 0

    for dependency in dependencies:
        # Out of the plan's reach. Skipped before the lookup rather than
        # suppressed after it: suppressed means "we looked and set it aside",
        # and counting an unexamined package as filtered would overstate the
        # work in the direction that flatters the product.
        if not policy.within_depth(dependency):
            unreached += 1
            continue

        for vulnerability in vulnerabilities_by_dependency.get(dependency.key, []):
            decision = triage(dependency, vulnerability, kev_index, policy, epss_index)
            if decision.verdict is Verdict.ACTIONABLE:
                actionable.append(decision)
            elif decision.verdict is Verdict.SUPPRESSED:
                suppressed.append(decision)

    return ScanResult(
        actionable=tuple(sorted(actionable, key=_urgency_key)),
        suppressed=tuple(sorted(suppressed, key=_urgency_key)),
        # What was actually examined, not what was parsed.
        dependencies_scanned=len(dependencies) - unreached,
        unreached_by_depth=unreached,
        errors=errors,
    )


def _urgency_key(decision: MatchDecision) -> tuple:
    """Sort key: exploited first, then severity, then package name.

    Negated so that ascending sort yields most-urgent-first.
    """
    return (
        0 if decision.kev else 1,
        -decision.severity.rank,
        decision.dependency.name.lower(),
        decision.vulnerability.id,
    )


def _kev_id_set(kev_index: dict[str, KevEntry] | set[str] | None) -> set[str]:
    if not kev_index:
        return set()
    if isinstance(kev_index, dict):
        return {k.upper() for k in kev_index}
    return {k.upper() for k in kev_index}


def _matching_affected(dependency: Dependency, vulnerability: Vulnerability):
    """Find the advisory entry that covers this dependency's version, if any."""
    name = dependency.name.lower()
    for affected in vulnerability.affected:
        if affected.ecosystem is not dependency.ecosystem:
            continue
        if affected.name.lower() != name:
            continue
        if version_matches(dependency.ecosystem, dependency.version, affected):
            return affected
    return None


def summarize(result: ScanResult) -> dict[str, int]:
    """Headline counts for the dashboard, including the noise-suppressed figure."""
    return {
        "dependencies": result.dependencies_scanned,
        "actionable": result.actionable_count,
        "suppressed": result.suppressed_count,
        "exploited": sum(1 for d in result.actionable if d.kev),
        "critical": sum(1 for d in result.actionable if d.severity is Severity.CRITICAL),
    }
