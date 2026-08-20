"""Turn a triage decision into plain language.

The alert detail view exists to answer three questions a developer actually has
— *what can go wrong*, *why am I seeing this and not the other 200 advisories*,
and *what do I type to fix it* — rather than to display a CVSS vector and leave
the reader to interpret it. These are pure string functions so the wording can
be tested and changed without touching a template.
"""

from __future__ import annotations

import re

from app.core.types import (
    ActionableReason,
    KevEntry,
    MatchDecision,
    Reachability,
    Severity,
    SuppressionReason,
)

__all__ = ["explain_decision", "fix_command", "risk_sentence", "why_surfaced"]


_SEVERITY_PHRASE = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high-severity",
    Severity.MEDIUM: "moderate",
    Severity.LOW: "low-severity",
    Severity.UNKNOWN: "unrated",
}


def risk_sentence(decision: MatchDecision) -> str:
    """One sentence on what the vulnerability actually is."""
    summary = (decision.vulnerability.summary or "").strip()
    if summary:
        # Advisory summaries are already single sentences; just normalise them.
        summary = re.sub(r"\s+", " ", summary).rstrip(".")
        return f"{summary}."

    if decision.vulnerability.is_malicious:
        return f"{decision.dependency.name} {decision.dependency.version} was published as malware."

    severity = _SEVERITY_PHRASE[decision.severity]
    return (
        f"A {severity} vulnerability was published for "
        f"{decision.dependency.name} {decision.dependency.version}."
    )


def why_surfaced(decision: MatchDecision, kev_entry: KevEntry | None = None) -> str:
    """Explain the triage decision in the user's terms.

    This is the sentence that justifies the interruption. For suppressed matches
    it justifies the silence instead.
    """
    dep = decision.dependency

    if decision.is_suppressed:
        return _explain_suppression(decision)

    if decision.actionable_reason is ActionableReason.MALICIOUS_PACKAGE:
        return (
            f"{dep.name} is not a package with a vulnerability in it — the package "
            "itself is malicious. It was published to the registry to run code on "
            "machines that install it, which includes developer laptops and CI "
            "runners as well as anything you ship. There is no version to upgrade "
            "to; remove it and treat any credential that machine could reach as "
            "exposed."
        )

    if decision.actionable_reason is ActionableReason.EXPLOITED_IN_WILD:
        base = (
            "CISA lists this vulnerability as being actively exploited in the wild, "
            "so it is not theoretical — attacks using it have been observed."
        )
        if kev_entry and kev_entry.known_ransomware_use:
            base += " It has been used in known ransomware campaigns."
        if kev_entry and kev_entry.due_date:
            base += (
                f" US federal agencies were required to remediate it by "
                f"{kev_entry.due_date.isoformat()}."
            )
        return base

    if decision.actionable_reason is ActionableReason.CRITICAL_IN_PRODUCTION:
        where = (
            "a package your project depends on directly"
            if dep.reachability is Reachability.RUNTIME_DIRECT
            else "a transitive dependency, pulled in by something else you use"
        )
        return (
            f"This is rated critical and affects {where}, which ships to production. "
            "Critical findings in production code clear the bar even when there is no "
            "evidence of exploitation yet."
        )

    if decision.actionable_reason is ActionableReason.HIGH_SEVERITY_DIRECT:
        return (
            f"This is rated high severity in {dep.name}, which your project depends on "
            "directly and which runs in production. Direct dependencies are yours to "
            "upgrade, so this one is actionable today."
        )

    return "This match cleared the alerting threshold."


def _explain_suppression(decision: MatchDecision) -> str:
    reason = decision.suppression_reason
    dep = decision.dependency

    if reason is SuppressionReason.WITHDRAWN:
        return (
            "The publisher has withdrawn this advisory, usually because it was filed "
            "in error or superseded. No action is needed."
        )

    if reason is SuppressionReason.DEV_ONLY_DEPENDENCY:
        return (
            f"{dep.name} is a development-only dependency — it is used for building or "
            "testing and is never shipped to production, so an attacker has no path to "
            "it in your running application. It is not on CISA's exploited list either."
        )

    if reason is SuppressionReason.TRANSITIVE_NOT_DIRECT:
        return (
            f"{dep.name} is pulled in indirectly by another package rather than declared "
            "by your project, and there is no evidence of exploitation in the wild. "
            "Upgrading it usually means waiting on the package that depends on it, so "
            "this is worth knowing but not worth waking anyone up for."
        )

    if reason is SuppressionReason.BELOW_SEVERITY_THRESHOLD:
        severity = _SEVERITY_PHRASE[decision.severity]
        return (
            f"This is rated {severity} and is not on CISA's actively-exploited list. "
            "The overwhelming majority of advisories in this category are never "
            "exploited against anyone, so it is recorded here rather than alerted on."
        )

    return "This match did not clear the alerting threshold."


def fix_command(decision: MatchDecision) -> str | None:
    """The literal command to run, when the advisory names a fixed version."""
    dep = decision.dependency
    fixed = decision.fixed_version
    if not fixed:
        return None

    match dep.ecosystem.value:
        case "npm":
            return f"npm install {dep.name}@{fixed}"
        case "PyPI":
            return f"pip install --upgrade '{dep.name}>={fixed}'"
        case "Go":
            return f"go get {dep.name}@v{fixed.lstrip('v')}"
        case _:
            return None


def fix_sentence(decision: MatchDecision) -> str:
    """What to do about it, in prose."""
    dep = decision.dependency

    # Never "upgrade": there is no good version of a malicious package, and a
    # later release of one is just newer malware.
    if decision.actionable_reason is ActionableReason.MALICIOUS_PACKAGE:
        return (
            f"Remove {dep.name} from your dependencies and reinstall from a clean "
            "lockfile. Then rotate anything the install could have read — tokens in "
            "the environment, SSH keys, and any credential your CI runner holds. "
            "Upgrading is not a fix here; there is no safe version of this package."
        )

    if decision.fixed_version:
        base = (
            f"Upgrade {dep.name} from {dep.version} to {decision.fixed_version} or later. "
            f"That release contains the fix."
        )
        if dep.reachability is Reachability.RUNTIME_TRANSITIVE:
            base += (
                " Because this package is a transitive dependency, you may need to bump "
                "whichever direct dependency pulls it in, or add an override/resolution."
            )
        return base

    return (
        f"No fixed version has been published for {dep.name} yet. Check the advisory "
        "references for a workaround, or consider whether the affected functionality "
        "is one you can avoid using."
    )


def confidence_note(decision: MatchDecision) -> str | None:
    """Warn when the matched version was inferred from a range, not observed.

    Without this, a user with `^4.17.4` in package.json and `4.17.21` actually
    installed would see a confident-looking alert about a version they do not
    have. Saying so plainly is the difference between a tool people trust and
    one they stop reading.
    """
    dep = decision.dependency
    if dep.version_exact:
        return None
    return (
        f"Your manifest requests {dep.version_spec!r}, which does not pin an exact "
        f"version. Weedout assumed the lowest version that range allows "
        f"({dep.version}). Upload your lockfile for an exact answer — the version you "
        f"actually have installed may already be patched."
    )


def explain_decision(
    decision: MatchDecision, kev_entry: KevEntry | None = None
) -> dict[str, str | None]:
    """Everything the detail view needs, as plain text."""
    return {
        "risk": risk_sentence(decision),
        "why": why_surfaced(decision, kev_entry),
        "fix": fix_sentence(decision),
        "command": fix_command(decision),
        "confidence": confidence_note(decision),
    }
