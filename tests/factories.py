"""Small builders for core dataclasses, so tests state only what they exercise."""

from __future__ import annotations

from app.core.types import (
    AffectedPackage,
    AffectedRange,
    Dependency,
    Ecosystem,
    KevEntry,
    Reachability,
    Severity,
    Vulnerability,
)


def dep(
    name: str = "lodash",
    version: str = "4.17.15",
    ecosystem: Ecosystem = Ecosystem.NPM,
    reachability: Reachability = Reachability.RUNTIME_DIRECT,
    version_exact: bool = True,
    version_spec: str | None = None,
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        version_spec=version_spec if version_spec is not None else version,
        reachability=reachability,
        version_exact=version_exact,
    )


def affected(
    name: str = "lodash",
    ecosystem: Ecosystem = Ecosystem.NPM,
    introduced: str | None = "0",
    fixed: str | None = "4.17.21",
    last_affected: str | None = None,
    versions: tuple[str, ...] = (),
) -> AffectedPackage:
    ranges: tuple[AffectedRange, ...] = ()
    if introduced is not None or fixed is not None or last_affected is not None:
        ranges = (AffectedRange(introduced=introduced, fixed=fixed, last_affected=last_affected),)
    return AffectedPackage(ecosystem=ecosystem, name=name, ranges=ranges, versions=versions)


def vuln(
    vuln_id: str = "GHSA-test-0001",
    severity: Severity = Severity.HIGH,
    aliases: tuple[str, ...] = ("CVE-2020-8203",),
    affected_packages: tuple[AffectedPackage, ...] | None = None,
    withdrawn: bool = False,
    summary: str = "Prototype pollution in lodash",
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        aliases=aliases,
        summary=summary,
        details="",
        severity=severity,
        affected=affected_packages if affected_packages is not None else (affected(),),
        withdrawn=withdrawn,
    )


def kev(cve_id: str = "CVE-2020-8203", ransomware: bool = False) -> KevEntry:
    return KevEntry(
        cve_id=cve_id,
        vendor_project="Example",
        product="lodash",
        vulnerability_name="Prototype pollution",
        short_description="Attacker-controlled prototype pollution.",
        required_action="Apply updates.",
        known_ransomware_use=ransomware,
    )
