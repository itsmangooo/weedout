"""Validate shared parity fixtures against the legacy Python detection core.

This intentionally imports only pure ``app.core`` modules: no database, web,
account, or project state is involved. Delete it only when the Python detector
is retired after all important fixtures pass in Go.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.core.manifests import parse_manifest
from app.core.matching import MatchPolicy, normalise_ids, normalise_packages, triage_all
from app.core.reachability import SourceBundle, SourceFile, analyze_node_reachability
from app.core.types import (
    AffectedPackage,
    AffectedRange,
    Ecosystem,
    KevEntry,
    ManifestKind,
    Severity,
    Vulnerability,
)


def validate(path: Path) -> None:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    request = fixture["request"]
    dependencies = []
    for item in request["manifests"]:
        dependencies.extend(
            parse_manifest(ManifestKind(item["kind"]), item["content"]).dependencies
        )
    if request.get("sources"):
        dependencies, _ = analyze_node_reachability(
            dependencies,
            SourceBundle(
                files=tuple(SourceFile(**source) for source in request["sources"]), complete=True
            ),
        )

    advisories = []
    for raw in request["advisories"]["inline"]:
        advisories.append(
            Vulnerability(
                id=raw["id"],
                aliases=tuple(raw.get("aliases", ())),
                summary=raw.get("summary", ""),
                severity=Severity(raw.get("severity", "unknown")),
                affected=tuple(
                    AffectedPackage(
                        ecosystem=Ecosystem(affected["ecosystem"]),
                        name=affected["name"],
                        ranges=tuple(
                            AffectedRange(**interval) for interval in affected.get("ranges", ())
                        ),
                        versions=tuple(affected.get("versions", ())),
                    )
                    for affected in raw["affected"]
                ),
            )
        )

    by_dependency = {
        dependency.key: tuple(
            advisory
            for advisory in advisories
            if any(
                affected.ecosystem == dependency.ecosystem
                and affected.name.lower() == dependency.name.lower()
                for affected in advisory.affected
            )
        )
        for dependency in dependencies
    }
    kev = {
        alias: KevEntry(cve_id=alias)
        for raw in request["advisories"]["inline"]
        if raw.get("known_exploited")
        for alias in raw.get("aliases", ())
        if alias.startswith("CVE-")
    }
    epss = {
        alias: (raw["epss_score"], raw.get("epss_percentile", 0.0))
        for raw in request["advisories"]["inline"]
        if raw.get("epss_score") is not None
        for alias in raw.get("aliases", ())
        if alias.startswith("CVE-")
    }
    rules = request.get("rules", {})
    ignored = rules.get("ignored", [])
    policy = MatchPolicy(
        always_alert_on_kev=rules.get("always_alert_on_kev", True),
        direct_threshold=Severity(rules.get("direct_threshold", "high")),
        transitive_threshold=Severity(rules.get("transitive_threshold", "critical")),
        dev_threshold=Severity(rules["dev_threshold"]) if rules.get("dev_threshold") else None,
        epss_threshold=rules.get("epss_alert_above"),
        max_depth=rules.get("max_depth"),
        ignored_ids=normalise_ids(
            entry["advisory_id"] for entry in ignored if entry.get("advisory_id")
        ),
        ignored_packages=normalise_packages(
            entry["package"] for entry in ignored if entry.get("package")
        ),
    )
    result = triage_all(dependencies, by_dependency, kev, policy, epss_index=epss)

    expected = fixture["expected"]
    actual_dependencies = sorted(
        f"{dependency.name}@{dependency.version}" for dependency in dependencies
    )
    assert actual_dependencies == expected["dependencies"]
    actual = [
        {
            "id": f"{decision.vulnerability.id}:{decision.dependency.ecosystem}:{decision.dependency.name}:{decision.dependency.version}",
            "verdict": str(decision.verdict),
            "fixed_version": decision.fixed_version,
            "known_exploited": decision.kev,
            "reachability": str(decision.dependency.automated_reachability),
        }
        for decision in (*result.actionable, *result.suppressed)
    ]
    for expected_finding, actual_finding in zip(expected["findings"], actual, strict=True):
        normalized_expected = dict(expected_finding)
        if normalized_expected.get("verdict") == "filtered":
            normalized_expected["verdict"] = "suppressed"
        for key in normalized_expected:
            assert actual_finding[key] == normalized_expected[key], (
                key,
                actual_finding,
                normalized_expected,
            )


if __name__ == "__main__":
    root = Path(__file__).parents[2]
    for fixture_path in sorted((root / "engine/testdata/parity").glob("*.json")):
        validate(fixture_path)
        print(f"legacy parity: {fixture_path.name}: ok")
