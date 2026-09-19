"""Validate shared parity fixtures against the legacy Python detection core.

This intentionally imports only pure ``app.core`` modules: no database, web,
account, or project state is involved. Delete it only when the Python detector
is retired after all important fixtures pass in Go.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.core.manifests import parse_manifest
from app.core.matching import triage_all
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
    result = triage_all(dependencies, by_dependency, kev)

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
        }
        for decision in (*result.actionable, *result.suppressed)
    ]
    for expected_finding, actual_finding in zip(expected["findings"], actual, strict=True):
        for key in ("id", "verdict", "fixed_version", "known_exploited"):
            assert actual_finding[key] == expected_finding[key], (
                key,
                actual_finding,
                expected_finding,
            )


if __name__ == "__main__":
    root = Path(__file__).parents[2]
    for fixture_path in sorted((root / "engine/testdata/parity").glob("*.json")):
        validate(fixture_path)
        print(f"legacy parity: {fixture_path.name}: ok")
