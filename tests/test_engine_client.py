from app.core.matching import DEFAULT_POLICY, triage_all
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
from app.services.engine_client import _differences, _request


def fixture():
    dependency = Dependency(
        ecosystem=Ecosystem.NPM,
        name="lodash",
        version="4.17.20",
        version_spec="4.17.20",
        reachability=Reachability.RUNTIME_DIRECT,
    )
    vulnerability = Vulnerability(
        id="GHSA-35JH-R3H4-6JHM",
        aliases=("CVE-2021-23337",),
        severity=Severity.HIGH,
        affected=(
            AffectedPackage(
                ecosystem=Ecosystem.NPM,
                name="lodash",
                ranges=(AffectedRange(introduced="0", fixed="4.17.21"),),
            ),
        ),
    )
    by_dependency = {dependency.key: [vulnerability]}
    kev = {"CVE-2021-23337": KevEntry(cve_id="CVE-2021-23337")}
    return dependency, vulnerability, by_dependency, kev


def test_shadow_request_carries_normalized_detection_inputs():
    dependency, _, by_dependency, kev = fixture()
    request = _request(
        manifest_path="package-lock.json",
        manifest_kind="package-lock.json",
        manifest_content='{"packages": {}}',
        source_bundle=None,
        policy=DEFAULT_POLICY,
        vulnerabilities_by_dependency=by_dependency,
        kev_index=kev,
        epss_index={"CVE-2021-23337": (0.8, 0.99)},
    )

    assert request["schema_version"] == "v1"
    assert request["advisories"]["inline"][0]["known_exploited"] is True
    assert request["advisories"]["inline"][0]["epss_score"] == 0.8
    assert request["rules"]["direct_threshold"] == "high"
    assert dependency.name in request["advisories"]["inline"][0]["affected"][0]["name"]


def test_identical_engine_decision_has_no_difference():
    dependency, vulnerability, by_dependency, kev = fixture()
    python_result = triage_all([dependency], by_dependency, kev)
    engine_result = {
        "findings": [
            {
                "advisory": {"id": vulnerability.id},
                "dependency": {
                    "ecosystem": "npm",
                    "name": "lodash",
                    "version": "4.17.20",
                },
                "verdict": "actionable",
                "fixed_version": "4.17.21",
            }
        ]
    }

    assert _differences(python_result, engine_result) == []
