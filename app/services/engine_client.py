"""Shadow adapter for the standalone Go detection engine.

The Python detector remains authoritative in shadow mode. A failure or mismatch
is logged and never changes stored findings, notification state, or scan status.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.config import get_settings
from app.core.matching import MatchPolicy
from app.core.reachability import SourceBundle
from app.core.types import KevEntry, ScanResult, Vulnerability
from app.logging_config import get_logger

log = get_logger(__name__)


async def shadow_compare(
    *,
    manifest_path: str,
    manifest_kind: str,
    manifest_content: str,
    source_bundle: SourceBundle | None,
    policy: MatchPolicy,
    vulnerabilities_by_dependency: dict[tuple[str, str, str], list[Vulnerability]],
    kev_index: dict[str, KevEntry] | set[str] | None,
    epss_index: dict[str, tuple[float, float]] | None,
    python_result: ScanResult,
) -> None:
    settings = get_settings()
    if settings.detection_engine_mode != "shadow" or not settings.detection_engine_url:
        return

    request = _request(
        manifest_path=manifest_path,
        manifest_kind=manifest_kind,
        manifest_content=manifest_content,
        source_bundle=source_bundle,
        policy=policy,
        vulnerabilities_by_dependency=vulnerabilities_by_dependency,
        kev_index=kev_index,
        epss_index=epss_index,
    )
    try:
        async with httpx.AsyncClient(timeout=settings.detection_engine_timeout_seconds) as client:
            response = await client.post(
                f"{settings.detection_engine_url.rstrip('/')}/v1/scan", json=request
            )
            response.raise_for_status()
            engine_result = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("engine.shadow_failed", error=str(exc), manifest=manifest_path)
        return

    differences = _differences(python_result, engine_result)
    if differences:
        log.warning(
            "engine.shadow_mismatch",
            manifest=manifest_path,
            differences=differences[:20],
            difference_count=len(differences),
        )
    else:
        log.info("engine.shadow_match", manifest=manifest_path)


def _request(
    *,
    manifest_path: str,
    manifest_kind: str,
    manifest_content: str,
    source_bundle: SourceBundle | None,
    policy: MatchPolicy,
    vulnerabilities_by_dependency: dict[tuple[str, str, str], list[Vulnerability]],
    kev_index: dict[str, KevEntry] | set[str] | None,
    epss_index: dict[str, tuple[float, float]] | None,
) -> dict[str, Any]:
    kev_ids = {item.upper() for item in (kev_index or {})}
    unique: dict[str, Vulnerability] = {}
    for candidates in vulnerabilities_by_dependency.values():
        for vulnerability in candidates:
            unique[vulnerability.id] = vulnerability

    return {
        "schema_version": "v1",
        "manifests": [{"path": manifest_path, "kind": manifest_kind, "content": manifest_content}],
        "sources": [
            {"path": source.path, "content": source.content}
            for source in (source_bundle.files if source_bundle else ())
        ],
        "rules": {
            "direct_threshold": str(policy.direct_threshold),
            "transitive_threshold": str(policy.transitive_threshold),
            "dev_threshold": str(policy.dev_threshold) if policy.dev_threshold else "",
            "epss_alert_above": policy.epss_threshold,
            "always_alert_on_kev": policy.always_alert_on_kev,
            "max_depth": policy.max_depth,
            "ignored": [
                *(
                    {"advisory_id": identifier, "reason": "legacy project rule"}
                    for identifier in sorted(policy.ignored_ids)
                ),
                *(
                    {"package": package, "reason": "legacy project rule"}
                    for package in sorted(policy.ignored_packages)
                ),
            ],
        },
        "advisories": {
            "provider": "legacy-mirror-shadow",
            "inline": [
                _advisory(vulnerability, kev_ids, epss_index or {})
                for vulnerability in sorted(unique.values(), key=lambda item: item.id)
            ],
        },
    }


def _advisory(
    vulnerability: Vulnerability,
    kev_ids: set[str],
    epss_index: dict[str, tuple[float, float]],
) -> dict[str, Any]:
    epss = max(
        (epss_index[cve] for cve in vulnerability.cve_ids if cve in epss_index),
        default=(None, None),
        key=lambda item: item[0] if item[0] is not None else -1,
    )
    return {
        "id": vulnerability.id,
        "aliases": list(vulnerability.aliases),
        "summary": vulnerability.summary,
        "details": vulnerability.details,
        "severity": str(vulnerability.severity),
        "cvss_score": vulnerability.cvss_score,
        "cvss_vector": vulnerability.cvss_vector,
        "references": list(vulnerability.references),
        "cwe_ids": list(vulnerability.cwe_ids),
        "withdrawn": vulnerability.withdrawn,
        "known_exploited": any(cve.upper() in kev_ids for cve in vulnerability.cve_ids),
        "epss_score": epss[0],
        "epss_percentile": epss[1],
        "affected": [
            {
                "ecosystem": str(affected.ecosystem),
                "name": affected.name,
                "versions": list(affected.versions),
                "ranges": [
                    {
                        "introduced": interval.introduced,
                        "fixed": interval.fixed,
                        "last_affected": interval.last_affected,
                    }
                    for interval in affected.ranges
                ],
            }
            for affected in vulnerability.affected
        ],
    }


def _differences(python_result: ScanResult, engine_result: dict[str, Any]) -> list[str]:
    expected = {
        (
            decision.vulnerability.id,
            str(decision.dependency.ecosystem),
            decision.dependency.name,
            decision.dependency.version,
        ): (str(decision.verdict), decision.fixed_version)
        for decision in (*python_result.actionable, *python_result.suppressed)
    }
    actual = {}
    for finding in engine_result.get("findings", []):
        dependency = finding.get("dependency", {})
        key = (
            finding.get("advisory", {}).get("id"),
            dependency.get("ecosystem"),
            dependency.get("name"),
            dependency.get("version"),
        )
        verdict = "suppressed" if finding.get("verdict") == "filtered" else finding.get("verdict")
        actual[key] = (verdict, finding.get("fixed_version") or None)

    differences = []
    for key in sorted(expected.keys() | actual.keys(), key=str):
        if expected.get(key) != actual.get(key):
            differences.append(f"{key}: python={expected.get(key)!r}, go={actual.get(key)!r}")
    return differences
