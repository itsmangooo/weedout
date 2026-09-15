"""StrictSeal regression coverage for automated Node reachability."""

from __future__ import annotations

from pathlib import Path

from app.core.manifests import parse_manifest
from app.core.reachability import (
    SourceBundle,
    SourceFile,
    analyze_node_reachability,
    safe_source_path,
)
from app.core.types import AutomatedReachability, ManifestKind

FIXTURE = Path(__file__).parent / "fixtures" / "strictseal" / "node-project"


def strictseal_dependencies():
    parsed = parse_manifest(
        ManifestKind.PACKAGE_LOCK_JSON,
        (FIXTURE / "package-lock.json").read_text(encoding="utf-8"),
    )
    return parsed.dependencies


def test_strictseal_dependency_versions_are_pinned() -> None:
    versions = {dependency.name: dependency.version for dependency in strictseal_dependencies()}
    assert (
        versions
        | {
            "lodash": "4.17.11",
            "minimist": "1.2.5",
            "axios": "0.21.1",
            "express": "4.17.1",
        }
        == versions
    )
    assert {name: versions[name] for name in ("lodash", "minimist", "axios", "express")} == {
        "lodash": "4.17.11",
        "minimist": "1.2.5",
        "axios": "0.21.1",
        "express": "4.17.1",
    }


def test_imported_vulnerable_package_is_reachable_with_line_evidence() -> None:
    source = (FIXTURE / "src" / "api.js").read_text(encoding="utf-8")
    analysed, notes = analyze_node_reachability(
        strictseal_dependencies(),
        SourceBundle(files=(SourceFile("src/api.js", source),), complete=True),
    )

    axios = next(dependency for dependency in analysed if dependency.name == "axios")
    assert axios.automated_reachability is AutomatedReachability.REACHABLE
    assert axios.reachability_evidence[0].source_file == "src/api.js"
    assert axios.reachability_evidence[0].line == 1
    assert "src/api.js:1 imports axios" in axios.reachability_evidence[0].explanation
    assert not notes


def test_installed_but_unreferenced_package_is_not_observed() -> None:
    source = (FIXTURE / "src" / "api.js").read_text(encoding="utf-8")
    analysed, _ = analyze_node_reachability(
        strictseal_dependencies(),
        SourceBundle(files=(SourceFile("src/api.js", source),), complete=True),
    )

    lodash = next(dependency for dependency in analysed if dependency.name == "lodash")
    assert lodash.automated_reachability is AutomatedReachability.NOT_OBSERVED
    assert lodash.reachability_evidence == ()


def test_transitive_package_uses_import_and_dependency_path_evidence() -> None:
    source = (FIXTURE / "src" / "api.js").read_text(encoding="utf-8")
    analysed, _ = analyze_node_reachability(
        strictseal_dependencies(),
        SourceBundle(files=(SourceFile("src/api.js", source),), complete=True),
    )

    qs = next(dependency for dependency in analysed if dependency.name == "qs")
    assert qs.automated_reachability is AutomatedReachability.POTENTIALLY_REACHABLE
    assert qs.reachability_evidence[0].dependency_path == ("express", "qs")
    assert "dependency path express > qs" in qs.reachability_evidence[0].explanation


def test_analysis_uncertainty_is_unknown_not_not_observed() -> None:
    analysed, notes = analyze_node_reachability(
        strictseal_dependencies(),
        SourceBundle(
            files=(SourceFile("src/plugin.js", "const selected = require(pluginName);"),),
            complete=True,
        ),
    )

    lodash = next(dependency for dependency in analysed if dependency.name == "lodash")
    assert lodash.automated_reachability is AutomatedReachability.UNKNOWN
    assert any("non-literal" in note for note in notes)


def test_missing_source_inventory_is_unknown() -> None:
    analysed, _ = analyze_node_reachability(
        strictseal_dependencies(),
        SourceBundle(complete=False),
    )
    assert all(
        dependency.automated_reachability is AutomatedReachability.UNKNOWN
        for dependency in analysed
    )


def test_source_labels_reject_absolute_traversing_and_control_paths() -> None:
    assert safe_source_path("src/api.js") == "src/api.js"
    for unsafe in ("../secret.js", "/etc/passwd.js", r"C:\\secret.js", "src/evil\n.js"):
        assert safe_source_path(unsafe) is None
