"""Conservative source reachability analysis for Node/JavaScript projects.

The analyser receives source text and an already-parsed npm dependency graph.
It never executes project code, resolves arbitrary paths, or asks severity to
stand in for reachability.  Static imports are strong evidence; an imported
top-level dependency leading to a vulnerable transitive package is weaker but
still inspectable evidence.  Missing or incomplete input stays ``unknown``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import PurePosixPath

from app.core.types import (
    AutomatedReachability,
    Dependency,
    Ecosystem,
    ReachabilityEvidence,
)

MAX_EVIDENCE_PER_DEPENDENCY = 8
MAX_SOURCE_FILES = 512
MAX_SOURCE_FILE_BYTES = 512 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SourceFile:
    """One UTF-8 JavaScript/TypeScript source file supplied to the scanner."""

    path: str
    content: str


@dataclass(frozen=True, slots=True)
class SourceBundle:
    """The bounded source inventory supplied with one scan.

    ``complete`` means discovery and reads completed within the scanner's
    documented limits. It is not a claim that regexes understand every
    possible JavaScript program; dynamic/non-literal imports independently
    make negative conclusions unsafe.
    """

    files: tuple[SourceFile, ...] = ()
    complete: bool = False
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _Import:
    source_file: str
    line: int
    kind: str
    specifier: str
    package: str
    production_source: bool


_ESM_FROM_RE = re.compile(
    r"\b(?:import|export)\s+(?:type\s+)?[^;\n]{0,500}?\s+from\s*['\"](?P<name>[^'\"]+)['\"]"
)
_ESM_BARE_RE = re.compile(r"\bimport\s*['\"](?P<name>[^'\"]+)['\"]")
_REQUIRE_RE = re.compile(r"\brequire(?:\.resolve)?\s*\(\s*['\"](?P<name>[^'\"]+)['\"]\s*\)")
_DYNAMIC_LITERAL_RE = re.compile(r"\bimport\s*\(\s*['\"](?P<name>[^'\"]+)['\"]\s*\)")
_DYNAMIC_UNKNOWN_RE = re.compile(r"\b(?:require(?:\.resolve)?|import)\s*\(\s*(?!['\"])")

_SOURCE_SUFFIXES = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
}
_NON_PRODUCTION_PARTS = {
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "fixtures",
    "scripts",
}


def supported_source_path(path: str) -> bool:
    """Whether ``path`` is a source kind this analyser understands."""
    return PurePosixPath(path.replace("\\", "/")).suffix.lower() in _SOURCE_SUFFIXES


def safe_source_path(path: str) -> str | None:
    """Normalise an upload label and reject absolute/traversing paths.

    Source files are never written to disk, but accepting traversal-shaped
    names would still leak unsafe labels into evidence, exports and logs.
    """
    raw = path.replace("\\", "/").strip()
    if (
        not raw
        or len(raw) > 400
        or any(ord(character) < 32 for character in raw)
        or re.match(r"^[A-Za-z]:", raw)
    ):
        return None
    candidate = PurePosixPath(raw)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    normalised = candidate.as_posix().lstrip("./")
    return normalised or None


def analyze_node_reachability(
    dependencies: list[Dependency], bundle: SourceBundle
) -> tuple[list[Dependency], tuple[str, ...]]:
    """Attach source-derived reachability to npm dependencies.

    Reliable positive observations survive an incomplete source inventory.
    Negative observations do not: if discovery, reading, or static analysis is
    uncertain, every otherwise-unobserved package is ``unknown``.
    """
    imports: list[_Import] = []
    uncertain = not bundle.complete
    notes = list(bundle.notes)

    for source in bundle.files:
        path = safe_source_path(source.path)
        if path is None or not supported_source_path(path):
            uncertain = True
            notes.append(f"Skipped unsupported or unsafe source path: {source.path!r}.")
            continue
        found, dynamic = _imports_from(path, source.content)
        imports.extend(found)
        if dynamic:
            uncertain = True
            notes.append(
                f"{path} contains a non-literal import/require; negative results are unknown."
            )

    by_package: dict[str, list[_Import]] = {}
    for observation in imports:
        by_package.setdefault(observation.package, []).append(observation)

    analysed: list[Dependency] = []
    for dependency in dependencies:
        if dependency.ecosystem is not Ecosystem.NPM:
            analysed.append(dependency)
            continue

        direct_observations = by_package.get(dependency.name, [])
        if direct_observations:
            state = (
                AutomatedReachability.REACHABLE
                if any(item.production_source for item in direct_observations)
                else AutomatedReachability.POTENTIALLY_REACHABLE
            )
            evidence = tuple(
                _direct_evidence(item, dependency)
                for item in direct_observations[:MAX_EVIDENCE_PER_DEPENDENCY]
            )
            analysed.append(
                replace(
                    dependency,
                    automated_reachability=state,
                    reachability_evidence=evidence,
                )
            )
            continue

        root = dependency.via[0] if dependency.via else ""
        root_observations = by_package.get(root, []) if root else []
        if dependency.depth > 0 and root_observations:
            evidence = tuple(
                _transitive_evidence(item, dependency)
                for item in root_observations[:MAX_EVIDENCE_PER_DEPENDENCY]
            )
            analysed.append(
                replace(
                    dependency,
                    automated_reachability=AutomatedReachability.POTENTIALLY_REACHABLE,
                    reachability_evidence=evidence,
                )
            )
            continue

        # A transitive package with no known route cannot earn a reliable
        # negative result even if source discovery was complete: the lockfile
        # did not give us enough dependency evidence to connect it.
        cannot_map_path = dependency.depth > 0 and not dependency.via
        state = (
            AutomatedReachability.UNKNOWN
            if uncertain or cannot_map_path
            else AutomatedReachability.NOT_OBSERVED
        )
        analysed.append(
            replace(
                dependency,
                automated_reachability=state,
                reachability_evidence=(),
            )
        )

    if uncertain and not any("negative results are unknown" in note for note in notes):
        notes.append("Source analysis was incomplete; unobserved dependencies remain unknown.")
    return analysed, tuple(dict.fromkeys(notes))


def _imports_from(path: str, content: str) -> tuple[list[_Import], bool]:
    matches: list[tuple[int, str, str]] = []
    for kind, pattern in (
        ("import", _ESM_FROM_RE),
        ("import", _ESM_BARE_RE),
        ("require", _REQUIRE_RE),
        ("dynamic_import", _DYNAMIC_LITERAL_RE),
    ):
        for match in pattern.finditer(content):
            matches.append((match.start(), kind, match.group("name")))

    seen: set[tuple[int, str]] = set()
    observations: list[_Import] = []
    for offset, kind, specifier in sorted(matches):
        package = _package_name(specifier)
        if package is None or (offset, package) in seen:
            continue
        seen.add((offset, package))
        observations.append(
            _Import(
                source_file=path,
                line=content.count("\n", 0, offset) + 1,
                kind=kind,
                specifier=specifier,
                package=package,
                production_source=_is_production_source(path),
            )
        )
    return observations, bool(_DYNAMIC_UNKNOWN_RE.search(content))


def _package_name(specifier: str) -> str | None:
    value = specifier.strip()
    if not value or value.startswith((".", "/", "#", "node:")):
        return None
    if value.startswith("@"):
        parts = value.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return value.split("/", 1)[0]


def _is_production_source(path: str) -> bool:
    candidate = PurePosixPath(path)
    parts = {part.lower() for part in candidate.parts[:-1]}
    name = candidate.name.lower()
    return not (
        parts & _NON_PRODUCTION_PARTS
        or ".test." in name
        or ".spec." in name
        or name.endswith((".config.js", ".config.ts", ".config.mjs", ".config.cjs"))
    )


def _location(item: _Import) -> str:
    return f"{item.source_file}:{item.line}"


def _direct_evidence(item: _Import, dependency: Dependency) -> ReachabilityEvidence:
    path = (*dependency.via, dependency.name)
    qualifier = "" if item.production_source else " in non-production source"
    return ReachabilityEvidence(
        source_file=item.source_file,
        line=item.line,
        import_kind=item.kind,
        imported_package=item.package,
        dependency_path=path,
        explanation=f"{_location(item)} {item.kind}s {item.specifier}{qualifier}",
    )


def _transitive_evidence(item: _Import, dependency: Dependency) -> ReachabilityEvidence:
    path = (*dependency.via, dependency.name)
    rendered = " > ".join(path)
    return ReachabilityEvidence(
        source_file=item.source_file,
        line=item.line,
        import_kind=item.kind,
        imported_package=item.package,
        dependency_path=path,
        explanation=(
            f"{_location(item)} {item.kind}s {item.specifier}; dependency path {rendered}"
        ),
    )
