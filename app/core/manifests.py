"""Manifest parsing: turn an uploaded dependency file into `Dependency` records.

The hard part is not reading the file formats, it is deciding *which version* to
test against advisories. A lockfile states the installed version as fact. A
manifest states a range, and the honest answer to "what is installed?" is "we
don't know". Rather than guess high (which hides real vulnerabilities) this
module resolves each range to the lowest version it permits and marks the
result inexact, so the UI can say "your manifest allows 4.17.4, which is
vulnerable — check your lockfile" instead of asserting something it cannot know.

Every parser is total: malformed lines are collected as warnings rather than
raising, because a single unparseable line in a 300-line requirements.txt must
not cost the user their whole scan.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from app.core.types import Dependency, Ecosystem, ManifestKind, Reachability
from app.core.versions import InvalidVersion, compare, normalize

__all__ = [
    "ManifestParseError",
    "ParsedManifest",
    "detect_manifest_kind",
    "parse_manifest",
]

MAX_DEPENDENCIES = 5000


class ManifestParseError(ValueError):
    """The file could not be parsed as the claimed manifest kind at all."""


@dataclass(slots=True)
class ParsedManifest:
    kind: ManifestKind
    ecosystem: Ecosystem
    dependencies: list[Dependency] = field(default_factory=list)
    #: Non-fatal problems: unparseable lines, unsupported specifiers, git deps.
    warnings: list[str] = field(default_factory=list)
    #: Project name when the manifest declares one (package.json `name`, go.mod `module`).
    project_name: str | None = None

    @property
    def runtime_count(self) -> int:
        return sum(1 for d in self.dependencies if d.reachability.ships_to_production)

    @property
    def dev_count(self) -> int:
        return sum(1 for d in self.dependencies if not d.reachability.ships_to_production)


def supported_names() -> str:
    """The files we can read, for an error message.

    Derived from `ManifestKind` rather than written out. Three copies of this
    sentence lived in `target_service` and all three still named four formats
    after eight existed — so somebody uploading a Cargo.lock was told it was
    not supported by the same system that had just parsed one.
    """
    return ", ".join(kind.value for kind in ManifestKind)


def detect_manifest_kind(filename: str, content: str) -> ManifestKind | None:
    """Identify a manifest from its filename, falling back to content sniffing.

    Users rename files (``requirements-prod.txt``, ``frontend-package.json``),
    so the name is a hint rather than a rule.
    """
    name = (filename or "").strip().replace("\\", "/").rsplit("/", maxsplit=1)[-1].lower()

    if name == "package-lock.json":
        return ManifestKind.PACKAGE_LOCK_JSON
    if name == "package.json":
        return ManifestKind.PACKAGE_JSON
    if name == "go.mod":
        return ManifestKind.GO_MOD
    if name == "cargo.lock":
        return ManifestKind.CARGO_LOCK
    if name == "pom.xml":
        return ManifestKind.POM_XML
    if name == "build.sbt.lock":
        return ManifestKind.SBT_LOCK
    # Gradle writes one per project and per configuration set, so the name
    # varies: `gradle.lockfile`, `settings-gradle.lockfile`, and whatever a
    # build script chooses.
    if name.endswith("gradle.lockfile") or name == "dependencies.lock":
        return ManifestKind.GRADLE_LOCKFILE
    if name.endswith(".txt") and "requirement" in name:
        return ManifestKind.REQUIREMENTS_TXT

    stripped = content.lstrip()

    if stripped.startswith("<?xml") or stripped.startswith("<project"):
        return ManifestKind.POM_XML if "<artifactId" in content else None

    if stripped.startswith("{"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        if "lockfileVersion" in data:
            return ManifestKind.PACKAGE_LOCK_JSON
        if {"dependencies", "devDependencies", "peerDependencies"} & data.keys():
            return ManifestKind.PACKAGE_JSON
        return None

    if re.search(r"^module\s+\S+", content, re.MULTILINE):
        return ManifestKind.GO_MOD
    # Cargo.lock's `[[package]]` array-of-tables is distinctive enough to sniff;
    # no other manifest here uses it.
    if re.search(r"^\[\[package\]\]", content, re.MULTILINE):
        return ManifestKind.CARGO_LOCK
    if name.endswith(".txt"):
        return ManifestKind.REQUIREMENTS_TXT
    return None


def parse_manifest(kind: ManifestKind, content: str) -> ParsedManifest:
    """Parse ``content`` as ``kind``. Raises ``ManifestParseError`` only if the
    file is not that format at all."""
    parsers = {
        ManifestKind.PACKAGE_JSON: _parse_package_json,
        ManifestKind.PACKAGE_LOCK_JSON: _parse_package_lock,
        ManifestKind.REQUIREMENTS_TXT: _parse_requirements_txt,
        ManifestKind.GO_MOD: _parse_go_mod,
        ManifestKind.CARGO_LOCK: _parse_cargo_lock,
        ManifestKind.POM_XML: _parse_pom_xml,
        ManifestKind.GRADLE_LOCKFILE: _parse_gradle_lockfile,
        ManifestKind.SBT_LOCK: _parse_sbt_lock,
    }
    parsed = parsers[kind](content)
    parsed.dependencies = _dedupe(parsed.dependencies)
    if len(parsed.dependencies) > MAX_DEPENDENCIES:
        parsed.warnings.append(
            f"Manifest lists {len(parsed.dependencies)} dependencies; "
            f"only the first {MAX_DEPENDENCIES} were kept."
        )
        parsed.dependencies = parsed.dependencies[:MAX_DEPENDENCIES]
    return parsed


def _dedupe(deps: list[Dependency]) -> list[Dependency]:
    """Collapse duplicates, keeping the most exposed reachability.

    A package listed in both ``dependencies`` and ``devDependencies`` ships to
    production, so the runtime classification must win. Distinct versions of the
    same package (normal in a lockfile) are kept as separate entries.
    """
    order = {
        Reachability.RUNTIME_DIRECT: 0,
        Reachability.RUNTIME_TRANSITIVE: 1,
        Reachability.DEV_ONLY: 2,
    }
    best: dict[tuple[str, str, str], Dependency] = {}
    for dep in deps:
        key = (str(dep.ecosystem), dep.name, dep.version)
        current = best.get(key)
        if current is None or order[dep.reachability] < order[current.reachability]:
            best[key] = dep
    return sorted(best.values(), key=lambda d: (d.name.lower(), d.version))


# ---------------------------------------------------------------------------
# npm: package.json
# ---------------------------------------------------------------------------

#: Specifiers that describe a source location rather than a registry version.
#: We cannot resolve these to a version, so they are reported and skipped.
_NPM_NON_REGISTRY_PREFIXES = (
    "file:",
    "link:",
    "git:",
    "git+",
    "github:",
    "workspace:",
    "portal:",
    "http://",
    "https://",
)

_NPM_ALIAS_RE = re.compile(r"^npm:(?P<name>@?[^@]+(?:/[^@]+)?)@(?P<spec>.+)$")
_NPM_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?")


def _parse_package_json(content: str) -> ParsedManifest:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestParseError(
            f"package.json is not valid JSON: {exc.msg} (line {exc.lineno})"
        ) from exc
    if not isinstance(data, dict):
        raise ManifestParseError("package.json must contain a JSON object")

    result = ParsedManifest(kind=ManifestKind.PACKAGE_JSON, ecosystem=Ecosystem.NPM)
    name = data.get("name")
    result.project_name = name if isinstance(name, str) else None

    sections: list[tuple[str, Reachability]] = [
        ("dependencies", Reachability.RUNTIME_DIRECT),
        ("optionalDependencies", Reachability.RUNTIME_DIRECT),
        # Peers are expected to be installed alongside and do reach production.
        ("peerDependencies", Reachability.RUNTIME_DIRECT),
        ("devDependencies", Reachability.DEV_ONLY),
    ]

    for section, reachability in sections:
        block = data.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            result.warnings.append(f'"{section}" is not an object; skipped.')
            continue
        for raw_name, raw_spec in block.items():
            if not isinstance(raw_name, str) or not isinstance(raw_spec, str):
                result.warnings.append(f'Skipped malformed entry in "{section}".')
                continue
            _add_npm_dependency(result, raw_name, raw_spec, reachability)

    return result


def _add_npm_dependency(
    result: ParsedManifest, name: str, spec: str, reachability: Reachability
) -> None:
    spec = spec.strip()

    if alias := _NPM_ALIAS_RE.match(spec):
        # "npm:lodash@^4.17.21" — the vulnerable package is the aliased one.
        name = alias.group("name")
        spec = alias.group("spec")

    if spec.startswith(_NPM_NON_REGISTRY_PREFIXES):
        result.warnings.append(
            f"{name}: installed from a source location ({spec}) — no version to check."
        )
        return

    resolved = resolve_npm_floor(spec)
    if resolved is None:
        result.warnings.append(f"{name}: version range {spec!r} is unbounded — skipped.")
        return

    version, exact = resolved
    result.dependencies.append(
        Dependency(
            ecosystem=Ecosystem.NPM,
            name=name,
            version=version,
            version_spec=spec,
            reachability=reachability,
            version_exact=exact,
        )
    )


def resolve_npm_floor(spec: str) -> tuple[str, bool] | None:
    """Resolve an npm range to (lowest permitted version, is_exact).

    Returns ``None`` for ranges with no lower bound (``*``, ``latest``, ``<2``),
    where any version at all could be installed and guessing would be dishonest.

    ``||`` unions take the lowest floor across branches, since that is the
    lowest version the whole range permits.
    """
    spec = (spec or "").strip()
    if not spec or spec in {"*", "x", "X", "latest", "next"}:
        return None

    branches = [b.strip() for b in spec.split("||")]
    floors: list[tuple[str, bool]] = []
    for branch in branches:
        resolved = _resolve_npm_branch(branch)
        if resolved is not None:
            floors.append(resolved)

    if not floors:
        return None

    lowest = floors[0]
    for candidate in floors[1:]:
        try:
            if compare(Ecosystem.NPM, candidate[0], lowest[0]) < 0:
                lowest = candidate
        except InvalidVersion:
            continue
    # A union of several branches is never a single pinned version.
    return (lowest[0], lowest[1] and len(floors) == 1)


def _resolve_npm_branch(branch: str) -> tuple[str, bool] | None:
    branch = branch.strip()
    if not branch or branch in {"*", "x", "X"}:
        return None

    # Hyphen range: "1.2.3 - 2.3.4". The floor is the left operand.
    if " - " in branch:
        left = branch.split(" - ", maxsplit=1)[0].strip()
        return _npm_zero_fill(left, exact=False)

    # Comparator set: ">=1.2.3 <2.0.0". Use the lowest inclusive lower bound.
    tokens = branch.split()
    if len(tokens) > 1:
        for token in tokens:
            if token.startswith((">=", "^", "~")) or re.match(r"^\d", token):
                resolved = _resolve_npm_branch(token)
                if resolved is not None:
                    return (resolved[0], False)
        return None

    token = tokens[0] if tokens else branch

    for prefix in ("^", "~>", "~", ">=", "="):
        if token.startswith(prefix):
            # Only "=" and a bare version pin exactly; the rest are floors.
            return _npm_zero_fill(token[len(prefix) :], exact=(prefix == "="))

    if token.startswith(("<", ">")):
        # "<2.0.0" has no lower bound; ">1.2.3" excludes its own value but is
        # the closest honest floor we can name.
        if token.startswith(">"):
            return _npm_zero_fill(token.lstrip(">"), exact=False)
        return None

    return _npm_zero_fill(token, exact=True)


def _npm_zero_fill(raw: str, exact: bool) -> tuple[str, bool] | None:
    """Turn a possibly-partial npm version into a concrete floor.

    ``4`` and ``4.x`` both mean "anything in 4.x", whose floor is ``4.0.0``.
    """
    value = normalize(Ecosystem.NPM, raw)
    if not value:
        return None

    # "4.x" / "4.*" / "4.2.x" -> drop the wildcard components and zero-fill.
    parts = value.replace("*", "x").split(".")
    concrete: list[str] = []
    for part in parts:
        if part.lower().startswith("x") or part == "":
            break
        concrete.append(part)
    if not concrete:
        return None

    was_partial = len(concrete) < 3 or len(concrete) < len(parts)
    while len(concrete) < 3:
        concrete.append("0")

    candidate = ".".join(concrete)
    # Preserve a prerelease/build suffix that survived the split.
    if len(parts) >= 3 and not was_partial:
        candidate = value

    if not _NPM_VERSION_TOKEN_RE.match(candidate):
        return None
    try:
        compare(Ecosystem.NPM, candidate, candidate)
    except InvalidVersion:
        return None

    return (candidate, exact and not was_partial)


# ---------------------------------------------------------------------------
# npm: package-lock.json  (authoritative — exact installed versions)
# ---------------------------------------------------------------------------


def _parse_package_lock(content: str) -> ParsedManifest:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestParseError(
            f"package-lock.json is not valid JSON: {exc.msg} (line {exc.lineno})"
        ) from exc
    if not isinstance(data, dict):
        raise ManifestParseError("package-lock.json must contain a JSON object")

    result = ParsedManifest(kind=ManifestKind.PACKAGE_LOCK_JSON, ecosystem=Ecosystem.NPM)
    name = data.get("name")
    result.project_name = name if isinstance(name, str) else None

    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        _parse_lock_v2(result, packages)
    elif isinstance(data.get("dependencies"), dict):
        _parse_lock_v1(result, data["dependencies"], direct_names=set())
    else:
        raise ManifestParseError(
            "package-lock.json has neither a 'packages' nor a 'dependencies' section."
        )
    return result


def _lock_package_name(path: str) -> str | None:
    """``node_modules/a/node_modules/@scope/b`` -> ``@scope/b``."""
    marker = "node_modules/"
    index = path.rfind(marker)
    if index == -1:
        return None
    name = path[index + len(marker) :]
    return name or None


def _parse_lock_v2(result: ParsedManifest, packages: dict[str, object]) -> None:
    root = packages.get("")
    direct: set[str] = set()
    if isinstance(root, dict):
        for section in ("dependencies", "optionalDependencies", "peerDependencies"):
            block = root.get(section)
            if isinstance(block, dict):
                direct.update(k for k in block if isinstance(k, str))
        if isinstance(root.get("name"), str) and not result.project_name:
            result.project_name = root["name"]  # type: ignore[index]

    by_name = _index_by_name(packages)
    routes = _walk_npm_graph(root, by_name, direct)

    for path, entry in packages.items():
        if not path or not isinstance(entry, dict):
            continue
        if entry.get("link") is True:
            continue  # symlinked workspace member; its real entry appears separately
        name = entry.get("name") if isinstance(entry.get("name"), str) else _lock_package_name(path)
        version = entry.get("version")
        if not name or not isinstance(version, str) or not version:
            continue

        if entry.get("dev") is True:
            reachability = Reachability.DEV_ONLY
        elif name in direct:
            reachability = Reachability.RUNTIME_DIRECT
        else:
            reachability = Reachability.RUNTIME_TRANSITIVE

        # A package reachable by no route from the root is one npm left in the
        # tree that nothing currently asks for. Treated as depth 1 rather than
        # dropped: it is installed, so it is on disk and worth scanning, but
        # calling it direct would be a lie.
        # routes[name] ends with the package itself; via is the path to it.
        via = routes[name][:-1] if name in routes else ()
        depth = len(via)
        if name not in routes:
            depth = 0 if name in direct else 1

        result.dependencies.append(
            Dependency(
                ecosystem=Ecosystem.NPM,
                name=name,
                version=version,
                version_spec=version,
                reachability=reachability,
                version_exact=True,
                depth=depth,
                via=via,
            )
        )


def _index_by_name(packages: dict[str, object]) -> dict[str, dict]:
    """Package entries keyed by name, preferring the hoisted copy.

    npm hoists: the same package can appear at `node_modules/x` and again,
    nested, at `node_modules/a/node_modules/x` when versions conflict. The
    shallowest path is the one most of the tree actually resolves to, so it is
    the one whose dependency list describes the common case.
    """
    best: dict[str, tuple[int, dict]] = {}
    for path, entry in packages.items():
        if not path or not isinstance(entry, dict) or entry.get("link") is True:
            continue
        name = entry.get("name") if isinstance(entry.get("name"), str) else _lock_package_name(path)
        if not name:
            continue
        nesting = path.count("node_modules/")
        if name not in best or nesting < best[name][0]:
            best[name] = (nesting, entry)
    return {name: entry for name, (_, entry) in best.items()}


#: How far the walk will go before giving up. A resolved npm tree is rarely
#: deeper than about twenty; this is a guard against a cycle the visited set
#: somehow fails to catch, not a product limit. The *product* limit is
#: MatchPolicy.max_depth, applied later and per tier.
_MAX_WALK_DEPTH = 64


def _walk_npm_graph(
    root: object, by_name: dict[str, dict], direct: set[str]
) -> dict[str, tuple[str, ...]]:
    """Shortest route from the project to every reachable package.

    Breadth-first, so the first route found to a package is the shortest one --
    which is the honest answer to "how did this get in?" when several things
    depend on it. Returns chains that include the package itself, so
    `("express", "qs")` means the project depends on express which depends on
    qs.

    A package cannot be reached twice: the visited set is what makes a
    dependency cycle terminate rather than recurse until the stack gives out.
    """
    from collections import deque

    routes: dict[str, tuple[str, ...]] = {}
    queue: deque[tuple[str, tuple[str, ...]]] = deque()

    for name in sorted(direct):
        routes[name] = (name,)
        queue.append((name, (name,)))

    while queue:
        name, chain = queue.popleft()
        if len(chain) >= _MAX_WALK_DEPTH:
            continue
        entry = by_name.get(name)
        if not entry:
            continue
        for section in ("dependencies", "optionalDependencies"):
            block = entry.get(section)
            if not isinstance(block, dict):
                continue
            for child in block:
                if not isinstance(child, str) or child in routes:
                    continue
                routes[child] = (*chain, child)
                queue.append((child, (*chain, child)))

    return routes


def _parse_lock_v1(
    result: ParsedManifest,
    tree: dict[str, object],
    direct_names: set[str],
    depth: int = 0,
    via: tuple[str, ...] = (),
) -> None:
    """A v1 lockfile nests, so the recursion *is* the dependency chain."""
    if depth > _MAX_WALK_DEPTH:  # pathological nesting guard
        return
    for name, entry in tree.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if isinstance(version, str) and version and not version.startswith(("file:", "git")):
            if entry.get("dev") is True:
                reachability = Reachability.DEV_ONLY
            elif depth == 0:
                reachability = Reachability.RUNTIME_DIRECT
            else:
                reachability = Reachability.RUNTIME_TRANSITIVE
            result.dependencies.append(
                Dependency(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    version=version,
                    version_spec=version,
                    reachability=reachability,
                    version_exact=True,
                    depth=depth,
                    via=via,
                )
            )
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _parse_lock_v1(result, nested, direct_names, depth + 1, (*via, name))


# ---------------------------------------------------------------------------
# PyPI: requirements.txt
# ---------------------------------------------------------------------------

_REQ_OPTION_PREFIXES = (
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-e",
    "--editable",
    "-f",
    "--find-links",
    "-i",
    "--index-url",
    "--extra-index-url",
    "--no-index",
    "--pre",
    "--trusted-host",
    "--use-feature",
    "--no-binary",
    "--only-binary",
    "--prefer-binary",
    "--require-hashes",
)


def _parse_requirements_txt(content: str) -> ParsedManifest:
    result = ParsedManifest(kind=ManifestKind.REQUIREMENTS_TXT, ecosystem=Ecosystem.PYPI)

    for lineno, line in _join_continuations(content):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Strip inline comments (only when " #", so URLs with fragments survive).
        stripped = re.split(r"\s+#", stripped, maxsplit=1)[0].strip()
        if not stripped:
            continue

        # Drop --hash=... fragments; they are not part of the requirement.
        stripped = re.sub(r"\s--hash=\S+", "", stripped).strip()

        if stripped.startswith("-"):
            option = stripped.split(maxsplit=1)[0]
            if option in ("-r", "--requirement", "-c", "--constraint"):
                result.warnings.append(
                    f"Line {lineno}: '{stripped}' references another file, "
                    "which was not uploaded — its dependencies are not covered."
                )
            elif not option.startswith(_REQ_OPTION_PREFIXES):
                result.warnings.append(f"Line {lineno}: unrecognised option {option!r}; skipped.")
            continue

        try:
            requirement = Requirement(stripped)
        except InvalidRequirement:
            result.warnings.append(f"Line {lineno}: could not parse {stripped!r}; skipped.")
            continue

        if requirement.url:
            result.warnings.append(
                f"{requirement.name}: installed from a URL — no version to check."
            )
            continue

        resolved = resolve_pypi_floor(requirement.specifier)
        if resolved is None:
            result.warnings.append(
                f"{requirement.name}: no lower version bound "
                f"({str(requirement.specifier) or 'unpinned'}) — skipped."
            )
            continue

        version, exact = resolved
        result.dependencies.append(
            Dependency(
                ecosystem=Ecosystem.PYPI,
                name=requirement.name,
                version=version,
                version_spec=str(requirement.specifier) or "*",
                # requirements.txt has no dev/prod distinction; treat as shipping.
                reachability=Reachability.RUNTIME_DIRECT,
                version_exact=exact,
            )
        )

    return result


def _join_continuations(content: str) -> list[tuple[int, str]]:
    """Merge backslash-continued lines, reporting the first line number of each."""
    joined: list[tuple[int, str]] = []
    buffer = ""
    start = 1
    for lineno, raw in enumerate(content.splitlines(), start=1):
        if not buffer:
            start = lineno
        if raw.rstrip().endswith("\\"):
            buffer += raw.rstrip()[:-1]
            continue
        joined.append((start, buffer + raw))
        buffer = ""
    if buffer:
        joined.append((start, buffer))
    return joined


def resolve_pypi_floor(specifier: SpecifierSet | str) -> tuple[str, bool] | None:
    """Resolve a PEP 440 specifier set to (lowest permitted version, is_exact)."""
    if isinstance(specifier, str):
        try:
            specifier = SpecifierSet(specifier)
        except InvalidSpecifier:
            return None

    clauses = list(specifier)
    if not clauses:
        return None

    # An exact pin is authoritative, even alongside other clauses.
    for clause in clauses:
        if clause.operator in ("==", "===") and "*" not in clause.version:
            return (clause.version, True)

    floors: list[str] = []
    for clause in clauses:
        if clause.operator in (">=", "~=", ">"):
            floors.append(clause.version)
        elif clause.operator == "==" and "*" in clause.version:
            # "==1.4.*" -> floor 1.4
            floors.append(clause.version.replace(".*", "").replace("*", "").rstrip("."))

    floors = [f for f in floors if f]
    if not floors:
        return None

    highest = floors[0]
    for candidate in floors[1:]:
        try:
            if compare(Ecosystem.PYPI, candidate, highest) > 0:
                highest = candidate
        except InvalidVersion:
            continue
    try:
        compare(Ecosystem.PYPI, highest, highest)
    except InvalidVersion:
        return None
    return (highest, False)


# ---------------------------------------------------------------------------
# Go: go.mod
# ---------------------------------------------------------------------------

_GO_MODULE_RE = re.compile(r"^module\s+(?P<path>\S+)")
_GO_REQUIRE_LINE_RE = re.compile(
    r"^(?P<path>[^\s()]+)\s+(?P<version>v\S+)(?P<rest>.*)$",
)
_GO_REPLACE_RE = re.compile(
    r"^(?:replace\s+)?(?P<old>[^\s=]+)(?:\s+(?P<oldver>v\S+))?\s*=>\s*"
    r"(?P<new>\S+)(?:\s+(?P<newver>v\S+))?\s*$"
)


def _parse_go_mod(content: str) -> ParsedManifest:
    result = ParsedManifest(kind=ManifestKind.GO_MOD, ecosystem=Ecosystem.GO)

    block: str | None = None
    requires: list[tuple[str, str, bool]] = []  # (path, version, indirect)
    replacements: dict[str, tuple[str, str | None]] = {}
    excluded: set[tuple[str, str]] = set()

    for raw in content.splitlines():
        line = raw.split("//")[0].strip() if not raw.strip().startswith("//") else ""
        comment = raw.partition("//")[2].strip()
        if not line:
            continue

        if block is None:
            if match := _GO_MODULE_RE.match(line):
                result.project_name = match.group("path")
                continue
            for directive in ("require", "replace", "exclude", "retract"):
                if line == f"{directive} (" or line.startswith(f"{directive} ("):
                    block = directive
                    break
            else:
                if line.startswith("require "):
                    _collect_go_require(requires, line[len("require ") :], comment, result)
                elif line.startswith("replace "):
                    _collect_go_replace(replacements, line[len("replace ") :], result)
                elif line.startswith("exclude "):
                    _collect_go_exclude(excluded, line[len("exclude ") :])
                continue
            continue

        if line == ")":
            block = None
            continue

        if block == "require":
            _collect_go_require(requires, line, comment, result)
        elif block == "replace":
            _collect_go_replace(replacements, line, result)
        elif block == "exclude":
            _collect_go_exclude(excluded, line)

    for path, version, indirect in requires:
        if (path, version) in excluded:
            continue
        if path in replacements:
            new_path, new_version = replacements[path]
            if new_version is None:
                result.warnings.append(
                    f"{path} is replaced by a local path ({new_path}) — no version to check."
                )
                continue
            path, version = new_path, new_version

        result.dependencies.append(
            Dependency(
                ecosystem=Ecosystem.GO,
                name=path,
                version=normalize(Ecosystem.GO, version),
                version_spec=version,
                reachability=(
                    Reachability.RUNTIME_TRANSITIVE if indirect else Reachability.RUNTIME_DIRECT
                ),
                version_exact=True,
                # go.mod flattens: `// indirect` says a module is not required
                # directly, but not by what or how far away. Depth 1 is the
                # honest floor -- it is at least one hop -- and go.sum does not
                # help, since it lists hashes rather than edges. A deeper answer
                # needs `go mod graph`, which means running the toolchain
                # against the source rather than reading a file.
                depth=1 if indirect else 0,
            )
        )

    return result


def _collect_go_require(
    out: list[tuple[str, str, bool]], line: str, comment: str, result: ParsedManifest
) -> None:
    match = _GO_REQUIRE_LINE_RE.match(line.strip())
    if not match:
        if line.strip() and line.strip() != "(":
            result.warnings.append(f"Unparseable require line: {line.strip()!r}")
        return
    indirect = "indirect" in comment or "indirect" in match.group("rest")
    out.append((match.group("path"), match.group("version"), indirect))


def _collect_go_replace(
    out: dict[str, tuple[str, str | None]], line: str, result: ParsedManifest
) -> None:
    match = _GO_REPLACE_RE.match(line.strip())
    if not match:
        result.warnings.append(f"Unparseable replace directive: {line.strip()!r}")
        return
    out[match.group("old")] = (match.group("new"), match.group("newver"))


def _collect_go_exclude(out: set[tuple[str, str]], line: str) -> None:
    match = _GO_REQUIRE_LINE_RE.match(line.strip())
    if match:
        out.add((match.group("path"), match.group("version")))


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


def _parse_cargo_lock(content: str) -> ParsedManifest:
    """Cargo.lock — TOML, exact versions, and a real dependency graph.

    Every crate in the tree gets a `[[package]]` entry, including the project
    itself. The root is the one nothing else depends on and which has no
    `source`: crates from a registry carry one, the local package does not.
    Excluding it matters — reporting your own crate as a vulnerable dependency
    of itself is nonsense, and it would be the only entry with no upstream to
    upgrade to.

    Cargo does not record which dependencies are dev-only in the lockfile, so
    everything resolved is treated as shipping. That is the conservative
    direction: calling a dev tool production noise is better than calling a
    production crate dev-only and filtering it out.
    """
    result = ParsedManifest(kind=ManifestKind.CARGO_LOCK, ecosystem=Ecosystem.CRATES_IO)

    try:
        data = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        raise ManifestParseError(f"Cargo.lock is not valid TOML: {exc}") from exc

    packages = data.get("package")
    if not isinstance(packages, list):
        raise ManifestParseError("Cargo.lock has no [[package]] entries.")

    entries: list[dict] = [p for p in packages if isinstance(p, dict)]

    # Local packages — the workspace members — have no `source`. Everything
    # else came from a registry or a git remote.
    local = {p.get("name") for p in entries if not p.get("source") and p.get("name")}
    if len(local) == 1:
        result.project_name = next(iter(local))

    direct: set[str] = set()
    for entry in entries:
        if entry.get("name") in local:
            for spec in entry.get("dependencies", []) or []:
                if isinstance(spec, str):
                    # Entries are "name" or "name version" or "name version source".
                    direct.add(spec.split(" ", 1)[0])

    for entry in entries:
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        if name in local:
            continue

        result.dependencies.append(
            Dependency(
                ecosystem=Ecosystem.CRATES_IO,
                name=name,
                version=normalize(Ecosystem.CRATES_IO, version),
                version_spec=version,
                reachability=(
                    Reachability.RUNTIME_DIRECT
                    if name in direct
                    else Reachability.RUNTIME_TRANSITIVE
                ),
                version_exact=True,
                depth=0 if name in direct else 1,
            )
        )

    if not result.dependencies:
        result.warnings.append("Cargo.lock lists no dependencies outside the workspace.")
    return result


# ---------------------------------------------------------------------------
# JVM — Maven, Gradle, sbt
# ---------------------------------------------------------------------------

#: A DTD in an uploaded document is only ever an attack or a mistake.
_DOCTYPE_RE = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)

#: Maven scopes that never reach a running application.
_MAVEN_DEV_SCOPES = {"test", "provided"}


def _maven_name(group: str, artifact: str) -> str:
    """OSV keys Maven advisories by `groupId:artifactId`."""
    return f"{group.strip()}:{artifact.strip()}"


def _parse_pom_xml(content: str) -> ParsedManifest:
    """pom.xml — what the build *asks for*, which is not always a version.

    Deliberately not treated as a lockfile. A POM can state a version as a
    property (`${spring.version}`), inherit it from a parent this server never
    sees, or give a range. Resolving any of those needs Maven itself and the
    whole parent chain.

    Properties defined in the same file are substituted, because that case is
    both common and knowable. Anything still unresolved after that is reported
    as a warning and skipped rather than guessed at — a made-up version checked
    against advisory ranges produces confident, wrong answers.

    `test` and `provided` scopes map to dev-only: neither ships in the artefact
    you deploy.
    """
    result = ParsedManifest(kind=ManifestKind.POM_XML, ecosystem=Ecosystem.MAVEN)

    # No POM needs a document type declaration, and every entity-expansion
    # attack does. Refusing one outright is a complete fix for the attack this
    # parser is exposed to, and cheaper than a dependency.
    #
    # Verified rather than assumed: `xml.etree` already refuses external
    # entities — an XXE payload raises "undefined entity" — but it *does*
    # expand internal ones, so a billion-laughs document parses and grows
    # until it exhausts memory.
    if _DOCTYPE_RE.search(content):
        raise ManifestParseError(
            "This POM declares a document type. POMs do not need one, and it is "
            "the mechanism behind entity-expansion attacks, so it is refused."
        )

    try:
        # The suppression below is earned by the DTD guard above, not waved
        # through: S314 flags `xml` wholesale, and the two attacks it exists
        # for are an external entity — which expat already refuses here, tested
        # — and entity expansion, which needs the DTD that is now rejected.
        # defusedxml would add a dependency and no further protection.
        root = ElementTree.fromstring(content)  # noqa: S314
    except ElementTree.ParseError as exc:
        raise ManifestParseError(f"pom.xml is not valid XML: {exc}") from exc

    # POMs are namespaced; the namespace is on every tag and varies by schema
    # version, so it is stripped rather than matched.
    def tag(element) -> str:
        return element.tag.rpartition("}")[2]

    def child(element, name: str):
        return next((c for c in element if tag(c) == name), None)

    def text(element, name: str) -> str:
        found = child(element, name)
        return (found.text or "").strip() if found is not None else ""

    if tag(root) != "project":
        raise ManifestParseError("That XML is not a Maven POM (no <project> root).")

    result.project_name = text(root, "artifactId") or None

    properties: dict[str, str] = {}
    props = child(root, "properties")
    if props is not None:
        for entry in props:
            properties[tag(entry)] = (entry.text or "").strip()

    def resolve(value: str) -> str:
        seen = 0
        while value.startswith("${") and value.endswith("}") and seen < 5:
            value = properties.get(value[2:-1], value)
            seen += 1
        return value

    blocks = [child(root, "dependencies")]
    management = child(root, "dependencyManagement")
    if management is not None:
        # Versions declared here apply to dependencies that omit one, which is
        # the ordinary pattern in a multi-module build.
        blocks.append(child(management, "dependencies"))

    managed: dict[str, str] = {}
    declared: list[tuple[str, str, str]] = []  # (name, version, scope)

    for index, block in enumerate(blocks):
        if block is None:
            continue
        for dependency in block:
            if tag(dependency) != "dependency":
                continue
            group = resolve(text(dependency, "groupId"))
            artifact = resolve(text(dependency, "artifactId"))
            if not group or not artifact:
                continue
            name = _maven_name(group, artifact)
            version = resolve(text(dependency, "version"))
            scope = text(dependency, "scope").lower()

            if index == 1:
                if version:
                    managed[name] = version
                continue
            declared.append((name, version, scope))

    for name, version, scope in declared:
        version = version or managed.get(name, "")

        if not version:
            result.warnings.append(
                f"{name} has no version in this POM — it comes from a parent or BOM "
                f"that is not in this file, so it was skipped."
            )
            continue
        if version.startswith("${"):
            result.warnings.append(
                f"{name} uses the property {version}, which is not defined here — skipped."
            )
            continue
        if version.startswith(("[", "(")):
            result.warnings.append(
                f"{name} declares the range {version}. Maven ranges resolve at build "
                f"time, so it was skipped rather than guessed at."
            )
            continue

        result.dependencies.append(
            Dependency(
                ecosystem=Ecosystem.MAVEN,
                name=name,
                version=normalize(Ecosystem.MAVEN, version),
                version_spec=version,
                reachability=(
                    Reachability.DEV_ONLY
                    if scope in _MAVEN_DEV_SCOPES
                    else Reachability.RUNTIME_DIRECT
                ),
                version_exact=True,
            )
        )

    if not result.dependencies and not result.warnings:
        result.warnings.append("This POM declares no dependencies.")
    return result


#: Gradle names its configurations, and the name says whether the classpath
#: ships. Anything only ever seen on a test or annotation-processor classpath
#: is build tooling.
_GRADLE_DEV_MARKERS = ("test", "checkstyle", "pmd", "spotbugs", "jacoco", "annotationprocessor")


def _parse_gradle_lockfile(content: str) -> ParsedManifest:
    """gradle.lockfile — one resolved coordinate per line.

    The format is `group:artifact:version=configuration,configuration`, with
    `#` comments and a trailing `empty=` line listing configurations that
    resolved to nothing.

    The configuration list is the only signal about whether a dependency
    ships. A coordinate seen *only* on test-ish classpaths is dev-only; one
    that appears on any runtime classpath is not, however many test
    configurations also pull it in.
    """
    result = ParsedManifest(kind=ManifestKind.GRADLE_LOCKFILE, ecosystem=Ecosystem.MAVEN)

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue

        coordinate, _, configurations = line.partition("=")
        parts = coordinate.strip().split(":")
        if len(parts) != 3:
            continue
        group, artifact, version = (part.strip() for part in parts)
        if not group or not artifact or not version:
            continue

        names = [c.strip().lower() for c in configurations.split(",") if c.strip()]
        ships = any(not any(marker in name for marker in _GRADLE_DEV_MARKERS) for name in names)

        result.dependencies.append(
            Dependency(
                ecosystem=Ecosystem.MAVEN,
                name=_maven_name(group, artifact),
                version=normalize(Ecosystem.MAVEN, version),
                version_spec=version,
                reachability=(Reachability.RUNTIME_TRANSITIVE if ships else Reachability.DEV_ONLY),
                version_exact=True,
            )
        )

    if not result.dependencies:
        raise ManifestParseError(
            "No `group:artifact:version=` lines found — this does not look like a Gradle lockfile."
        )
    return result


def _parse_sbt_lock(content: str) -> ParsedManifest:
    """build.sbt.lock — the sbt-dependency-lock plugin's JSON.

    Worth being precise about what this supports: plain `build.sbt` is a Scala
    program, not a data file, and resolving it means running sbt. This file is
    the only sbt artefact that states resolved versions as fact, and it exists
    only if the project uses the plugin.

    Configurations follow Ivy's naming, so `test` is the dev marker.
    """
    result = ParsedManifest(kind=ManifestKind.SBT_LOCK, ecosystem=Ecosystem.MAVEN)

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestParseError(f"build.sbt.lock is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
        raise ManifestParseError("build.sbt.lock has no `dependencies` list.")

    for entry in data["dependencies"]:
        if not isinstance(entry, dict):
            continue
        group = str(entry.get("org") or entry.get("organization") or "").strip()
        artifact = str(entry.get("name") or entry.get("artifact") or "").strip()
        version = str(entry.get("version") or "").strip()
        if not group or not artifact or not version:
            continue

        configurations = entry.get("configurations") or []
        if isinstance(configurations, str):
            configurations = [configurations]
        names = [str(c).lower() for c in configurations]
        dev_only = bool(names) and all("test" in name for name in names)

        result.dependencies.append(
            Dependency(
                ecosystem=Ecosystem.MAVEN,
                name=_maven_name(group, artifact),
                version=normalize(Ecosystem.MAVEN, version),
                version_spec=version,
                reachability=(
                    Reachability.DEV_ONLY if dev_only else Reachability.RUNTIME_TRANSITIVE
                ),
                version_exact=True,
            )
        )

    if not result.dependencies:
        result.warnings.append("build.sbt.lock lists no dependencies.")
    return result
