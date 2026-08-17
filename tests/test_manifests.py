"""Manifest parsing across all four supported formats.

The recurring theme: a manifest range is not an installed version. Anything we
infer from a range must be marked inexact so the UI can say so, and anything we
cannot infer at all must become a warning rather than a silent omission.
"""

from __future__ import annotations

import json

import pytest

from app.core.manifests import (
    ManifestParseError,
    detect_manifest_kind,
    parse_manifest,
    resolve_npm_floor,
    resolve_pypi_floor,
)
from app.core.types import Ecosystem, ManifestKind, Reachability


def by_name(parsed):
    return {d.name: d for d in parsed.dependencies}


class TestDetectManifestKind:
    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("package.json", ManifestKind.PACKAGE_JSON),
            ("package-lock.json", ManifestKind.PACKAGE_LOCK_JSON),
            ("go.mod", ManifestKind.GO_MOD),
            ("requirements.txt", ManifestKind.REQUIREMENTS_TXT),
            ("requirements-dev.txt", ManifestKind.REQUIREMENTS_TXT),
            ("app/frontend/package.json", ManifestKind.PACKAGE_JSON),
            ("C:\\repo\\go.mod", ManifestKind.GO_MOD),
        ],
    )
    def test_detects_by_filename(self, filename, expected):
        assert detect_manifest_kind(filename, "{}") == expected

    def test_falls_back_to_content_for_renamed_files(self):
        assert (
            detect_manifest_kind("deps.json", '{"dependencies": {"a": "1.0.0"}}')
            == ManifestKind.PACKAGE_JSON
        )
        assert (
            detect_manifest_kind("lock.json", '{"lockfileVersion": 3, "packages": {}}')
            == ManifestKind.PACKAGE_LOCK_JSON
        )
        assert (
            detect_manifest_kind("deps", "module example.com/x\n\ngo 1.21\n") == ManifestKind.GO_MOD
        )

    def test_returns_none_for_unrecognisable_input(self):
        assert detect_manifest_kind("mystery.bin", "\x00\x01binary") is None
        assert detect_manifest_kind("x.json", "{not json") is None


class TestPackageJson:
    MANIFEST = json.dumps(
        {
            "name": "my-app",
            "dependencies": {
                "lodash": "4.17.20",
                "express": "^4.18.0",
                "react": "~18.2.1",
                "semver": ">=7.3.0 <8.0.0",
                "left-pad": "1.x",
                "any-version": "*",
                "local-lib": "file:../local-lib",
                "forked": "git+https://github.com/me/forked.git",
                "aliased": "npm:underscore@^1.13.0",
                "either": "^2.0.0 || ^3.0.0",
                "ranged": "1.2.3 - 2.0.0",
            },
            "devDependencies": {"jest": "29.0.0", "lodash": "4.17.20"},
            "peerDependencies": {"vue": "^3.0.0"},
        }
    )

    def test_exact_pin_is_marked_exact(self):
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_JSON, self.MANIFEST))
        assert deps["lodash"].version == "4.17.20"
        assert deps["lodash"].version_exact is True

    @pytest.mark.parametrize(
        ("name", "version"),
        [
            ("express", "4.18.0"),  # ^4.18.0 -> floor
            ("react", "18.2.1"),  # ~18.2.1 -> floor
            ("semver", "7.3.0"),  # comparator set -> lowest inclusive bound
            ("left-pad", "1.0.0"),  # 1.x -> zero-filled floor
            ("either", "2.0.0"),  # union -> lowest branch floor
            ("ranged", "1.2.3"),  # hyphen range -> left operand
        ],
    )
    def test_ranges_resolve_to_their_floor_and_are_marked_inexact(self, name, version):
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_JSON, self.MANIFEST))
        assert deps[name].version == version
        assert deps[name].version_exact is False, "a range is not an observed version"

    def test_dev_dependencies_are_classified_dev_only(self):
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_JSON, self.MANIFEST))
        assert deps["jest"].reachability is Reachability.DEV_ONLY

    def test_package_in_both_sections_counts_as_production(self):
        # lodash is in dependencies AND devDependencies. It ships, so suppressing
        # it as "dev only" would hide a real production exposure.
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_JSON, self.MANIFEST))
        assert deps["lodash"].reachability is Reachability.RUNTIME_DIRECT

    def test_peer_dependencies_reach_production(self):
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_JSON, self.MANIFEST))
        assert deps["vue"].reachability is Reachability.RUNTIME_DIRECT

    def test_npm_alias_resolves_to_the_real_package(self):
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_JSON, self.MANIFEST))
        assert "aliased" not in deps
        assert deps["underscore"].version == "1.13.0"

    def test_unresolvable_specs_become_warnings_not_silent_drops(self):
        parsed = parse_manifest(ManifestKind.PACKAGE_JSON, self.MANIFEST)
        names = by_name(parsed)
        for skipped in ("any-version", "local-lib", "forked"):
            assert skipped not in names
        warned = " ".join(parsed.warnings)
        assert "any-version" in warned
        assert "local-lib" in warned
        assert "forked" in warned

    def test_reads_project_name(self):
        assert parse_manifest(ManifestKind.PACKAGE_JSON, self.MANIFEST).project_name == "my-app"

    def test_invalid_json_raises(self):
        with pytest.raises(ManifestParseError):
            parse_manifest(ManifestKind.PACKAGE_JSON, "{not json")

    def test_json_array_raises(self):
        with pytest.raises(ManifestParseError):
            parse_manifest(ManifestKind.PACKAGE_JSON, "[1,2,3]")

    def test_empty_manifest_yields_no_dependencies(self):
        parsed = parse_manifest(ManifestKind.PACKAGE_JSON, '{"name": "x"}')
        assert parsed.dependencies == []


class TestResolveNpmFloor:
    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("1.2.3", ("1.2.3", True)),
            ("=1.2.3", ("1.2.3", True)),
            ("v1.2.3", ("1.2.3", True)),
            ("^1.2.3", ("1.2.3", False)),
            ("~1.2.3", ("1.2.3", False)),
            ("~1.2", ("1.2.0", False)),
            (">=1.2.3", ("1.2.3", False)),
            ("1.2.x", ("1.2.0", False)),
            ("4", ("4.0.0", False)),
            ("1.2.3-beta.1", ("1.2.3-beta.1", True)),
        ],
    )
    def test_resolution(self, spec, expected):
        assert resolve_npm_floor(spec) == expected

    @pytest.mark.parametrize("spec", ["*", "", "latest", "x", "<2.0.0"])
    def test_unbounded_specs_are_unresolvable(self, spec):
        # Guessing a version for these would invent findings out of nothing.
        assert resolve_npm_floor(spec) is None


class TestPackageLock:
    LOCK_V3 = json.dumps(
        {
            "name": "my-app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "dependencies": {"express": "^4.18.0"}},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/body-parser": {"version": "1.20.1"},
                "node_modules/jest": {"version": "29.0.0", "dev": True},
                "node_modules/express/node_modules/debug": {"version": "2.6.9"},
                "node_modules/@scope/pkg": {"version": "0.1.0"},
                "node_modules/linked": {"link": True, "resolved": "packages/linked"},
            },
        }
    )

    def test_lockfile_versions_are_exact(self):
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, self.LOCK_V3))
        assert all(d.version_exact for d in deps.values())
        assert deps["express"].version == "4.18.2"

    def test_direct_versus_transitive_is_read_from_the_root_entry(self):
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, self.LOCK_V3))
        assert deps["express"].reachability is Reachability.RUNTIME_DIRECT
        assert deps["body-parser"].reachability is Reachability.RUNTIME_TRANSITIVE

    def test_dev_flag_is_honoured(self):
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, self.LOCK_V3))
        assert deps["jest"].reachability is Reachability.DEV_ONLY

    def test_nested_and_scoped_packages_are_named_correctly(self):
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, self.LOCK_V3))
        assert deps["debug"].version == "2.6.9"
        assert deps["@scope/pkg"].version == "0.1.0"

    def test_symlinked_workspace_entries_are_skipped(self):
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, self.LOCK_V3))
        assert "linked" not in deps

    def test_lockfile_v1_format_is_supported(self):
        lock_v1 = json.dumps(
            {
                "name": "old-app",
                "lockfileVersion": 1,
                "dependencies": {
                    "express": {
                        "version": "4.17.1",
                        "dependencies": {"debug": {"version": "2.6.9"}},
                    },
                    "jest": {"version": "24.0.0", "dev": True},
                },
            }
        )
        deps = by_name(parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, lock_v1))
        assert deps["express"].reachability is Reachability.RUNTIME_DIRECT
        assert deps["debug"].reachability is Reachability.RUNTIME_TRANSITIVE
        assert deps["jest"].reachability is Reachability.DEV_ONLY

    def test_lockfile_without_a_recognised_section_raises(self):
        with pytest.raises(ManifestParseError):
            parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, '{"lockfileVersion": 3}')


class TestRequirementsTxt:
    MANIFEST = """
# Production dependencies
Django==4.2.7
requests>=2.28.0,<3.0.0
urllib3~=1.26.5
flask[async]==2.3.0
pyyaml >= 6.0
unpinned-package
numpy==1.24.*
pytz===2023.3
old-lib>1.0
marked; python_version < "3.10"
-r other-requirements.txt
--index-url https://pypi.org/simple
some-pkg @ https://example.com/some-pkg.whl
cryptography==41.0.0 \\
    --hash=sha256:deadbeef
"""

    def test_exact_pins_are_exact(self):
        deps = by_name(parse_manifest(ManifestKind.REQUIREMENTS_TXT, self.MANIFEST))
        assert deps["Django"].version == "4.2.7"
        assert deps["Django"].version_exact is True
        assert deps["pytz"].version == "2023.3"  # arbitrary equality
        assert deps["pytz"].version_exact is True

    @pytest.mark.parametrize(
        ("name", "version"),
        [
            ("requests", "2.28.0"),
            ("urllib3", "1.26.5"),
            ("pyyaml", "6.0"),
            ("numpy", "1.24"),
            ("old-lib", "1.0"),
        ],
    )
    def test_ranges_resolve_to_floors_marked_inexact(self, name, version):
        deps = by_name(parse_manifest(ManifestKind.REQUIREMENTS_TXT, self.MANIFEST))
        assert deps[name].version == version
        assert deps[name].version_exact is False

    def test_extras_are_stripped_from_the_package_name(self):
        deps = by_name(parse_manifest(ManifestKind.REQUIREMENTS_TXT, self.MANIFEST))
        assert deps["flask"].version == "2.3.0"

    def test_environment_markers_do_not_break_parsing(self):
        parsed = parse_manifest(ManifestKind.REQUIREMENTS_TXT, self.MANIFEST)
        # `marked` has a marker but no version, so it is warned about, not crashed on.
        assert "marked" not in by_name(parsed)
        assert any("marked" in w for w in parsed.warnings)

    def test_line_continuations_and_hashes_are_handled(self):
        deps = by_name(parse_manifest(ManifestKind.REQUIREMENTS_TXT, self.MANIFEST))
        assert deps["cryptography"].version == "41.0.0"

    def test_unpinned_package_is_warned_about_not_guessed(self):
        parsed = parse_manifest(ManifestKind.REQUIREMENTS_TXT, self.MANIFEST)
        assert "unpinned-package" not in by_name(parsed)
        assert any("unpinned-package" in w for w in parsed.warnings)

    def test_included_files_produce_a_coverage_warning(self):
        # Silently ignoring `-r other.txt` would understate what is unscanned.
        parsed = parse_manifest(ManifestKind.REQUIREMENTS_TXT, self.MANIFEST)
        assert any("other-requirements.txt" in w for w in parsed.warnings)

    def test_url_installs_are_skipped_with_a_warning(self):
        parsed = parse_manifest(ManifestKind.REQUIREMENTS_TXT, self.MANIFEST)
        assert "some-pkg" not in by_name(parsed)
        assert any("some-pkg" in w for w in parsed.warnings)

    def test_pip_options_are_ignored_without_warnings(self):
        parsed = parse_manifest(
            ManifestKind.REQUIREMENTS_TXT, "--index-url https://x/\nDjango==4.2\n"
        )
        assert parsed.warnings == []

    def test_malformed_line_does_not_abort_the_file(self):
        parsed = parse_manifest(
            ManifestKind.REQUIREMENTS_TXT, "good-pkg==1.0.0\n===garbage===\nother==2.0.0\n"
        )
        assert set(by_name(parsed)) == {"good-pkg", "other"}
        assert len(parsed.warnings) == 1

    def test_everything_is_treated_as_shipping_to_production(self):
        # requirements.txt has no dev/prod distinction, so we must not assume one.
        parsed = parse_manifest(ManifestKind.REQUIREMENTS_TXT, "Django==4.2.7\n")
        assert parsed.dependencies[0].reachability is Reachability.RUNTIME_DIRECT
        assert parsed.ecosystem is Ecosystem.PYPI


class TestResolvePypiFloor:
    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("==1.2.3", ("1.2.3", True)),
            ("===1.2.3", ("1.2.3", True)),
            (">=1.0,<2.0", ("1.0", False)),
            ("~=1.4.2", ("1.4.2", False)),
            ("==1.4.*", ("1.4", False)),
            (">=1.0,>=1.5", ("1.5", False)),  # tightest lower bound wins
        ],
    )
    def test_resolution(self, spec, expected):
        assert resolve_pypi_floor(spec) == expected

    @pytest.mark.parametrize("spec", ["", "<2.0", "!=1.5"])
    def test_specs_without_a_lower_bound_are_unresolvable(self, spec):
        assert resolve_pypi_floor(spec) is None


class TestGoMod:
    MANIFEST = """
module github.com/example/app

go 1.21
toolchain go1.21.5

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/crypto v0.14.0 // indirect
	github.com/stretchr/testify v1.8.4
)

require github.com/spf13/cobra v1.7.0

require golang.org/x/net v0.17.0 // indirect

replace github.com/old/pkg => github.com/new/pkg v2.0.0

exclude github.com/bad/pkg v1.0.0
"""

    def test_direct_requirements_are_direct(self):
        deps = by_name(parse_manifest(ManifestKind.GO_MOD, self.MANIFEST))
        assert deps["github.com/gin-gonic/gin"].reachability is Reachability.RUNTIME_DIRECT
        assert deps["github.com/spf13/cobra"].reachability is Reachability.RUNTIME_DIRECT

    def test_indirect_comment_marks_transitive(self):
        deps = by_name(parse_manifest(ManifestKind.GO_MOD, self.MANIFEST))
        assert deps["golang.org/x/crypto"].reachability is Reachability.RUNTIME_TRANSITIVE
        assert deps["golang.org/x/net"].reachability is Reachability.RUNTIME_TRANSITIVE

    def test_versions_are_exact_and_v_prefix_normalised(self):
        deps = by_name(parse_manifest(ManifestKind.GO_MOD, self.MANIFEST))
        assert deps["github.com/gin-gonic/gin"].version == "1.9.1"
        assert deps["github.com/gin-gonic/gin"].version_exact is True

    def test_module_path_is_captured(self):
        parsed = parse_manifest(ManifestKind.GO_MOD, self.MANIFEST)
        assert parsed.project_name == "github.com/example/app"

    def test_directives_are_not_mistaken_for_dependencies(self):
        deps = by_name(parse_manifest(ManifestKind.GO_MOD, self.MANIFEST))
        assert "go" not in deps
        assert "toolchain" not in deps
        assert "github.com/bad/pkg" not in deps  # excluded

    def test_replace_directive_substitutes_the_module(self):
        manifest = (
            "module x\n\nrequire github.com/old/pkg v1.0.0\n"
            "replace github.com/old/pkg => github.com/new/pkg v2.0.0\n"
        )
        deps = by_name(parse_manifest(ManifestKind.GO_MOD, manifest))
        assert "github.com/old/pkg" not in deps
        assert deps["github.com/new/pkg"].version == "2.0.0"

    def test_local_replace_is_warned_about_not_scanned(self):
        manifest = "module x\n\nrequire github.com/old/pkg v1.0.0\nreplace github.com/old/pkg => ../local\n"
        parsed = parse_manifest(ManifestKind.GO_MOD, manifest)
        assert parsed.dependencies == []
        assert any("local" in w for w in parsed.warnings)

    def test_pseudo_versions_are_preserved(self):
        manifest = "module x\n\nrequire github.com/a/b v0.0.0-20191109021931-daa7c04131f5\n"
        deps = by_name(parse_manifest(ManifestKind.GO_MOD, manifest))
        assert deps["github.com/a/b"].version == "0.0.0-20191109021931-daa7c04131f5"

    def test_incompatible_suffix_is_normalised(self):
        manifest = "module x\n\nrequire github.com/a/b v2.0.0+incompatible\n"
        deps = by_name(parse_manifest(ManifestKind.GO_MOD, manifest))
        assert deps["github.com/a/b"].version == "2.0.0"


class TestDeduplication:
    def test_same_package_at_two_versions_is_kept_separately(self):
        lock = json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {}},
                    "node_modules/debug": {"version": "4.3.4"},
                    "node_modules/express/node_modules/debug": {"version": "2.6.9"},
                },
            }
        )
        parsed = parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, lock)
        versions = sorted(d.version for d in parsed.dependencies if d.name == "debug")
        assert versions == ["2.6.9", "4.3.4"]

    def test_results_are_sorted_for_stable_output(self):
        parsed = parse_manifest(
            ManifestKind.PACKAGE_JSON, '{"dependencies": {"zebra": "1.0.0", "alpha": "1.0.0"}}'
        )
        assert [d.name for d in parsed.dependencies] == ["alpha", "zebra"]
