"""Version ordering and range evaluation.

A false negative here means a real, exploited vulnerability is silently dropped,
so the edge cases (prereleases, zero-filling, Go pseudo-versions, inclusive vs
exclusive bounds) are covered explicitly rather than assumed.
"""

from __future__ import annotations

import pytest

from app.core.types import AffectedPackage, AffectedRange, Ecosystem
from app.core.versions import (
    InvalidVersion,
    SemVer,
    compare,
    first_fixed_version,
    in_range,
    normalize,
    version_matches,
)

NPM = Ecosystem.NPM
PYPI = Ecosystem.PYPI
GO = Ecosystem.GO


class TestSemVerOrdering:
    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [
            ("1.0.0", "1.0.0", 0),
            ("1.0.0", "1.0.1", -1),
            ("1.0.1", "1.0.0", 1),
            ("1.9.0", "1.10.0", -1),  # numeric, not lexicographic
            ("2.0.0", "10.0.0", -1),
            # Partial versions zero-fill.
            ("1", "1.0.0", 0),
            ("1.2", "1.2.0", 0),
            ("1.2", "1.2.1", -1),
            # Build metadata is ignored for precedence.
            ("1.0.0+build.1", "1.0.0+build.9", 0),
            ("1.0.0+build", "1.0.0", 0),
            # Extra numeric components are significant.
            ("1.2.3.4", "1.2.3", 1),
            ("1.2.3", "1.2.3.0", 0),
        ],
    )
    def test_release_precedence(self, left, right, expected):
        assert compare(NPM, left, right) == expected

    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [
            # A prerelease is lower than its release.
            ("1.0.0-alpha", "1.0.0", -1),
            ("1.0.0", "1.0.0-rc.1", 1),
            # The full semver.org precedence chain.
            ("1.0.0-alpha", "1.0.0-alpha.1", -1),
            ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
            ("1.0.0-alpha.beta", "1.0.0-beta", -1),
            ("1.0.0-beta", "1.0.0-beta.2", -1),
            ("1.0.0-beta.2", "1.0.0-beta.11", -1),  # numeric identifiers compare numerically
            ("1.0.0-beta.11", "1.0.0-rc.1", -1),
            # Numeric identifiers rank below alphanumeric ones.
            ("1.0.0-1", "1.0.0-alpha", -1),
        ],
    )
    def test_prerelease_precedence(self, left, right, expected):
        assert compare(NPM, left, right) == expected

    def test_garbage_is_rejected_not_treated_as_zero(self):
        # Sorting an unparseable version to 0.0.0 would make every "introduced: 0"
        # advisory match it, manufacturing false positives.
        for bad in ["", "latest", "not-a-version", "v", "abc.def"]:
            with pytest.raises(InvalidVersion):
                compare(NPM, bad, "1.0.0")

    def test_semver_is_hashable_and_equal_by_precedence(self):
        assert SemVer.parse("1.2.3+a") == SemVer.parse("1.2.3+b")
        assert len({SemVer.parse("1.2"), SemVer.parse("1.2.0")}) == 1


class TestNormalize:
    def test_go_strips_v_prefix_and_incompatible_suffix(self):
        assert normalize(GO, "v1.2.3") == "1.2.3"
        assert normalize(GO, "v2.0.0+incompatible") == "2.0.0"

    def test_npm_tolerates_stray_v(self):
        assert normalize(NPM, "v1.2.3") == "1.2.3"

    def test_pypi_is_left_alone(self):
        assert normalize(PYPI, "1.2.3.post1") == "1.2.3.post1"

    def test_go_and_osv_forms_compare_equal(self):
        # go.mod writes "v1.2.3"; OSV writes "1.2.3". They must not disagree.
        assert compare(GO, "v1.2.3", "1.2.3") == 0


class TestPep440:
    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [
            ("1.0", "1.0.0", 0),
            ("1.0a1", "1.0", -1),
            ("1.0", "1.0.post1", -1),
            ("1.0.post1", "1.0.1", -1),
            ("1!1.0", "2.0", 1),  # epoch wins
            ("1.0.dev1", "1.0a1", -1),
        ],
    )
    def test_pep440_precedence(self, left, right, expected):
        assert compare(PYPI, left, right) == expected

    def test_invalid_pep440_rejected(self):
        with pytest.raises(InvalidVersion):
            compare(PYPI, "not-a-version", "1.0")


class TestInRange:
    def test_fixed_is_an_exclusive_upper_bound(self):
        rng = AffectedRange(introduced="0", fixed="4.17.21")
        assert in_range(NPM, "4.17.20", rng) is True
        # The fix landed IN 4.17.21, so 4.17.21 itself is safe.
        assert in_range(NPM, "4.17.21", rng) is False
        assert in_range(NPM, "5.0.0", rng) is False

    def test_last_affected_is_an_inclusive_upper_bound(self):
        rng = AffectedRange(introduced="1.0.0", fixed=None, last_affected="1.4.2")
        assert in_range(NPM, "1.4.2", rng) is True
        assert in_range(NPM, "1.4.3", rng) is False

    def test_introduced_is_inclusive(self):
        rng = AffectedRange(introduced="2.0.0", fixed="2.5.0")
        assert in_range(NPM, "1.9.9", rng) is False
        assert in_range(NPM, "2.0.0", rng) is True

    def test_no_upper_bound_means_still_affected(self):
        rng = AffectedRange(introduced="1.0.0", fixed=None)
        assert in_range(NPM, "99.0.0", rng) is True

    def test_introduced_zero_means_from_the_beginning(self):
        rng = AffectedRange(introduced="0", fixed="1.0.0")
        assert in_range(NPM, "0.0.1", rng) is True


class TestVersionMatches:
    def test_matches_via_enumerated_versions(self):
        pkg = AffectedPackage(ecosystem=NPM, name="x", ranges=(), versions=("1.0.0", "1.0.1"))
        assert version_matches(NPM, "1.0.1", pkg) is True
        assert version_matches(NPM, "1.0.2", pkg) is False

    def test_ranges_and_versions_are_a_union(self):
        pkg = AffectedPackage(
            ecosystem=NPM,
            name="x",
            ranges=(AffectedRange(introduced="2.0.0", fixed="2.1.0"),),
            versions=("1.0.0",),
        )
        assert version_matches(NPM, "1.0.0", pkg) is True
        assert version_matches(NPM, "2.0.5", pkg) is True
        assert version_matches(NPM, "3.0.0", pkg) is False

    def test_multiple_disjoint_windows(self):
        pkg = AffectedPackage(
            ecosystem=NPM,
            name="x",
            ranges=(
                AffectedRange(introduced="0", fixed="1.5.0"),
                AffectedRange(introduced="2.0.0", fixed="2.3.0"),
            ),
        )
        assert version_matches(NPM, "1.0.0", pkg) is True
        assert version_matches(NPM, "1.9.0", pkg) is False  # patched in the 1.x line
        assert version_matches(NPM, "2.1.0", pkg) is True
        assert version_matches(NPM, "2.3.0", pkg) is False

    def test_unparseable_installed_version_does_not_match(self):
        pkg = AffectedPackage(ecosystem=NPM, name="x", ranges=(AffectedRange("0", "9.9.9"),))
        assert version_matches(NPM, "garbage", pkg) is False

    def test_one_malformed_range_does_not_mask_a_valid_one(self):
        pkg = AffectedPackage(
            ecosystem=NPM,
            name="x",
            ranges=(
                AffectedRange(introduced="not-a-version", fixed="???"),
                AffectedRange(introduced="1.0.0", fixed="2.0.0"),
            ),
        )
        assert version_matches(NPM, "1.5.0", pkg) is True

    def test_go_version_with_v_prefix_matches_bare_osv_range(self):
        pkg = AffectedPackage(
            ecosystem=GO, name="github.com/x/y", ranges=(AffectedRange("0", "1.4.0"),)
        )
        assert version_matches(GO, "v1.3.0", pkg) is True
        assert version_matches(GO, "v1.4.0", pkg) is False

    def test_go_pseudo_version_sorts_as_prerelease(self):
        # v0.0.0-2019... precedes any real v0.0.x tag.
        pkg = AffectedPackage(
            ecosystem=GO, name="github.com/x/y", ranges=(AffectedRange("0", "0.0.1"),)
        )
        assert version_matches(GO, "v0.0.0-20191109021931-daa7c04131f5", pkg) is True


class TestFirstFixedVersion:
    def test_picks_lowest_fix_above_installed_version(self):
        pkg = AffectedPackage(
            ecosystem=NPM,
            name="x",
            ranges=(
                AffectedRange(introduced="0", fixed="1.5.0"),
                AffectedRange(introduced="2.0.0", fixed="2.3.0"),
            ),
        )
        assert first_fixed_version(NPM, "1.0.0", pkg) == "1.5.0"
        # An installed 2.1.0 must not be told to "upgrade" to 1.5.0.
        assert first_fixed_version(NPM, "2.1.0", pkg) == "2.3.0"

    def test_returns_none_when_no_fix_published(self):
        pkg = AffectedPackage(ecosystem=NPM, name="x", ranges=(AffectedRange("0", None),))
        assert first_fixed_version(NPM, "1.0.0", pkg) is None
