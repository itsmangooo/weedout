"""Version parsing, ordering and range evaluation for npm, PyPI and Go.

Every "is this dependency affected?" question ultimately reduces to a version
comparison, and each ecosystem orders versions differently. This module keeps
that per-ecosystem knowledge in one testable place:

* **npm** and **Go** use SemVer 2.0.0 precedence (Go additionally prefixes a
  ``v`` and encodes untagged commits as ``v0.0.0-<timestamp>-<hash>``
  pseudo-versions, which sort as ordinary prereleases).
* **PyPI** uses PEP 440, delegated to ``packaging`` rather than reimplemented —
  epochs, post-releases and local versions have too many edge cases to redo.

Parsing is deliberately lenient about *shape* (``"1"`` and ``"1.2"`` zero-fill)
because OSV advisories are not consistent about it, but strict about
*garbage* — an unparseable version raises ``InvalidVersion`` rather than
silently sorting to zero, which would turn every advisory into a false positive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from packaging.version import InvalidVersion as _Pep440InvalidVersion
from packaging.version import Version as Pep440Version

from app.core.types import AffectedPackage, AffectedRange, Ecosystem

__all__ = [
    "InvalidVersion",
    "SemVer",
    "compare",
    "in_range",
    "normalize",
    "version_matches",
]


class InvalidVersion(ValueError):
    """Raised when a version string cannot be interpreted in its ecosystem."""


_SEMVER_RE = re.compile(
    r"""
    ^\s*v?                                  # optional leading v (Go, sloppy npm)
    (?P<major>\d+)
    (?:\.(?P<minor>\d+))?                   # minor/patch optional: OSV emits "1" and "1.2"
    (?:\.(?P<patch>\d+))?
    (?:\.(?P<extra>\d+(?:\.\d+)*))?         # 4th+ component (seen in the wild, e.g. 1.2.3.4)
    (?:-(?P<prerelease>[0-9A-Za-z.\-]+))?
    (?:\+(?P<build>[0-9A-Za-z.\-]+))?       # build metadata: ignored for precedence
    \s*$
    """,
    re.VERBOSE,
)

_NUMERIC_RE = re.compile(r"^\d+$")


@dataclass(frozen=True, slots=True)
class SemVer:
    """A SemVer 2.0.0 version with total ordering.

    Build metadata is parsed but excluded from comparison, per the spec.
    ``extra`` holds any 4th-and-beyond numeric components; real SemVer has none,
    but published packages occasionally do, and dropping them would make
    ``1.2.3.4`` compare equal to ``1.2.3``.
    """

    major: int
    minor: int
    patch: int
    extra: tuple[int, ...] = ()
    prerelease: tuple[str | int, ...] = ()
    build: str | None = None

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def _release_key(self) -> tuple[int, ...]:
        return (self.major, self.minor, self.patch, *self.extra)

    def _compare(self, other: SemVer) -> int:
        a, b = self._release_key(), other._release_key()
        # Zero-pad so (1,2,3) and (1,2,3,0) compare equal.
        width = max(len(a), len(b))
        a += (0,) * (width - len(a))
        b += (0,) * (width - len(b))
        if a != b:
            return -1 if a < b else 1

        # A version WITH a prerelease has lower precedence than one without.
        if not self.prerelease and not other.prerelease:
            return 0
        if not self.prerelease:
            return 1
        if not other.prerelease:
            return -1

        for x, y in zip(self.prerelease, other.prerelease, strict=False):
            if x == y:
                continue
            x_num, y_num = isinstance(x, int), isinstance(y, int)
            if x_num and y_num:
                return -1 if x < y else 1  # type: ignore[operator]
            if x_num != y_num:
                # Numeric identifiers always have lower precedence than alphanumeric.
                return -1 if x_num else 1
            return -1 if str(x) < str(y) else 1

        # All shared identifiers equal: the one with more fields wins.
        if len(self.prerelease) == len(other.prerelease):
            return 0
        return -1 if len(self.prerelease) < len(other.prerelease) else 1

    def __lt__(self, other: SemVer) -> bool:
        return self._compare(other) < 0

    def __le__(self, other: SemVer) -> bool:
        return self._compare(other) <= 0

    def __gt__(self, other: SemVer) -> bool:
        return self._compare(other) > 0

    def __ge__(self, other: SemVer) -> bool:
        return self._compare(other) >= 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._compare(other) == 0

    def __hash__(self) -> int:
        return hash((self._release_key(), self.prerelease))

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.extra:
            base += "." + ".".join(str(p) for p in self.extra)
        if self.prerelease:
            base += "-" + ".".join(str(p) for p in self.prerelease)
        if self.build:
            base += f"+{self.build}"
        return base

    @classmethod
    def parse(cls, raw: str) -> SemVer:
        match = _SEMVER_RE.match(raw or "")
        if not match:
            raise InvalidVersion(f"not a semver-style version: {raw!r}")

        prerelease: tuple[str | int, ...] = ()
        if pre := match.group("prerelease"):
            parts: list[str | int] = []
            for ident in pre.split("."):
                if _NUMERIC_RE.match(ident):
                    parts.append(int(ident))
                else:
                    parts.append(ident)
            prerelease = tuple(parts)

        extra: tuple[int, ...] = ()
        if raw_extra := match.group("extra"):
            extra = tuple(int(p) for p in raw_extra.split("."))

        return cls(
            major=int(match.group("major")),
            minor=int(match.group("minor") or 0),
            patch=int(match.group("patch") or 0),
            extra=extra,
            prerelease=prerelease,
            build=match.group("build"),
        )


def normalize(ecosystem: Ecosystem, raw: str) -> str:
    """Canonicalise a raw version string for storage and equality checks.

    Go module versions carry a ``v`` prefix in ``go.mod`` but OSV advisories
    write them bare, so both sides are normalised to the bare form. The
    ``+incompatible`` suffix Go appends to pre-modules majors is build metadata
    and is dropped.
    """
    value = (raw or "").strip()
    if ecosystem is Ecosystem.GO:
        value = value.removeprefix("v")
        value = value.removesuffix("+incompatible")
    elif ecosystem is Ecosystem.NPM:
        value = value.removeprefix("v")
    return value


class _MavenVersion:
    """A parsed Maven version, ordered by `_maven_compare`."""

    __slots__ = ("raw",)

    def __init__(self, raw: str) -> None:
        self.raw = raw

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _MavenVersion) and _maven_compare(self.raw, other.raw) == 0

    def __lt__(self, other: _MavenVersion) -> bool:
        return _maven_compare(self.raw, other.raw) < 0

    def __hash__(self) -> int:
        return hash(tuple(_maven_trim(_maven_tokens(self.raw))))

    def __repr__(self) -> str:
        return f"<MavenVersion {self.raw}>"


@lru_cache(maxsize=8192)
def _parse(ecosystem: Ecosystem, raw: str) -> SemVer | Pep440Version:
    value = normalize(ecosystem, raw)
    if not value:
        raise InvalidVersion("empty version string")
    if ecosystem is Ecosystem.PYPI:
        try:
            return Pep440Version(value)
        except _Pep440InvalidVersion as exc:
            raise InvalidVersion(f"not a PEP 440 version: {raw!r}") from exc
    if ecosystem is Ecosystem.MAVEN:
        # Anything with a token in it is a Maven version; the scheme has no
        # invalid forms, only unusual ones. Returning a sortable stand-in keeps
        # `affects()`'s "can I reason about this at all" gate honest without
        # pretending Maven versions are semver.
        if not _maven_tokens(value):
            raise InvalidVersion(f"no version tokens in {raw!r}")
        return _MavenVersion(value)
    return SemVer.parse(value)


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------

#: Maven's qualifier ladder, lowest first. A release — no qualifier at all —
#: sits above every pre-release and below a service pack.
#:
#: Taken from Maven's own `ComparableVersion`. The ordering is not alphabetical
#: and cannot be guessed: `rc` outranks `milestone`, and `sp` outranks the
#: release it patches.
_MAVEN_QUALIFIERS: dict[str, int] = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "milestone": 2,
    "m": 2,
    "rc": 3,
    "cr": 3,
    "snapshot": 4,
    "": 5,  # the release itself
    "ga": 5,
    "final": 5,
    "release": 5,
    "sp": 6,
}

#: Anything not in the table sorts above every known qualifier, which is what
#: Maven does — an unrecognised qualifier is assumed to be a downstream build
#: rather than a pre-release. `31.1-jre` is therefore above `31.1`.
_MAVEN_UNKNOWN_RANK = 7

_MAVEN_TOKEN_RE = re.compile(r"(\d+|[A-Za-z]+)")


def _maven_tokens(value: str) -> list[tuple[int, object]]:
    """Split a Maven version into comparable tokens.

    Separators are `.` and `-`, and a digit/letter boundary also separates —
    so `1.0rc2` tokenises the same as `1.0-rc-2`. Each token is tagged so that
    numbers never compare against words: `(0, int)` for numeric, `(1, rank,
    text)` for qualifiers.
    """
    tokens: list[tuple[int, object]] = []
    for part in re.split(r"[.\-_+]", value.strip().lower()):
        if not part:
            continue
        for piece in _MAVEN_TOKEN_RE.findall(part):
            if piece.isdigit():
                tokens.append((0, int(piece)))
            else:
                rank = _MAVEN_QUALIFIERS.get(piece, _MAVEN_UNKNOWN_RANK)
                tokens.append((1, rank, piece))
    return tokens


def _maven_trim(tokens: list) -> list:
    """Drop trailing nulls so `1.0.0` and `1` are the same version.

    A trailing numeric zero and a trailing release-rank qualifier are both
    "nothing", which is why `1.0`, `1.0.0` and `1.0.0.RELEASE` compare equal.
    """
    while tokens:
        last = tokens[-1]
        if last[0] == 0 and last[1] == 0:
            tokens.pop()
        elif last[0] == 1 and last[1] == _MAVEN_QUALIFIERS[""]:
            tokens.pop()
        else:
            break
    return tokens


def _maven_compare(left: str, right: str) -> int:
    a = _maven_trim(_maven_tokens(left))
    b = _maven_trim(_maven_tokens(right))

    for index in range(max(len(a), len(b))):
        # A missing token is a null: numeric zero against a number, release
        # rank against a qualifier. Comparing against the *other* side's kind
        # is what makes `1.0` < `1.0.1` and `1.0-rc1` < `1.0`.
        one = a[index] if index < len(a) else ((0, 0) if b[index][0] == 0 else (1, 5, ""))
        two = b[index] if index < len(b) else ((0, 0) if a[index][0] == 0 else (1, 5, ""))

        if one[0] != two[0]:
            # A number outranks a qualifier at the same position: `1.1` beats
            # `1.0-rc`, and more usefully `1.1` beats `1.1-jre`.
            return 1 if one[0] == 0 else -1

        if one[0] == 0:
            if one[1] != two[1]:
                return -1 if one[1] < two[1] else 1
            continue

        if one[1] != two[1]:
            return -1 if one[1] < two[1] else 1
        # Same rank, both unknown: fall back to lexical, as Maven does.
        if one[2] != two[2]:
            return -1 if one[2] < two[2] else 1

    return 0


def compare(ecosystem: Ecosystem, left: str, right: str) -> int:
    """Return -1, 0 or 1 for ``left`` vs ``right`` under ``ecosystem`` rules."""
    if ecosystem is Ecosystem.MAVEN:
        # Maven's ordering is its own: qualifiers rank on a fixed ladder rather
        # than alphabetically, and `1.0`, `1.0.0` and `1.0.0.RELEASE` are one
        # version. Semver rejects most of those outright.
        if not left.strip() or not right.strip():
            raise InvalidVersion("empty version string")
        return _maven_compare(left, right)

    a = _parse(ecosystem, left)
    b = _parse(ecosystem, right)
    if a == b:
        return 0
    return -1 if a < b else 1  # type: ignore[operator]


def in_range(ecosystem: Ecosystem, version: str, rng: AffectedRange) -> bool:
    """Is ``version`` inside the half-open interval ``rng`` describes?

    OSV models an affected window as an ``introduced`` event followed by either
    a ``fixed`` event (exclusive upper bound — the fix landed *in* that version)
    or a ``last_affected`` event (inclusive upper bound). An absent upper bound
    means "still affected in every later version".
    """
    if rng.introduced not in (None, "", "0"):
        assert rng.introduced is not None
        if compare(ecosystem, version, rng.introduced) < 0:
            return False

    if rng.fixed not in (None, ""):
        assert rng.fixed is not None
        return compare(ecosystem, version, rng.fixed) < 0

    if rng.last_affected not in (None, ""):
        assert rng.last_affected is not None
        return compare(ecosystem, version, rng.last_affected) <= 0

    return True


def version_matches(ecosystem: Ecosystem, version: str, affected: AffectedPackage) -> bool:
    """Is ``version`` affected by this advisory entry?

    An advisory may enumerate exact ``versions``, describe ``ranges``, or both
    (the enumeration is usually a materialised view of the ranges). Either
    hitting counts. Individually unparseable bounds are skipped rather than
    failing the whole check, so one malformed range in a record cannot mask a
    valid one — but a version we cannot parse at all is reported as not
    matching, since we have no basis to claim otherwise.
    """
    try:
        _parse(ecosystem, version)
    except InvalidVersion:
        return False

    normalized = normalize(ecosystem, version)
    for candidate in affected.versions:
        if normalize(ecosystem, candidate) == normalized:
            return True

    for rng in affected.ranges:
        try:
            if in_range(ecosystem, version, rng):
                return True
        except InvalidVersion:
            continue

    return False


def first_fixed_version(
    ecosystem: Ecosystem, version: str, affected: AffectedPackage
) -> str | None:
    """The lowest ``fixed`` version strictly above ``version``, if the advisory has one.

    This is what the UI tells the user to upgrade to. Ranges whose ``fixed``
    bound is at or below the installed version belong to an earlier affected
    window and are ignored.
    """
    candidates: list[str] = []
    for rng in affected.ranges:
        if not rng.fixed:
            continue
        try:
            if compare(ecosystem, rng.fixed, version) > 0:
                candidates.append(rng.fixed)
        except InvalidVersion:
            continue

    if not candidates:
        return None

    lowest = candidates[0]
    for candidate in candidates[1:]:
        try:
            if compare(ecosystem, candidate, lowest) < 0:
                lowest = candidate
        except InvalidVersion:
            continue
    return lowest
