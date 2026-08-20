"""Signals about a package that are not about a vulnerability in it.

Everything else in `app.core.matching` answers "is this version affected by that
advisory?". These answer a different question -- "is depending on this package a
good idea?" -- and they are kept apart from severity deliberately. A package
with one maintainer is not a "medium vulnerability"; it is not a vulnerability
at all, and putting it on the same scale would make both scales useless.

Hence `SignalLevel`, whose words are chosen so they cannot be mistaken for
severities. There is no "high" or "critical" here.

The typosquat check is the interesting one, because the naive version is
useless. Edit distance alone flags `preact` as a typo of `react`, `fs-extra`
against `fs`, and every two-character package against every other. What makes
it work is a set of rules about *which* one-character differences are the ones
attackers actually use, plus an explicit list of well-known packages that sit
close to each other on purpose.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.core.types import Ecosystem

__all__ = [
    "POPULAR",
    "SignalKind",
    "SignalLevel",
    "SupplyChainSignal",
    "check_typosquat",
    "edit_distance",
]


class SignalKind(StrEnum):
    """What a supply-chain signal is saying."""

    TYPOSQUAT = "typosquat"
    UNMAINTAINED = "unmaintained"
    SINGLE_MAINTAINER = "single_maintainer"
    PROVENANCE_MISSING = "provenance_missing"
    PROVENANCE_VERIFIED = "provenance_verified"

    @property
    def label(self) -> str:
        return {
            "typosquat": "Name resembles a popular package",
            "unmaintained": "No releases for a long time",
            "single_maintainer": "One maintainer",
            "provenance_missing": "No build provenance",
            "provenance_verified": "Build provenance verified",
        }[self.value]


class SignalLevel(StrEnum):
    """How much attention a signal deserves.

    Deliberately *not* severity words. A supply-chain signal is a different
    kind of statement from "critical vulnerability", and sharing vocabulary
    with the severity scale would invite people to add them together.
    """

    CONCERNING = "concerning"
    NOTABLE = "notable"
    INFORMATIONAL = "informational"

    @property
    def label(self) -> str:
        return self.value.capitalize()


@dataclass(frozen=True, slots=True)
class SupplyChainSignal:
    """One observation about one package."""

    kind: SignalKind
    level: SignalLevel
    #: A sentence for the person reading it. Never a template with a blank in
    #: it: the specifics are what make this actionable.
    detail: str
    #: Structured specifics, for the interface to render without re-deriving.
    data: dict | None = None


# ---------------------------------------------------------------------------
# Typosquatting
# ---------------------------------------------------------------------------

#: Names an attacker would imitate, per ecosystem.
#:
#: Deliberately short and hand-picked rather than "the top 5,000 by downloads".
#: A longer list does not catch proportionally more attacks -- it catches
#: proportionally more *legitimate* packages that happen to sit one character
#: from something -- and every false positive here spends the user's attention
#: on nothing. These are the names worth impersonating.
POPULAR: dict[Ecosystem, frozenset[str]] = {
    Ecosystem.NPM: frozenset(
        {
            "axios",
            "babel",
            "chalk",
            "commander",
            "cors",
            "debug",
            "dotenv",
            "eslint",
            "express",
            "jest",
            "jquery",
            "lodash",
            "moment",
            "mongoose",
            "next",
            "nodemon",
            "prettier",
            "react",
            "react-dom",
            "redux",
            "request",
            "rimraf",
            "semver",
            "typescript",
            "uuid",
            "vue",
            "webpack",
            "yargs",
            "socket.io",
            "body-parser",
            "mocha",
            "chai",
            "underscore",
            "async",
            "bluebird",
            "classnames",
            "cross-env",
            "date-fns",
            "ejs",
            "fs-extra",
            "glob",
            "graphql",
            "husky",
            "inquirer",
            "ioredis",
            "jsonwebtoken",
            "minimist",
            "mkdirp",
            "nanoid",
            "node-fetch",
            "nodemailer",
            "passport",
            "pg",
            "prop-types",
            "puppeteer",
            "qs",
            "rxjs",
            "sequelize",
            "sharp",
            "styled-components",
            "tailwindcss",
            "vite",
            "winston",
            "ws",
            "zod",
        }
    ),
    Ecosystem.PYPI: frozenset(
        {
            "requests",
            "urllib3",
            "numpy",
            "pandas",
            "flask",
            "django",
            "boto3",
            "setuptools",
            "six",
            "click",
            "jinja2",
            "pytest",
            "pyyaml",
            "certifi",
            "cryptography",
            "sqlalchemy",
            "scipy",
            "pillow",
            "matplotlib",
            "beautifulsoup4",
            "selenium",
            "fastapi",
            "pydantic",
            "httpx",
            "aiohttp",
            "attrs",
            "colorama",
            "python-dateutil",
            "packaging",
            "typing-extensions",
            "wheel",
            "virtualenv",
            "psycopg2",
            "redis",
            "celery",
            "tensorflow",
            "torch",
            "scikit-learn",
            "tqdm",
            "openpyxl",
            "lxml",
            "markupsafe",
            "werkzeug",
            "uvicorn",
            "starlette",
            "rich",
            "typer",
            "poetry",
        }
    ),
    Ecosystem.GO: frozenset(
        {
            "github.com/gin-gonic/gin",
            "github.com/gorilla/mux",
            "github.com/stretchr/testify",
            "github.com/sirupsen/logrus",
            "github.com/spf13/cobra",
            "github.com/spf13/viper",
            "github.com/pkg/errors",
            "github.com/google/uuid",
            "github.com/go-sql-driver/mysql",
            "github.com/lib/pq",
            "google.golang.org/grpc",
            "gopkg.in/yaml.v3",
        }
    ),
}

#: Packages that genuinely sit within a character or two of a popular one.
#:
#: Every entry is a false positive somebody would otherwise have had to dismiss
#: forever. `preact` really is one edit from `react` and really is a different,
#: legitimate project; so is `vue` from `vuex`. Keeping this list is cheaper
#: than teaching the heuristic about each case, and far cheaper than the
#: alternative -- which is users learning that this signal is usually wrong.
KNOWN_DISTINCT: dict[Ecosystem, frozenset[str]] = {
    Ecosystem.NPM: frozenset(
        {
            "preact",
            "vuex",
            "next-auth",
            "reactstrap",
            "react-redux",
            "expressjs",
            "chalk-cli",
            "lodash-es",
            "moment-timezone",
            "uuidv4",
            "async-mutex",
            "qrcode",
            "pgpass",
            "wss",
            "cores",
            "corser",
            "debug-fabulous",
        }
    ),
    Ecosystem.PYPI: frozenset(
        {
            "requests-oauthlib",
            "urllib3-secure-extra",
            "flask-cors",
            "django-cors-headers",
            "pytest-cov",
            "six-py",
            "clickhouse-driver",
            "redis-py-cluster",
            "types-requests",
            "types-six",
            "attr",
            "attrs-strict",
        }
    ),
    Ecosystem.GO: frozenset(),
}

#: Below this, a one-character difference means nothing. `ms` and `fs` are one
#: apart and both real; so are `qs` and `js`. Short names are dense.
MIN_LENGTH = 5

#: Character pairs that look alike in a terminal or a browser. These are the
#: substitutions worth treating as deliberate rather than as coincidence.
_CONFUSABLE = {
    frozenset("l1"),
    frozenset("lI"),
    frozenset("o0"),
    frozenset("O0"),
    frozenset("s5"),
    frozenset("g9"),
    frozenset("b6"),
    frozenset("z2"),
}

#: Separators npm and PyPI treat as noise, and attackers as an opportunity.
_SEPARATORS = "-_."


def edit_distance(left: str, right: str, *, limit: int = 2) -> int:
    """Levenshtein distance, giving up once it exceeds `limit`.

    Bounded because the answer "more than two" is the only one this module
    acts on, and computing the exact distance between two unrelated 40-character
    module paths is work nobody reads.
    """
    if left == right:
        return 0
    if abs(len(left) - len(right)) > limit:
        return limit + 1

    previous = list(range(len(right) + 1))
    for i, lchar in enumerate(left, start=1):
        current = [i]
        best = i
        for j, rchar in enumerate(right, start=1):
            cost = 0 if lchar == rchar else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            current.append(value)
            best = min(best, value)
        if best > limit:
            return limit + 1
        previous = current

    return previous[-1]


def _canonical(name: str) -> str:
    """Strip what registries treat as insignificant.

    npm and PyPI both fold case, and PyPI folds `-`, `_` and `.` together. A
    name that differs only there is not a typo -- it is the same name.
    """
    lowered = name.strip().lower()
    return "".join(ch for ch in lowered if ch not in _SEPARATORS)


def _is_confusable_swap(left: str, right: str) -> bool:
    """One substitution, of a pair that looks alike."""
    if len(left) != len(right):
        return False
    differences = [(a, b) for a, b in zip(left, right, strict=True) if a != b]
    if len(differences) != 1:
        return False
    return frozenset(differences[0]) in _CONFUSABLE


def _is_transposition(left: str, right: str) -> bool:
    """Two adjacent characters swapped: `lodahs` for `lodash`."""
    if len(left) != len(right):
        return False
    differences = [i for i, (a, b) in enumerate(zip(left, right, strict=True)) if a != b]
    if len(differences) != 2:
        return False
    first, second = differences
    return second == first + 1 and left[first] == right[second] and left[second] == right[first]


def check_typosquat(name: str, ecosystem: Ecosystem) -> SupplyChainSignal | None:
    """Does this name look like an imitation of a popular package?

    Returns None for the overwhelming majority. The bar is deliberately high:
    a signal that fires on legitimate packages teaches people to ignore it, and
    an ignored typosquat warning is worse than none because it cost attention
    on the way past.
    """
    popular = POPULAR.get(ecosystem, frozenset())
    if not popular:
        return None

    lowered = name.strip().lower()

    # The package *is* the popular one.
    if lowered in popular:
        return None

    # Known to sit near a popular name and be a real project anyway.
    if lowered in KNOWN_DISTINCT.get(ecosystem, frozenset()):
        return None

    # Scoped npm packages (@scope/name) are namespaced by the registry, so
    # squatting the name inside somebody else's scope is not the attack this
    # looks for. Compare the bare name only when it is unscoped.
    if lowered.startswith("@"):
        return None

    if len(lowered) < MIN_LENGTH:
        return None

    canonical = _canonical(lowered)

    for target in popular:
        target_canonical = _canonical(target)

        # Same name once separators and case are folded away. Not a typo: npm
        # and PyPI resolve these to different packages, and an attacker
        # publishing `python-dateutil` as `python_dateutil` is squatting.
        if canonical == target_canonical and lowered != target:
            return SupplyChainSignal(
                kind=SignalKind.TYPOSQUAT,
                level=SignalLevel.CONCERNING,
                detail=(
                    f"{name} differs from {target} only in punctuation. "
                    "Registries treat those as different packages; people do not."
                ),
                data={"resembles": target, "kind": "separator"},
            )

        # Bounded at 2, not 1. Levenshtein scores a transposition as two
        # edits -- `lodahs` is distance 2 from `lodash` -- so a limit of 1
        # silently drops the single most common typo there is.
        distance = edit_distance(canonical, target_canonical, limit=2)
        if distance > 2:
            continue

        transposed = _is_transposition(canonical, target_canonical)
        if distance == 2 and not transposed:
            # Two unrelated edits is where the false positives live. Only the
            # swap is worth reporting at this distance.
            continue

        # Only report the shapes attackers use; "one character apart" on its
        # own catches too much that is simply a different package.
        if transposed:
            reason, description = "transposition", "two letters swapped"
        elif _is_confusable_swap(canonical, target_canonical):
            reason, description = "confusable", "a character that looks alike"
        elif len(canonical) != len(target_canonical):
            reason, description = "length", "one character added or missing"
        else:
            # A plain substitution of unrelated characters. `ledash` for
            # `lodash` is possible but so is an unrelated word, so this is the
            # weakest case and gets the lower level.
            reason, description = "substitution", "one character different"

        level = SignalLevel.NOTABLE if reason == "substitution" else SignalLevel.CONCERNING
        return SupplyChainSignal(
            kind=SignalKind.TYPOSQUAT,
            level=level,
            detail=(
                f"{name} is one character from {target} ({description}). "
                "Check you meant this package before shipping it."
            ),
            data={"resembles": target, "kind": reason},
        )

    return None
