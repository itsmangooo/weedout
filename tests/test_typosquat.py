"""The typosquat heuristic, and the false positives it must not produce.

A signal that fires on legitimate packages teaches people to ignore it, and an
ignored typosquat warning is worse than no warning at all — it cost attention
on the way past. So this file is weighted towards the negative cases: the whole
list of popular packages, their well-known near-neighbours, and the short names
where a one-character difference means nothing.

The naive version of this check flags `preact` as a typo of `react` and every
two-letter package against every other. Those are the tests that matter.
"""

from __future__ import annotations

import pytest

from app.core.supply_chain import (
    KNOWN_DISTINCT,
    MIN_LENGTH,
    POPULAR,
    SignalKind,
    SignalLevel,
    check_typosquat,
    edit_distance,
)
from app.core.types import Ecosystem
from tests.factories import set_manifest

NPM = Ecosystem.NPM
PYPI = Ecosystem.PYPI


class TestEditDistance:
    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [
            ("lodash", "lodash", 0),
            ("lodash", "lodsh", 1),
            ("lodash", "ledash", 1),
            ("lodash", "lodahs", 2),
            ("abc", "xyz", 3),
        ],
    )
    def test_it_measures(self, left, right, expected):
        assert edit_distance(left, right, limit=5) == expected

    def test_it_gives_up_past_the_limit(self):
        """The answer "more than two" is the only one this module acts on."""
        assert edit_distance("a" * 40, "b" * 40, limit=2) == 3

    def test_a_length_gap_is_answered_without_the_matrix(self):
        assert edit_distance("ab", "abcdefgh", limit=2) == 3


class TestItCatchesTheRealShapes:
    @pytest.mark.parametrize(
        ("name", "ecosystem", "resembles", "kind"),
        [
            ("lodahs", NPM, "lodash", "transposition"),
            ("typescirpt", NPM, "typescript", "transposition"),
            ("reqeusts", PYPI, "requests", "transposition"),
            ("djnago", PYPI, "django", "transposition"),
            ("requsts", PYPI, "requests", "length"),
            ("expres", NPM, "express", "length"),
            ("numpyy", PYPI, "numpy", "length"),
            ("l0dash", NPM, "lodash", "confusable"),
            ("python_dateutil", PYPI, "python-dateutil", "separator"),
        ],
    )
    def test_it_flags(self, name, ecosystem, resembles, kind):
        signal = check_typosquat(name, ecosystem)

        assert signal is not None, f"{name} should have been flagged"
        assert signal.kind is SignalKind.TYPOSQUAT
        assert signal.data["resembles"] == resembles
        assert signal.data["kind"] == kind

    def test_a_transposition_is_reachable_at_all(self):
        """The bug this guards: Levenshtein scores a swap as two edits, so a
        distance limit of one silently dropped the commonest typo there is."""
        assert check_typosquat("lodahs", NPM) is not None

    def test_the_detail_names_what_it_resembles(self):
        """A signal that says "this looks suspicious" without saying what it
        looks like is not actionable."""
        signal = check_typosquat("lodahs", NPM)
        assert "lodash" in signal.detail

    def test_a_plain_substitution_is_only_notable(self):
        """`ledash` could be a typo or an unrelated word. The shapes that are
        unambiguously deliberate rank higher than the one that is not."""
        confusable = check_typosquat("l0dash", NPM)
        substitution = check_typosquat("ledash", NPM)

        assert confusable.level is SignalLevel.CONCERNING
        assert substitution.level is SignalLevel.NOTABLE


class TestItDoesNotCryWolf:
    @pytest.mark.parametrize("ecosystem", [NPM, PYPI])
    def test_no_popular_package_flags_itself(self, ecosystem):
        """The most embarrassing possible false positive."""
        for name in POPULAR[ecosystem]:
            assert check_typosquat(name, ecosystem) is None, name

    @pytest.mark.parametrize("ecosystem", [NPM, PYPI])
    def test_no_known_neighbour_flags(self, ecosystem):
        """`preact` genuinely is one edit from `react` and genuinely is a
        different, legitimate project."""
        for name in KNOWN_DISTINCT[ecosystem]:
            assert check_typosquat(name, ecosystem) is None, name

    @pytest.mark.parametrize("name", ["ms", "fs", "qs", "js", "ws", "pg", "vue"])
    def test_short_names_are_left_alone(self, name):
        """Short names are dense: at two characters almost everything is one
        edit from something. Documented limitation -- `flsk` is not caught for
        the same reason, and that is the right trade."""
        assert check_typosquat(name, NPM) is None
        assert len(name) < MIN_LENGTH or name in POPULAR[NPM]

    @pytest.mark.parametrize(
        "name",
        [
            "my-internal-app",
            "acme-design-system",
            "company-shared-utils",
            "some-really-long-package-name-nobody-imitates",
        ],
    )
    def test_ordinary_names_are_left_alone(self, name):
        assert check_typosquat(name, NPM) is None

    def test_a_scoped_package_is_left_alone(self):
        """npm scopes are namespaced by the registry, so publishing inside
        somebody else's scope is not the attack this looks for."""
        assert check_typosquat("@types/node", NPM) is None
        assert check_typosquat("@acme/lodash", NPM) is None

    def test_the_wrong_ecosystem_is_not_consulted(self):
        """`numpy` is a PyPI name. An npm package called `numpyy` is not
        imitating it, because nobody would be looking for it there."""
        assert check_typosquat("numpyy", NPM) is None

    def test_an_ecosystem_with_no_list_is_silent(self):
        """Go module paths are long and namespaced by domain, so the same
        heuristic would be noise. Returning nothing beats guessing."""
        assert check_typosquat("github.com/acme/thing", Ecosystem.GO) is None


class TestReconciliation:
    async def _project(self, db, owner, packages: list[str]):
        import json

        from app.core.types import ManifestKind
        from tests.test_scan_pipeline import make_target, seed_mirror

        await seed_mirror(db)
        target = await make_target(db, owner)
        target.manifest_kind = ManifestKind.PACKAGE_JSON
        await set_manifest(
            db, target, json.dumps({"dependencies": {name: "1.0.0" for name in packages}})
        )
        return target

    async def test_a_pro_scan_raises_the_signal(self, db, pro_user):
        from app.services.scan_service import scan_target
        from app.services.supply_chain_service import open_signals

        target = await self._project(db, pro_user, ["lodahs", "express"])
        await scan_target(db, target)
        await db.commit()

        signals = await open_signals(db, target.id)
        assert [s.package_name for s in signals] == ["lodahs"]
        assert signals[0].kind is SignalKind.TYPOSQUAT

    async def test_a_free_scan_raises_the_signal(self, db, user):
        from app.services.scan_service import scan_target
        from app.services.supply_chain_service import open_signals

        target = await self._project(db, user, ["lodahs"])
        await scan_target(db, target)
        await db.commit()

        signals = await open_signals(db, target.id)
        assert [signal.package_name for signal in signals] == ["lodahs"]

    async def test_a_signal_is_not_raised_twice(self, db, pro_user):
        from app.services.scan_service import scan_target
        from app.services.supply_chain_service import open_signals

        target = await self._project(db, pro_user, ["lodahs"])
        await scan_target(db, target)
        await db.commit()
        await scan_target(db, target)
        await db.commit()

        assert len(await open_signals(db, target.id)) == 1

    async def test_a_dismissal_survives_a_rescan(self, db, pro_user):
        """Being told a second time that you chose this on purpose is how a
        signal gets switched off entirely."""
        from sqlalchemy import select

        from app.core.types import AlertStatus
        from app.models import SupplyChainFinding
        from app.services.scan_service import scan_target
        from app.services.supply_chain_service import open_signals

        target = await self._project(db, pro_user, ["lodahs"])
        await scan_target(db, target)
        await db.commit()

        row = (await db.execute(select(SupplyChainFinding))).scalars().one()
        row.status = AlertStatus.DISMISSED
        row.dismiss_note = "Deliberate: it is our own fork."
        await db.commit()

        await scan_target(db, target)
        await db.commit()

        await db.refresh(row)
        assert row.status is AlertStatus.DISMISSED
        assert await open_signals(db, target.id) == []

    async def test_removing_the_package_clears_the_signal(self, db, pro_user):
        """It was a fact about a version of this project, not about the
        project, so it is deleted rather than kept as resolved history."""
        import json

        from sqlalchemy import select

        from app.models import SupplyChainFinding
        from app.services.scan_service import scan_target

        target = await self._project(db, pro_user, ["lodahs"])
        await scan_target(db, target)
        await db.commit()
        assert (await db.execute(select(SupplyChainFinding))).scalars().first() is not None

        await set_manifest(db, target, json.dumps({"dependencies": {"express": "1.0.0"}}))
        await scan_target(db, target)
        await db.commit()

        assert (await db.execute(select(SupplyChainFinding))).scalars().first() is None


class TestItIsShownSeparately:
    async def test_the_page_keeps_it_apart_from_vulnerabilities(self, db, pro_user, client):
        """The constraint: a supply-chain signal must not be readable as a
        severity tier."""
        import json

        from app.core.types import ManifestKind
        from app.security import hash_password
        from app.services.scan_service import scan_target
        from tests.conftest import sign_in
        from tests.test_scan_pipeline import make_target, seed_mirror

        pro_user.password_hash = hash_password("correct-horse-battery")
        await seed_mirror(db)
        target = await make_target(db, pro_user)
        target.manifest_kind = ManifestKind.PACKAGE_JSON
        await set_manifest(db, target, json.dumps({"dependencies": {"lodahs": "1.0.0"}}))
        await scan_target(db, target)
        await db.commit()

        await sign_in(client, pro_user.email)
        response = await client.get(f"/api/internal/projects/{target.id}")

        assert response.status_code == 200
        body = response.json()

        # Delivered in its own section, not mixed into findings — a package
        # that merely looks like a typo is not a vulnerability.
        signals = body["supply_chain"]
        assert any(signal["kind"] == "typosquat" for signal in signals)
        assert body["findings"] == []

        # And in its own vocabulary. "concerning" is not a severity, and
        # borrowing "critical" for it would cheapen the real ones.
        levels = {signal["level"] for signal in signals}
        assert "concerning" in levels
        assert levels.isdisjoint({"critical", "high", "medium", "low"})
