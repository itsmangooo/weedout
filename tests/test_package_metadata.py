"""Unmaintained, single-maintainer and provenance signals.

These three are the only checks in the product that need to ask somebody else's
server a question, so the shape is a cache and a job: the job pays the network
cost on a schedule, and a scan reads what it left. A scan that fetched per
dependency would turn a 300-package manifest into 300 outbound requests on the
request path.

The rule the tests are built around is that **not knowing is not the same as
nothing being wrong**. A package whose metadata was never fetched, or whose
fetch failed, raises no signal — and must not be mistaken for one that was
checked and came back fine.
"""

from __future__ import annotations

import httpx
import pytest

from app.core.supply_chain import (
    UNMAINTAINED_AFTER_DAYS,
    PackageFacts,
    SignalKind,
    SignalLevel,
    assess_facts,
)
from app.core.types import Ecosystem
from app.feeds.registry import RegistryClient, RegistryError, supports_metadata
from tests.factories import set_manifest

NPM = Ecosystem.NPM
PYPI = Ecosystem.PYPI


def facts(**overrides) -> PackageFacts:
    base = {"ecosystem": NPM, "name": "example", "latest_version": "1.0.0"}
    base.update(overrides)
    return PackageFacts(**base)


class TestUnmaintained:
    def test_a_long_silence_is_notable(self):
        signals = assess_facts(facts(days_since_release=UNMAINTAINED_AFTER_DAYS + 1))
        kinds = {s.kind for s in signals}

        assert SignalKind.UNMAINTAINED in kinds
        assert next(s for s in signals if s.kind is SignalKind.UNMAINTAINED).level is (
            SignalLevel.NOTABLE
        )

    def test_just_under_the_line_is_silent(self):
        signals = assess_facts(facts(days_since_release=UNMAINTAINED_AFTER_DAYS - 1))
        assert SignalKind.UNMAINTAINED not in {s.kind for s in signals}

    def test_the_wording_does_not_call_it_a_fault(self):
        """Plenty of small libraries are simply finished. Saying otherwise
        would make the signal an accusation rather than context."""
        signal = next(
            s
            for s in assess_facts(facts(days_since_release=1200))
            if s.kind is SignalKind.UNMAINTAINED
        )
        assert "not a fault" in signal.detail
        assert "1200" not in signal.detail  # said in years, not raw days
        assert "3.3 years" in signal.detail

    def test_an_explicit_deprecation_outranks_the_age_guess(self):
        """A maintainer saying "do not use this" is a fact, where a date is an
        inference, so it is reported as the stronger of the two and only once."""
        signals = assess_facts(
            facts(days_since_release=3000, deprecated="use String.prototype.padStart")
        )
        unmaintained = [s for s in signals if s.kind is SignalKind.UNMAINTAINED]

        assert len(unmaintained) == 1
        assert unmaintained[0].level is SignalLevel.CONCERNING
        assert "padStart" in unmaintained[0].detail

    def test_an_unknown_age_says_nothing(self):
        assert assess_facts(facts(days_since_release=None)) == []


class TestMaintainers:
    def test_one_maintainer_is_informational(self):
        signals = assess_facts(facts(maintainer_count=1))
        assert signals[0].kind is SignalKind.SINGLE_MAINTAINER
        assert signals[0].level is SignalLevel.INFORMATIONAL

    def test_it_is_worded_as_context_not_an_accusation(self):
        signal = assess_facts(facts(maintainer_count=1))[0]
        assert "worth knowing rather than worth acting on" in signal.detail.lower()

    def test_several_maintainers_is_silent(self):
        assert assess_facts(facts(maintainer_count=4)) == []

    def test_an_unknown_count_is_silent(self):
        """PyPI's JSON API does not report one. Guessing from a free-text
        author field would be inventing a security signal."""
        assert assess_facts(facts(maintainer_count=None)) == []


class TestProvenance:
    def test_an_attested_build_is_reported(self):
        signals = assess_facts(facts(has_provenance=True))
        assert signals[0].kind is SignalKind.PROVENANCE_VERIFIED

    def test_a_missing_attestation_is_reported_as_context(self):
        signals = assess_facts(facts(has_provenance=False))
        assert signals[0].kind is SignalKind.PROVENANCE_MISSING
        assert signals[0].level is SignalLevel.INFORMATIONAL
        assert "not a problem" in signals[0].detail

    def test_an_ecosystem_without_the_concept_says_nothing(self):
        """`None` means "no such thing here", which is a different statement
        from "not attested" and must not render as a finding."""
        assert assess_facts(facts(ecosystem=PYPI, has_provenance=None)) == []


class TestTheRegistryClients:
    async def _client(self, handler) -> RegistryClient:
        client = RegistryClient(timeout=5, user_agent="test")
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return client

    async def test_npm_answers_all_four(self):
        payload = {
            "dist-tags": {"latest": "1.3.0"},
            "time": {"1.3.0": "2017-04-12T10:00:00.000Z"},
            "maintainers": [{"name": "a"}, {"name": "b"}],
            "versions": {
                "1.3.0": {
                    "dist": {"attestations": {"url": "https://example"}},
                    "deprecated": "use something else",
                }
            },
        }
        client = await self._client(lambda r: httpx.Response(200, json=payload))
        async with client:
            result = await client.fetch(NPM, "left-pad")

        assert result.latest_version == "1.3.0"
        assert result.maintainer_count == 2
        assert result.has_provenance is True
        assert result.deprecated == "use something else"
        assert result.days_since_release and result.days_since_release > 3000

    async def test_npm_absence_of_attestations_is_a_real_no(self):
        """Every npm package could carry one, so absence is information."""
        payload = {
            "dist-tags": {"latest": "1.0.0"},
            "time": {"1.0.0": "2025-01-01T00:00:00.000Z"},
            "versions": {"1.0.0": {"dist": {}}},
        }
        client = await self._client(lambda r: httpx.Response(200, json=payload))
        async with client:
            assert (await client.fetch(NPM, "x")).has_provenance is False

    async def test_pypi_leaves_what_it_cannot_answer_unknown(self):
        payload = {
            "info": {"version": "2.31.0", "yanked": False},
            "urls": [{"upload_time_iso_8601": "2023-05-22T15:12:00.000000Z"}],
        }
        client = await self._client(lambda r: httpx.Response(200, json=payload))
        async with client:
            result = await client.fetch(PYPI, "requests")

        assert result.latest_version == "2.31.0"
        assert result.maintainer_count is None
        assert result.has_provenance is None

    async def test_a_yanked_release_reads_as_deprecated(self):
        payload = {
            "info": {"version": "0.1.0", "yanked": True, "yanked_reason": "broken build"},
            "urls": [],
        }
        client = await self._client(lambda r: httpx.Response(200, json=payload))
        async with client:
            assert (await client.fetch(PYPI, "x")).deprecated == "broken build"

    async def test_a_404_is_distinguished_from_an_outage(self):
        """Usually a private or renamed package rather than a problem."""
        client = await self._client(lambda r: httpx.Response(404))
        async with client:
            with pytest.raises(RegistryError) as caught:
                await client.fetch(NPM, "not-published")
        assert "not published" in str(caught.value)

    async def test_a_future_timestamp_does_not_go_negative(self):
        payload = {
            "dist-tags": {"latest": "1.0.0"},
            "time": {"1.0.0": "2099-01-01T00:00:00.000Z"},
            "versions": {"1.0.0": {"dist": {}}},
        }
        client = await self._client(lambda r: httpx.Response(200, json=payload))
        async with client:
            assert (await client.fetch(NPM, "x")).days_since_release == 0

    def test_go_has_no_metadata_source(self):
        """Go modules resolve from their source host, not a registry with an
        API. Saying so beats a client that quietly returns nothing."""
        assert supports_metadata(Ecosystem.GO) is False
        assert supports_metadata(NPM) and supports_metadata(PYPI)


class TestTheCache:
    async def test_a_scan_raises_nothing_for_an_unfetched_package(self, db, pro_user):
        """The rule this whole file is built on: not knowing is not the same
        as nothing being wrong."""
        import json

        from app.core.types import ManifestKind
        from app.services.scan_service import scan_target
        from app.services.supply_chain_service import open_signals
        from tests.test_scan_pipeline import make_target, seed_mirror

        await seed_mirror(db)
        target = await make_target(db, pro_user)
        target.manifest_kind = ManifestKind.PACKAGE_JSON
        await set_manifest(db, target, json.dumps({"dependencies": {"express": "4.0.0"}}))
        await scan_target(db, target)
        await db.commit()

        assert await open_signals(db, target.id) == []

    async def test_a_cached_fact_becomes_a_signal(self, db, pro_user):
        import json

        from app.core.types import ManifestKind
        from app.models import PackageMetadata
        from app.services.scan_service import scan_target
        from app.services.supply_chain_service import open_signals
        from tests.test_scan_pipeline import make_target, seed_mirror

        await seed_mirror(db)
        db.add(
            PackageMetadata(
                ecosystem=NPM,
                name="express",
                latest_version="4.0.0",
                days_since_release=3000,
                maintainer_count=1,
                has_provenance=False,
            )
        )
        target = await make_target(db, pro_user)
        target.manifest_kind = ManifestKind.PACKAGE_JSON
        await set_manifest(db, target, json.dumps({"dependencies": {"express": "4.0.0"}}))
        await db.flush()

        await scan_target(db, target)
        await db.commit()

        kinds = {s.kind for s in await open_signals(db, target.id)}
        assert kinds == {
            SignalKind.UNMAINTAINED,
            SignalKind.SINGLE_MAINTAINER,
            SignalKind.PROVENANCE_MISSING,
        }

    async def test_a_failed_fetch_is_treated_as_unknown(self, db, pro_user):
        """A row exists so the retry is spaced out, but it must not be read as
        a package that came back clean."""
        import json

        from app.core.types import ManifestKind
        from app.models import PackageMetadata
        from app.services.scan_service import scan_target
        from app.services.supply_chain_service import open_signals
        from tests.test_scan_pipeline import make_target, seed_mirror

        await seed_mirror(db)
        db.add(
            PackageMetadata(
                ecosystem=NPM,
                name="express",
                days_since_release=3000,
                fetch_error="The registry answered 503",
            )
        )
        target = await make_target(db, pro_user)
        target.manifest_kind = ManifestKind.PACKAGE_JSON
        await set_manifest(db, target, json.dumps({"dependencies": {"express": "4.0.0"}}))
        await db.flush()

        await scan_target(db, target)
        await db.commit()

        assert await open_signals(db, target.id) == []

    async def test_a_free_project_gets_supply_chain_context(self, db, user):
        import json

        from app.core.types import ManifestKind
        from app.models import PackageMetadata
        from app.services.scan_service import scan_target
        from app.services.supply_chain_service import open_signals
        from tests.test_scan_pipeline import make_target, seed_mirror

        await seed_mirror(db)
        db.add(
            PackageMetadata(
                ecosystem=NPM, name="express", days_since_release=3000, maintainer_count=1
            )
        )
        target = await make_target(db, user)
        target.manifest_kind = ManifestKind.PACKAGE_JSON
        await set_manifest(db, target, json.dumps({"dependencies": {"express": "4.0.0"}}))
        await db.flush()

        await scan_target(db, target)
        await db.commit()

        kinds = {signal.kind for signal in await open_signals(db, target.id)}
        assert kinds == {SignalKind.UNMAINTAINED, SignalKind.SINGLE_MAINTAINER}


class TestTheJobLocks:
    def test_every_advisory_lock_key_is_distinct_and_deliberate(self):
        """Written after a careless edit left LOCK_FEED_REFRESH as 0.

        Two jobs sharing a key means one silently waits for the other; a key of
        zero means it shares with anything else that forgot to pick one.
        """
        from app.jobs import tasks

        keys = {name: getattr(tasks, name) for name in dir(tasks) if name.startswith("LOCK_")}

        assert len(keys) >= 4
        assert len(set(keys.values())) == len(keys), f"duplicate lock keys: {keys}"
        assert all(value != 0 for value in keys.values()), f"a lock key is zero: {keys}"
