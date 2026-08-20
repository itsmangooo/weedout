"""EPSS: shown on everything, gating only where asked.

The decision this file pins is the one that was flagged rather than made
silently: EPSS does **not** feed severity tiering by default. It is a model
output, re-scored daily, and a finding drifting over a threshold overnight
would interrupt somebody because a number moved rather than because a
vulnerability did.

So the tests come in two halves. The score is attached to every decision
whether or not anybody asked for it, because a number that appeared only for
people who switched something on would be a worse explanation than none. And
nothing changes verdict until a project sets a threshold itself.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from app.core.epss import band_label, parse_epss_csv
from app.core.matching import DEFAULT_POLICY, triage
from app.core.policy import parse_policy
from app.core.types import (
    ActionableReason,
    AffectedPackage,
    AffectedRange,
    Dependency,
    Ecosystem,
    Reachability,
    Severity,
    Verdict,
    Vulnerability,
)

LOG4SHELL = "CVE-2021-44228"


def dep(reachability: Reachability = Reachability.RUNTIME_TRANSITIVE) -> Dependency:
    return Dependency(
        ecosystem=Ecosystem.NPM,
        name="pkg",
        version="1.0.0",
        version_spec="1.0.0",
        reachability=reachability,
    )


def advisory(severity: Severity = Severity.MEDIUM) -> Vulnerability:
    return Vulnerability(
        id="GHSA-example",
        aliases=(LOG4SHELL,),
        severity=severity,
        affected=(
            AffectedPackage(
                ecosystem=Ecosystem.NPM,
                name="pkg",
                ranges=(AffectedRange(introduced="0", fixed="2.0.0"),),
            ),
        ),
    )


INDEX = {LOG4SHELL: (0.9754, 0.9998)}


class TestParsingTheFeed:
    def test_it_reads_the_header_and_the_rows(self):
        snapshot = parse_epss_csv(
            "#model_version:v2025.03.14,score_date:2025-03-14T00:00:00+0000\n"
            "cve,epss,percentile\n"
            "CVE-1999-0001,0.01234,0.78901\n"
        )
        assert snapshot.model_version == "v2025.03.14"
        assert str(snapshot.scored_on) == "2025-03-14"
        assert snapshot.entries[0].cve_id == "CVE-1999-0001"
        assert snapshot.entries[0].percent == 1.23

    def test_a_malformed_row_does_not_lose_the_day(self):
        """280,000 rows from a third party. Discarding the whole file because
        one line is short would lose far more than it protects."""
        snapshot = parse_epss_csv(
            "cve,epss,percentile\n"
            "CVE-1999-0001,0.5,0.5\n"
            "garbage\n"
            "CVE-BAD,notanumber,0.5\n"
            "CVE-1999-0002,0.6,0.6\n"
        )
        assert [e.cve_id for e in snapshot.entries] == ["CVE-1999-0001", "CVE-1999-0002"]

    def test_an_impossible_probability_is_dropped(self):
        """A score above 1 is a corrupt row, not a very likely CVE."""
        snapshot = parse_epss_csv("cve,epss,percentile\nCVE-1999-0001,1.5,0.2\n")
        assert snapshot.entries == ()

    def test_the_first_score_for_a_cve_wins(self):
        snapshot = parse_epss_csv(
            "cve,epss,percentile\nCVE-1999-0001,0.1,0.1\nCVE-1999-0001,0.9,0.9\n"
        )
        assert len(snapshot.entries) == 1
        assert snapshot.entries[0].score == 0.1

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (None, "Not scored"),
            (0.0001, "Unlikely"),
            (0.05, "Possible"),
            (0.3, "Likely"),
            (0.97, "Very likely"),
        ],
    )
    def test_the_band_reads_as_probability_not_severity(self, score, expected):
        """Deliberately not "high" or "critical". A reader who has to work out
        which scale a word belongs to will eventually get it wrong."""
        assert band_label(score) == expected


class TestItIsAlwaysShown:
    def test_the_score_rides_along_on_a_suppressed_finding(self):
        decision = triage(dep(), advisory(), policy=DEFAULT_POLICY, epss_index=INDEX)

        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.epss_score == 0.9754
        assert decision.epss_percentile == 0.9998

    def test_an_unscored_cve_carries_none_rather_than_zero(self):
        """Zero would read as "we checked and it is very unlikely". Most CVEs
        are simply not scored, and that is a different statement."""
        decision = triage(dep(), advisory(), policy=DEFAULT_POLICY, epss_index={})
        assert decision.epss_score is None

    def test_the_highest_score_among_aliases_wins(self):
        """An advisory can alias several CVEs. If any of the vulnerabilities it
        describes is likely to be exploited, the advisory is."""
        many = replace(advisory(), aliases=("CVE-2020-0001", LOG4SHELL))
        index = {"CVE-2020-0001": (0.01, 0.5), LOG4SHELL: (0.9754, 0.9998)}

        decision = triage(dep(), many, policy=DEFAULT_POLICY, epss_index=index)
        assert decision.epss_score == 0.9754


class TestItGatesOnlyWhenAsked:
    def test_by_default_a_high_score_changes_nothing(self):
        """The decision, pinned. A 97% probability on a medium transitive
        finding is still filed, because nobody asked to be woken for it."""
        decision = triage(dep(), advisory(), policy=DEFAULT_POLICY, epss_index=INDEX)
        assert decision.verdict is Verdict.SUPPRESSED
        assert DEFAULT_POLICY.epss_threshold is None

    def test_a_threshold_promotes_it(self):
        policy = replace(DEFAULT_POLICY, epss_threshold=0.5)
        decision = triage(dep(), advisory(), policy=policy, epss_index=INDEX)

        assert decision.verdict is Verdict.ACTIONABLE
        assert decision.actionable_reason is ActionableReason.LIKELY_TO_BE_EXPLOITED

    def test_a_score_below_the_threshold_does_not(self):
        policy = replace(DEFAULT_POLICY, epss_threshold=0.99)
        assert triage(dep(), advisory(), policy=policy, epss_index=INDEX).verdict is (
            Verdict.SUPPRESSED
        )

    def test_a_threshold_with_no_data_is_harmless(self):
        policy = replace(DEFAULT_POLICY, epss_threshold=0.5)
        assert triage(dep(), advisory(), policy=policy, epss_index={}).verdict is (
            Verdict.SUPPRESSED
        )

    def test_it_does_not_override_a_withdrawal(self):
        policy = replace(DEFAULT_POLICY, epss_threshold=0.5)
        retracted = replace(advisory(), withdrawn=True)
        assert triage(dep(), retracted, policy=policy, epss_index=INDEX).verdict is (
            Verdict.SUPPRESSED
        )

    def test_an_ignore_rule_still_wins_over_a_mere_probability(self):
        """Exploitation is a fact and overrides an ignore. A probability is
        not, so the rule stands."""
        from app.core.matching import normalise_ids

        policy = replace(DEFAULT_POLICY, epss_threshold=0.5, ignored_ids=normalise_ids([LOG4SHELL]))
        decision = triage(dep(), advisory(), policy=policy, epss_index=INDEX)
        assert decision.verdict is Verdict.SUPPRESSED


class TestThePolicyFile:
    def test_a_probability_is_read(self):
        assert parse_policy("epss:\n  alert_above: 0.5\n").epss_threshold == 0.5

    def test_a_percentage_is_read_as_the_same_thing(self):
        """Somebody writing `alert_above: 50` means half. Treating that as
        "always alert" would be the loudest possible misreading."""
        assert parse_policy("epss:\n  alert_above: 50\n").epss_threshold == 0.5

    def test_nonsense_is_refused_with_a_warning(self):
        parsed = parse_policy("epss:\n  alert_above: 5000\n")
        assert parsed.epss_threshold is None
        assert parsed.warnings

    def test_a_boolean_is_not_a_number(self):
        """YAML says `yes` is True, and True is an int in Python. Without the
        bool check that would silently become a threshold of 1.0."""
        parsed = parse_policy("epss:\n  alert_above: yes\n")
        assert parsed.epss_threshold is None


class TestPrecedence:
    async def test_the_file_beats_the_project_setting(self, db, pro_user):
        from app.core.types import Ecosystem as Eco
        from app.models import TrackedTarget
        from app.services.rules_service import build_policy

        target = TrackedTarget(user_id=pro_user.id, name="acme", ecosystem=Eco.NPM, is_active=True)
        target.epss_threshold = 0.9
        target.policy_file = "epss:\n  alert_above: 0.2\n"
        db.add(target)
        await db.flush()

        effective = await build_policy(db, target, pro_user)
        assert effective.policy.epss_threshold == 0.2

    async def test_a_free_project_never_gates_on_it(self, db, user):
        from app.core.types import Ecosystem as Eco
        from app.models import TrackedTarget
        from app.services.rules_service import build_policy

        target = TrackedTarget(user_id=user.id, name="free", ecosystem=Eco.NPM, is_active=True)
        target.epss_threshold = 0.2
        db.add(target)
        await db.flush()

        effective = await build_policy(db, target, user)
        assert effective.policy.epss_threshold is None


class TestEndToEnd:
    async def test_the_score_is_stored_on_the_finding(self, db, pro_user):
        """Denormalised, so a finding can be shown and exported without
        joining a 360,000-row table on every page."""
        import json

        from sqlalchemy import select

        from app.core.types import ManifestKind
        from app.models import CVEMatch, EpssScore
        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import LODASH_ADVISORY, make_target, seed_mirror

        await seed_mirror(db, LODASH_ADVISORY)
        db.add(EpssScore(cve_id="CVE-2020-8203", score=0.2133, percentile=0.9741))
        await db.flush()

        target = await make_target(db, pro_user)
        target.manifest_kind = ManifestKind.PACKAGE_JSON
        target.manifest_content = json.dumps({"dependencies": {"lodash": "4.17.15"}})
        await scan_target(db, target)
        await db.commit()

        scored = (
            (
                await db.execute(
                    select(CVEMatch).where(
                        CVEMatch.target_id == target.id, CVEMatch.epss_score.is_not(None)
                    )
                )
            )
            .scalars()
            .all()
        )

        assert scored, "the scan should have attached a score"
        assert abs(scored[0].epss_score - 0.2133) < 1e-6

    async def test_it_is_shown_as_a_signal_not_a_severity(self, auth_client, db, user):
        """`high severity` and `high EPSS` answer different questions, so they
        are rendered as different shapes."""
        import json

        from app.core.types import ManifestKind
        from app.models import EpssScore
        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import LODASH_ADVISORY, make_target, seed_mirror

        await seed_mirror(db, LODASH_ADVISORY)
        db.add(EpssScore(cve_id="CVE-2020-8203", score=0.2133, percentile=0.9741))
        await db.flush()

        target = await make_target(db, user)
        target.manifest_kind = ManifestKind.PACKAGE_JSON
        target.manifest_content = json.dumps({"dependencies": {"lodash": "4.17.15"}})
        await scan_target(db, target)
        await db.commit()

        # No ?show: a high-severity direct dependency is actionable, so the
        # finding is on the Open tab rather than Filtered.
        body = (await auth_client.get(f"/targets/{target.id}")).text
        assert "signal--epss" in body
        assert "21.3%" in body
        # Not dressed up as a severity tier.
        assert "pill--epss" not in body
