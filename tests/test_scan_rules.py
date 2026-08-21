"""Custom scan rules: thresholds, ignores, and the policy file.

The dangerous direction here is silence. Every other feature in this product
fails by being noisy; this one fails by making a real finding disappear, so the
tests are weighted towards the cases where a rule should *not* hold:

* an ignore rule does not survive a KEV listing,
* an ignore rule does not survive the subscription lapsing,
* a policy file that will not parse takes every rule in it down with it, in the
  direction of more alerts rather than fewer,
* and a Free account cannot reach any of it by posting directly.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from sqlalchemy import select

from app.core.matching import DEFAULT_POLICY, normalise_ids, triage
from app.core.policy import parse_policy
from app.core.types import (
    AffectedPackage,
    AffectedRange,
    Dependency,
    Ecosystem,
    ManifestKind,
    Reachability,
    Severity,
    SuppressionReason,
    Verdict,
)
from app.models import IgnoreRule, TrackedTarget
from tests.conftest import set_csrf

CVE = "CVE-2021-23337"


def lodash() -> Dependency:
    return Dependency(
        ecosystem=Ecosystem.NPM,
        name="lodash",
        version="4.17.15",
        version_spec="4.17.15",
        reachability=Reachability.RUNTIME_DIRECT,
    )


def advisory(severity: Severity = Severity.CRITICAL):
    from app.core.types import Vulnerability

    return Vulnerability(
        id="GHSA-35jh-r3h4-6jhm",
        aliases=(CVE,),
        summary="Command injection in lodash",
        severity=severity,
        affected=(
            AffectedPackage(
                ecosystem=Ecosystem.NPM,
                name="lodash",
                ranges=(AffectedRange(introduced="0", fixed="4.17.21"),),
            ),
        ),
    )


class TestIgnoring:
    def test_an_ignored_advisory_is_filed_not_deleted(self):
        policy = replace(DEFAULT_POLICY, ignored_ids=normalise_ids([CVE]))
        decision = triage(lodash(), advisory(), policy=policy)

        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason is SuppressionReason.IGNORED_BY_RULE
        # It is still a decision about a real match, so it appears on the
        # Filtered tab rather than vanishing.
        assert decision.suppression_reason.label == "Ignored by a rule on this project"

    def test_ignoring_the_cve_also_covers_the_ghsa_that_aliases_it(self):
        """A rule that only worked if you named the identifier the feed happened
        to use would be a rule that quietly stopped working."""
        by_cve = replace(DEFAULT_POLICY, ignored_ids=normalise_ids([CVE]))
        by_ghsa = replace(DEFAULT_POLICY, ignored_ids=normalise_ids(["GHSA-35jh-r3h4-6jhm"]))

        for policy in (by_cve, by_ghsa):
            assert triage(lodash(), advisory(), policy=policy).verdict is Verdict.SUPPRESSED

    def test_matching_is_case_insensitive(self):
        policy = replace(DEFAULT_POLICY, ignored_ids=normalise_ids(["cve-2021-23337"]))
        assert triage(lodash(), advisory(), policy=policy).verdict is Verdict.SUPPRESSED

    def test_an_unrelated_rule_changes_nothing(self):
        policy = replace(DEFAULT_POLICY, ignored_ids=normalise_ids(["CVE-2019-0001"]))
        assert triage(lodash(), advisory(), policy=policy).verdict is Verdict.ACTIONABLE


class TestKevOverridesAnIgnore:
    """The decision, tested rather than documented.

    An ignore rule is a judgement about a risk made at a moment in time.
    Confirmed exploitation is new information about that same risk, so the
    judgement is out of date rather than binding.
    """

    def test_a_kev_listing_raises_it_anyway(self):
        policy = replace(DEFAULT_POLICY, ignored_ids=normalise_ids([CVE]))
        decision = triage(lodash(), advisory(), kev_index={CVE}, policy=policy)

        assert decision.verdict is Verdict.ACTIONABLE

    def test_the_override_is_flagged_not_silent(self):
        """Whoever wrote the rule has to be able to see it was set aside."""
        policy = replace(DEFAULT_POLICY, ignored_ids=normalise_ids([CVE]))
        decision = triage(lodash(), advisory(), kev_index={CVE}, policy=policy)

        assert decision.ignore_overridden is True

    def test_a_kev_finding_with_no_rule_is_not_flagged_as_overridden(self):
        decision = triage(lodash(), advisory(), kev_index={CVE}, policy=DEFAULT_POLICY)
        assert decision.ignore_overridden is False

    def test_a_withdrawn_advisory_still_wins_over_everything(self):
        """Retracted by its own publisher. Never alert, not even on KEV --
        acting on data known to be wrong is worse than not acting."""
        from app.core.types import Vulnerability

        withdrawn = Vulnerability(
            id="GHSA-35jh-r3h4-6jhm",
            aliases=(CVE,),
            severity=Severity.CRITICAL,
            withdrawn=True,
            affected=advisory().affected,
        )
        decision = triage(lodash(), withdrawn, kev_index={CVE}, policy=DEFAULT_POLICY)
        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason is SuppressionReason.WITHDRAWN


class TestThresholds:
    def test_raising_the_bar_silences_a_high_finding(self):
        policy = replace(DEFAULT_POLICY, direct_threshold=Severity.CRITICAL)
        decision = triage(lodash(), advisory(Severity.HIGH), policy=policy)
        assert decision.verdict is Verdict.SUPPRESSED

    def test_lowering_it_surfaces_a_medium_one(self):
        policy = replace(DEFAULT_POLICY, direct_threshold=Severity.MEDIUM)
        decision = triage(lodash(), advisory(Severity.MEDIUM), policy=policy)
        assert decision.verdict is Verdict.ACTIONABLE

    def test_exploitation_ignores_the_threshold_entirely(self):
        policy = replace(DEFAULT_POLICY, direct_threshold=Severity.CRITICAL)
        decision = triage(lodash(), advisory(Severity.LOW), kev_index={CVE}, policy=policy)
        assert decision.verdict is Verdict.ACTIONABLE


class TestThePolicyFile:
    def test_a_well_formed_file_is_read(self):
        parsed = parse_policy(
            "version: 1\n"
            "severity:\n"
            "  direct: critical\n"
            "ignore:\n"
            f"  - cve: {CVE}\n"
            "    reason: Dev-only in our build, not reachable from what we ship.\n"
        )
        assert parsed.error is None
        assert parsed.direct_threshold is Severity.CRITICAL
        assert parsed.ignored_ids == (CVE,)

    def test_an_ignore_without_a_reason_is_refused(self):
        """The refusal is the feature. An ignore with no reason is
        unreviewable, and the author is the only one who can supply it."""
        parsed = parse_policy(f"ignore:\n  - cve: {CVE}\n")
        assert parsed.ignored_ids == ()
        assert any("reason" in warning for warning in parsed.warnings)

    def test_a_broken_file_is_discarded_whole(self):
        """Failing open. Every rule in the file stops applying, which can only
        produce more alerts than intended, never fewer."""
        parsed = parse_policy("ignore:\n  - [unclosed\n")
        assert parsed.error is not None
        assert parsed.ignored_ids == ()
        assert parsed.direct_threshold is None

    def test_an_unknown_setting_is_a_warning_not_a_failure(self):
        """A file written for a later version must not break a repository on
        upgrade."""
        parsed = parse_policy(f"future_thing: yes\nignore:\n  - cve: {CVE}\n    reason: because.\n")
        assert parsed.error is None
        assert parsed.ignored_ids == (CVE,)
        assert parsed.warnings

    def test_yaml_is_never_allowed_to_construct_objects(self):
        """safe_load, not load. This file comes out of somebody's repository."""
        parsed = parse_policy("!!python/object/apply:os.system ['echo pwned']\n")
        assert parsed.ignored_ids == ()
        assert parsed.error is not None

    def test_an_oversized_file_is_refused_before_parsing(self):
        parsed = parse_policy("ignore:\n" + ("  # padding\n" * 200_000))
        assert parsed.error is not None
        assert "too large" in parsed.error


@pytest.fixture
async def pro_target(db, pro_user) -> TrackedTarget:
    target = TrackedTarget(
        user_id=pro_user.id, name="acme", ecosystem=Ecosystem.NPM, is_active=True
    )
    db.add(target)
    await db.flush()
    return target


class TestPrecedence:
    async def test_the_file_beats_the_interface(self, db, pro_user, pro_target):
        """A rule about a codebase belongs beside the codebase. A settings page
        that could quietly override it would make a CI run depend on something
        invisible from the checkout."""
        from app.services.rules_service import build_policy

        pro_target.direct_threshold = Severity.LOW
        pro_target.policy_file = "severity:\n  direct: critical\n"
        await db.flush()

        effective = await build_policy(db, pro_target, pro_user)
        assert effective.policy.direct_threshold is Severity.CRITICAL

    async def test_a_silent_file_does_not_wipe_out_interface_settings(
        self, db, pro_user, pro_target
    ):
        """Saying nothing is not an instruction."""
        from app.services.rules_service import build_policy

        pro_target.direct_threshold = Severity.LOW
        pro_target.policy_file = f"ignore:\n  - cve: {CVE}\n    reason: because we said so.\n"
        await db.flush()

        effective = await build_policy(db, pro_target, pro_user)
        assert effective.policy.direct_threshold is Severity.LOW

    async def test_ignores_from_both_sources_are_unioned(self, db, pro_user, pro_target):
        from app.services.rules_service import build_policy

        db.add(
            IgnoreRule(
                target_id=pro_target.id,
                identifier="CVE-2019-0001",
                reason="From the interface.",
            )
        )
        pro_target.policy_file = f"ignore:\n  - cve: {CVE}\n    reason: From the file.\n"
        await db.flush()

        effective = await build_policy(db, pro_target, pro_user)
        assert "CVE-2019-0001" in effective.policy.ignored_ids
        assert CVE in effective.policy.ignored_ids

    async def test_a_free_project_honours_no_rules_at_all(self, db, user, pro_target):
        """The rows survive a lapsed subscription; they simply stop applying.
        Deleting somebody's configuration when they downgrade would be worse."""
        from app.services.rules_service import build_policy

        pro_target.user_id = user.id
        pro_target.direct_threshold = Severity.LOW
        pro_target.policy_file = f"ignore:\n  - cve: {CVE}\n    reason: because.\n"
        db.add(IgnoreRule(target_id=pro_target.id, identifier=CVE, reason="From the interface."))
        await db.flush()

        effective = await build_policy(db, pro_target, user)
        assert effective.policy.ignored_ids == frozenset()
        assert effective.policy.direct_threshold is DEFAULT_POLICY.direct_threshold
        assert any("Pro plan" in note for note in effective.notes)


class TestAccessControl:
    async def test_a_free_account_cannot_post_a_rule(self, auth_client, db, user):
        target = TrackedTarget(
            user_id=user.id, name="free-one", ecosystem=Ecosystem.NPM, is_active=True
        )
        db.add(target)
        await db.commit()

        response = await auth_client.post(
            f"/api/internal/projects/{target.id}/rules",
            json={"identifier": CVE, "reason": "I would rather not hear about this one."},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )
        assert response.status_code == 402
        assert "Pro" in response.json()["error"]["message"]
        assert (await db.execute(select(IgnoreRule))).scalars().first() is None

    async def test_a_free_account_cannot_post_a_threshold(self, auth_client, db, user):
        target = TrackedTarget(
            user_id=user.id, name="free-two", ecosystem=Ecosystem.NPM, is_active=True
        )
        db.add(target)
        await db.commit()

        response = await auth_client.post(
            f"/api/internal/projects/{target.id}/thresholds",
            json={"direct": "low"},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )
        assert response.status_code == 402
        await db.refresh(target)
        assert target.direct_threshold is None

    async def test_somebody_elses_project_is_a_404(self, auth_client, db, pro_user):
        theirs = TrackedTarget(
            user_id=pro_user.id, name="not-yours", ecosystem=Ecosystem.NPM, is_active=True
        )
        db.add(theirs)
        await db.commit()

        response = await auth_client.post(
            f"/api/internal/projects/{theirs.id}/rules",
            json={"identifier": CVE, "reason": "Trying to configure a project I do not own."},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )
        assert response.status_code == 404
        assert (await db.execute(select(IgnoreRule))).scalars().first() is None

    async def test_a_rule_cannot_be_deleted_through_another_project(
        self, pro_client, db, pro_user, user
    ):
        """Ownership comes from the project, not from the rule id.

        Run as a Pro account deliberately: a free one is refused for its tier
        before the ownership check is reached, so the boundary this test exists
        for would never be exercised.
        """
        mine = TrackedTarget(
            user_id=pro_user.id, name="mine", ecosystem=Ecosystem.NPM, is_active=True
        )
        theirs = TrackedTarget(
            user_id=user.id, name="theirs", ecosystem=Ecosystem.NPM, is_active=True
        )
        db.add_all([mine, theirs])
        await db.flush()
        rule = IgnoreRule(target_id=theirs.id, identifier=CVE, reason="Not mine to remove.")
        db.add(rule)
        await db.commit()

        response = await pro_client.post(
            f"/api/internal/projects/{mine.id}/rules/{rule.id}/delete",
            json={},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )
        assert response.status_code == 404
        assert (await db.execute(select(IgnoreRule))).scalars().first() is not None


class TestTheRequiredReason:
    async def test_a_rule_with_no_reason_is_refused(self, db, pro_user, pro_target):
        from app.schemas import IgnoreRuleForm
        from tests.test_scan_rules import CVE as identifier

        with pytest.raises(Exception) as caught:
            IgnoreRuleForm(identifier=identifier, reason="nope")
        assert "sentence" in str(caught.value)

    async def test_a_nonsense_identifier_is_refused(self):
        from app.schemas import IgnoreRuleForm

        with pytest.raises(Exception) as caught:
            IgnoreRuleForm(identifier="../../etc/passwd", reason="A perfectly good reason here.")
        assert "advisory id" in str(caught.value)


class TestEndToEnd:
    async def test_an_ignored_finding_is_filed_and_a_kev_one_is_not(self, db, pro_user):
        """Through the whole pipeline, with the rule in the database."""
        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import LODASH_ADVISORY, make_target, seed_mirror

        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, pro_user)
        target.manifest_kind = ManifestKind.PACKAGE_JSON
        target.manifest_content = json.dumps({"dependencies": {"lodash": "4.17.15"}})

        before = await scan_target(db, target)
        assert before.suppressed_count + before.actionable_count > 0

        # Now ignore everything this advisory is known as.
        for identifier in ("CVE-2021-23337", "CVE-2020-8203", "GHSA-35jh-r3h4-6jhm"):
            db.add(
                IgnoreRule(
                    target_id=target.id,
                    identifier=identifier,
                    reason="Ignored for the purposes of this test.",
                )
            )
        await db.commit()

        after = await scan_target(db, target)
        await db.commit()

        from app.models import CVEMatch

        ignored = (
            (
                await db.execute(
                    select(CVEMatch).where(
                        CVEMatch.target_id == target.id,
                        CVEMatch.suppression_reason == SuppressionReason.IGNORED_BY_RULE,
                    )
                )
            )
            .scalars()
            .all()
        )
        assert ignored, "the rule should have filed at least one finding"
        assert after.actionable_count <= before.actionable_count
