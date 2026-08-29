"""A severity floor of its own for dependencies that never ship.

The case this exists for: a critical advisory in a linter and a critical
advisory in a web framework are not the same problem, and the old boolean could
only say "treat them identically" or "never mention the linter". Both answers
are wrong often enough to matter — the second one hides a compromised build
tool, which is a real and current attack.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from app.core.matching import DEFAULT_POLICY, triage
from app.core.policy import parse_policy
from app.core.types import (
    AffectedPackage,
    AffectedRange,
    Dependency,
    Ecosystem,
    Reachability,
    Severity,
    SuppressionReason,
    Verdict,
    Vulnerability,
)


def dependency(reachability: Reachability) -> Dependency:
    return Dependency(
        ecosystem=Ecosystem.NPM,
        name="eslint",
        version="8.0.0",
        version_spec="8.0.0",
        reachability=reachability,
    )


def advisory(severity: Severity) -> Vulnerability:
    return Vulnerability(
        id="GHSA-dev-1",
        aliases=("CVE-2026-0001",),
        summary="Something in a build tool",
        details="",
        severity=severity,
        affected=(
            AffectedPackage(
                ecosystem=Ecosystem.NPM,
                name="eslint",
                ranges=(AffectedRange(introduced="0", fixed="9.0.0"),),
            ),
        ),
    )


def decide(policy, severity: Severity, reachability=Reachability.DEV_ONLY):
    return triage(dependency(reachability), advisory(severity), policy=policy)


class TestWithoutADevFloor:
    """The behaviour every existing project keeps."""

    def test_dev_findings_are_filed_not_raised(self):
        decision = decide(DEFAULT_POLICY, Severity.CRITICAL)

        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason is SuppressionReason.DEV_ONLY_DEPENDENCY

    def test_the_coarse_switch_still_turns_them_all_on(self):
        policy = replace(DEFAULT_POLICY, alert_on_dev_dependencies=True)

        assert decide(policy, Severity.CRITICAL).verdict is Verdict.ACTIONABLE

    def test_with_the_switch_on_a_dev_dependency_borrows_the_transitive_floor(self):
        """Which is the imprecision the new setting exists to fix: the floor
        for a build tool has nothing to do with how deep a runtime dependency
        is buried, and borrowing that number is a coincidence rather than a
        decision."""
        policy = replace(DEFAULT_POLICY, alert_on_dev_dependencies=True)

        assert policy.threshold_for(Reachability.DEV_ONLY) is policy.transitive_threshold
        assert decide(policy, Severity.HIGH).verdict is Verdict.SUPPRESSED


class TestWithADevFloor:
    def test_a_critical_in_a_build_tool_is_reported(self):
        policy = replace(DEFAULT_POLICY, dev_threshold=Severity.CRITICAL)

        assert decide(policy, Severity.CRITICAL).verdict is Verdict.ACTIONABLE

    def test_a_high_in_a_build_tool_is_not(self):
        """The whole point: a higher bar, not a different switch."""
        policy = replace(DEFAULT_POLICY, dev_threshold=Severity.CRITICAL)
        decision = decide(policy, Severity.HIGH)

        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason is SuppressionReason.DEV_ONLY_DEPENDENCY

    def test_it_wins_over_the_coarse_switch_being_off(self):
        """Setting a floor is a clearer statement than leaving the old switch
        off, so it is the one that applies."""
        policy = replace(
            DEFAULT_POLICY, dev_threshold=Severity.CRITICAL, alert_on_dev_dependencies=False
        )

        assert decide(policy, Severity.CRITICAL).verdict is Verdict.ACTIONABLE

    def test_production_dependencies_are_unaffected(self):
        """A dev floor must not quietly become the floor for everything."""
        policy = replace(DEFAULT_POLICY, dev_threshold=Severity.CRITICAL)

        assert (
            decide(policy, Severity.HIGH, Reachability.RUNTIME_DIRECT).verdict is Verdict.ACTIONABLE
        )

    def test_a_lower_dev_floor_than_production_is_honoured(self):
        """Unusual, but it is the user's call — somebody who has been burned by
        a supply-chain attack on their CI may well want this."""
        policy = replace(DEFAULT_POLICY, dev_threshold=Severity.LOW, direct_threshold=Severity.HIGH)

        assert decide(policy, Severity.LOW).verdict is Verdict.ACTIONABLE


class TestExploitationStillWins:
    def test_a_known_exploited_dev_dependency_is_reported_whatever_the_floor(self):
        """KEV is checked before any threshold. A build tool being actively
        exploited is the exact scenario the coarse switch used to hide."""
        policy = replace(DEFAULT_POLICY, dev_threshold=Severity.CRITICAL)
        decision = triage(
            dependency(Reachability.DEV_ONLY),
            advisory(Severity.LOW),
            kev_index={"CVE-2026-0001"},
            policy=policy,
        )

        assert decision.verdict is Verdict.ACTIONABLE


class TestFromThePolicyFile:
    def test_a_dev_floor_can_be_set_in_weedout_yml(self):
        parsed = parse_policy(
            """
            severity:
              direct: high
              dev: critical
            """
        )

        assert parsed.dev_threshold is Severity.CRITICAL
        assert parsed.warnings == ()

    def test_a_nonsense_value_is_reported_and_skipped(self):
        parsed = parse_policy("severity:\n  dev: sometimes\n")

        assert parsed.dev_threshold is None
        assert any("severity.dev" in w for w in parsed.warnings)

    def test_a_file_setting_only_dev_is_not_empty(self):
        parsed = parse_policy("severity:\n  dev: critical\n")

        assert parsed.is_empty is False


class TestItIsFree:
    async def test_a_free_project_gets_a_dev_floor(self, db, user):
        from app.services.rules_service import build_policy
        from app.services.target_service import create_target

        target = await create_target(
            db, user, filename="package.json", content='{"dependencies":{"lodash":"4.17.15"}}'
        )
        target.dev_threshold = Severity.CRITICAL
        await db.flush()

        effective = await build_policy(db, target, user)

        assert effective.policy.dev_threshold is Severity.CRITICAL
        assert not any("plan" in note.lower() for note in effective.notes)

    async def test_a_pro_project_does(self, db, pro_user):
        from app.services.rules_service import build_policy
        from app.services.target_service import create_target

        target = await create_target(
            db, pro_user, filename="package.json", content='{"dependencies":{"lodash":"4.17.15"}}'
        )
        target.dev_threshold = Severity.CRITICAL
        await db.flush()

        effective = await build_policy(db, target, pro_user)

        assert effective.policy.dev_threshold is Severity.CRITICAL


class TestTheFileBeatsTheProjectSetting:
    async def test_weedout_yml_wins(self, db, pro_user):
        """Same precedence as the other floors: the file that ran in the
        pipeline is the one that applied."""
        from app.services.rules_service import build_policy
        from app.services.target_service import create_target

        target = await create_target(
            db, pro_user, filename="package.json", content='{"dependencies":{"lodash":"4.17.15"}}'
        )
        target.dev_threshold = Severity.LOW
        target.policy_file = "severity:\n  dev: critical\n"
        await db.flush()

        effective = await build_policy(db, target, pro_user)

        assert effective.policy.dev_threshold is Severity.CRITICAL


class TestTheJvmParsersFeedIt:
    """The setting is only as good as the dev/prod signal underneath it."""

    @pytest.mark.parametrize(
        ("kind", "content", "dev_name"),
        [
            (
                "pom.xml",
                """<project xmlns="http://maven.apache.org/POM/4.0.0">
                  <artifactId>x</artifactId>
                  <dependencies><dependency>
                    <groupId>junit</groupId><artifactId>junit</artifactId>
                    <version>4.13.2</version><scope>test</scope>
                  </dependency></dependencies>
                </project>""",
                "junit:junit",
            ),
            (
                "gradle.lockfile",
                "org.junit.jupiter:junit-jupiter:5.8.2=testCompileClasspath\n",
                "org.junit.jupiter:junit-jupiter",
            ),
        ],
    )
    def test_test_scoped_dependencies_are_classified_dev_only(self, kind, content, dev_name):
        from app.core.manifests import detect_manifest_kind, parse_manifest

        parsed = parse_manifest(detect_manifest_kind(kind, content), content)
        by_name = {d.name: d for d in parsed.dependencies}

        assert by_name[dev_name].reachability is Reachability.DEV_ONLY
