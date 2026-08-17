"""Triage policy: what gets surfaced, what gets suppressed, and why.

These tests are the specification of the product's central claim. If the policy
changes, these must change deliberately — not be patched to match new behaviour.
"""

from __future__ import annotations

import pytest

from app.core.matching import DEFAULT_POLICY, MatchPolicy, summarize, triage, triage_all
from app.core.types import (
    ActionableReason,
    Ecosystem,
    Reachability,
    Severity,
    SuppressionReason,
    Verdict,
)
from tests.factories import affected, dep, kev, vuln

KEV_SET = {"CVE-2020-8203"}


class TestExploitedInTheWildAlwaysWins:
    def test_kev_listed_alerts_even_at_low_severity(self):
        decision = triage(dep(), vuln(severity=Severity.LOW), KEV_SET)
        assert decision.verdict is Verdict.ACTIONABLE
        assert decision.actionable_reason is ActionableReason.EXPLOITED_IN_WILD
        assert decision.kev is True

    def test_kev_listed_alerts_even_with_unknown_severity(self):
        decision = triage(dep(), vuln(severity=Severity.UNKNOWN), KEV_SET)
        assert decision.verdict is Verdict.ACTIONABLE

    def test_kev_listed_alerts_even_for_dev_only_dependency(self):
        # "It's only in CI" is not protection against a vulnerability with
        # working public exploitation.
        decision = triage(
            dep(reachability=Reachability.DEV_ONLY), vuln(severity=Severity.LOW), KEV_SET
        )
        assert decision.verdict is Verdict.ACTIONABLE
        assert decision.actionable_reason is ActionableReason.EXPLOITED_IN_WILD

    def test_kev_listed_alerts_even_for_transitive_dependency(self):
        decision = triage(
            dep(reachability=Reachability.RUNTIME_TRANSITIVE),
            vuln(severity=Severity.MEDIUM),
            KEV_SET,
        )
        assert decision.verdict is Verdict.ACTIONABLE

    def test_kev_lookup_matches_any_alias_and_is_case_insensitive(self):
        v = vuln(vuln_id="GHSA-abc", aliases=("GHSA-abc", "cve-2021-44228"))
        assert triage(dep(), v, {"CVE-2021-44228"}).kev is True

    def test_kev_index_may_be_a_mapping(self):
        decision = triage(dep(), vuln(severity=Severity.LOW), {"CVE-2020-8203": kev()})
        assert decision.verdict is Verdict.ACTIONABLE

    def test_non_kev_cve_is_not_marked_exploited(self):
        decision = triage(dep(), vuln(severity=Severity.HIGH), {"CVE-1999-0001"})
        assert decision.kev is False


class TestSeverityThresholds:
    def test_high_severity_direct_dependency_alerts(self):
        decision = triage(dep(), vuln(severity=Severity.HIGH), set())
        assert decision.verdict is Verdict.ACTIONABLE
        assert decision.actionable_reason is ActionableReason.HIGH_SEVERITY_DIRECT

    def test_critical_direct_dependency_alerts(self):
        decision = triage(dep(), vuln(severity=Severity.CRITICAL), set())
        assert decision.verdict is Verdict.ACTIONABLE
        assert decision.actionable_reason is ActionableReason.CRITICAL_IN_PRODUCTION

    @pytest.mark.parametrize("severity", [Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN])
    def test_below_threshold_direct_dependency_is_suppressed(self, severity):
        decision = triage(dep(), vuln(severity=severity), set())
        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason is SuppressionReason.BELOW_SEVERITY_THRESHOLD

    def test_critical_transitive_dependency_alerts(self):
        decision = triage(
            dep(reachability=Reachability.RUNTIME_TRANSITIVE),
            vuln(severity=Severity.CRITICAL),
            set(),
        )
        assert decision.verdict is Verdict.ACTIONABLE
        assert decision.actionable_reason is ActionableReason.CRITICAL_IN_PRODUCTION

    def test_high_transitive_dependency_is_suppressed_with_the_specific_reason(self):
        # The single largest source of noise in existing tools.
        decision = triage(
            dep(reachability=Reachability.RUNTIME_TRANSITIVE),
            vuln(severity=Severity.HIGH),
            set(),
        )
        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason is SuppressionReason.TRANSITIVE_NOT_DIRECT


class TestReachability:
    def test_dev_only_dependency_is_suppressed_regardless_of_severity(self):
        decision = triage(
            dep(reachability=Reachability.DEV_ONLY), vuln(severity=Severity.CRITICAL), set()
        )
        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason is SuppressionReason.DEV_ONLY_DEPENDENCY

    def test_dev_suppression_is_checked_before_severity(self):
        decision = triage(
            dep(reachability=Reachability.DEV_ONLY), vuln(severity=Severity.HIGH), set()
        )
        assert decision.suppression_reason is SuppressionReason.DEV_ONLY_DEPENDENCY


class TestVersionGate:
    def test_unaffected_version_is_not_a_match_at_all(self):
        # 4.17.21 contains the fix, so this is NOT_AFFECTED — it must not even
        # be counted as suppressed noise, or the "noise filtered" number becomes
        # meaningless.
        decision = triage(dep(version="4.17.21"), vuln(severity=Severity.CRITICAL), KEV_SET)
        assert decision.verdict is Verdict.NOT_AFFECTED
        assert decision.is_actionable is False
        assert decision.is_suppressed is False

    def test_different_package_name_is_not_a_match(self):
        decision = triage(dep(name="express"), vuln(severity=Severity.CRITICAL), KEV_SET)
        assert decision.verdict is Verdict.NOT_AFFECTED

    def test_package_name_matching_is_case_insensitive(self):
        decision = triage(dep(name="LoDaSh"), vuln(severity=Severity.HIGH), set())
        assert decision.verdict is Verdict.ACTIONABLE

    def test_same_name_in_a_different_ecosystem_is_not_a_match(self):
        # A PyPI package named "lodash" must not match an npm advisory.
        decision = triage(
            dep(name="lodash", ecosystem=Ecosystem.PYPI, version="4.17.15"),
            vuln(severity=Severity.CRITICAL),
            KEV_SET,
        )
        assert decision.verdict is Verdict.NOT_AFFECTED

    def test_fixed_version_is_attached_to_the_decision(self):
        decision = triage(dep(), vuln(severity=Severity.HIGH), set())
        assert decision.fixed_version == "4.17.21"


class TestWithdrawnAdvisories:
    def test_withdrawn_is_suppressed(self):
        decision = triage(dep(), vuln(severity=Severity.CRITICAL, withdrawn=True), set())
        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason is SuppressionReason.WITHDRAWN

    def test_withdrawn_beats_kev(self):
        # The publisher retracted it. Acting on retracted data is acting on data
        # we know to be wrong, even if a KEV row still references the CVE.
        decision = triage(dep(), vuln(severity=Severity.CRITICAL, withdrawn=True), KEV_SET)
        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason is SuppressionReason.WITHDRAWN


class TestPolicyIsConfigurable:
    def test_lowering_the_direct_threshold_surfaces_more(self):
        policy = MatchPolicy(direct_threshold=Severity.MEDIUM)
        assert triage(dep(), vuln(severity=Severity.MEDIUM), set(), policy).is_actionable

    def test_allowing_dev_dependencies_surfaces_them(self):
        policy = MatchPolicy(alert_on_dev_dependencies=True)
        decision = triage(
            dep(reachability=Reachability.DEV_ONLY), vuln(severity=Severity.CRITICAL), set(), policy
        )
        assert decision.is_actionable

    def test_disabling_kev_override_falls_back_to_severity_rules(self):
        policy = MatchPolicy(always_alert_on_kev=False)
        decision = triage(dep(), vuln(severity=Severity.LOW), KEV_SET, policy)
        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.kev is True  # still recorded, just not decisive

    def test_default_policy_thresholds(self):
        assert DEFAULT_POLICY.threshold_for(Reachability.RUNTIME_DIRECT) is Severity.HIGH
        assert DEFAULT_POLICY.threshold_for(Reachability.RUNTIME_TRANSITIVE) is Severity.CRITICAL


class TestTriageAll:
    def _fixture(self):
        direct_high = dep(name="lodash", version="4.17.15")
        transitive_high = dep(
            name="minimist", version="1.2.0", reachability=Reachability.RUNTIME_TRANSITIVE
        )
        dev_critical = dep(name="webpack", version="4.0.0", reachability=Reachability.DEV_ONLY)
        unaffected = dep(name="express", version="4.18.2")

        deps = [direct_high, transitive_high, dev_critical, unaffected]
        vulns = {
            direct_high.key: [vuln(vuln_id="GHSA-1", severity=Severity.HIGH)],
            transitive_high.key: [
                vuln(
                    vuln_id="GHSA-2",
                    severity=Severity.HIGH,
                    aliases=("CVE-2021-44906",),
                    affected_packages=(affected(name="minimist", fixed="1.2.6"),),
                )
            ],
            dev_critical.key: [
                vuln(
                    vuln_id="GHSA-3",
                    severity=Severity.CRITICAL,
                    aliases=("CVE-2023-28154",),
                    affected_packages=(affected(name="webpack", fixed="5.76.0"),),
                )
            ],
            unaffected.key: [
                vuln(
                    vuln_id="GHSA-4",
                    severity=Severity.CRITICAL,
                    aliases=("CVE-2022-24999",),
                    affected_packages=(affected(name="express", fixed="4.17.3"),),
                )
            ],
        }
        return deps, vulns

    def test_partitions_into_actionable_and_suppressed(self):
        deps, vulns = self._fixture()
        result = triage_all(deps, vulns, set())

        assert [d.vulnerability.id for d in result.actionable] == ["GHSA-1"]
        assert sorted(d.vulnerability.id for d in result.suppressed) == ["GHSA-2", "GHSA-3"]
        # GHSA-4 is NOT_AFFECTED (express 4.18.2 > 4.17.3) and appears in neither.
        assert result.dependencies_scanned == 4

    def test_summary_counts_include_suppressed_noise(self):
        deps, vulns = self._fixture()
        counts = summarize(triage_all(deps, vulns, set()))
        assert counts == {
            "dependencies": 4,
            "actionable": 1,
            "suppressed": 2,
            "exploited": 0,
            "critical": 0,
        }

    def test_actionable_results_are_ordered_most_urgent_first(self):
        low_kev = dep(name="aaa-last-alphabetically", version="1.0.0")
        critical = dep(name="bbb", version="1.0.0")
        high = dep(name="ccc", version="1.0.0")

        def v(vid, sev, name, cve):
            return vuln(
                vuln_id=vid,
                severity=sev,
                aliases=(cve,),
                affected_packages=(affected(name=name, fixed="2.0.0"),),
            )

        result = triage_all(
            [low_kev, critical, high],
            {
                low_kev.key: [v("V-KEV", Severity.LOW, low_kev.name, "CVE-2000-0001")],
                critical.key: [v("V-CRIT", Severity.CRITICAL, "bbb", "CVE-2000-0002")],
                high.key: [v("V-HIGH", Severity.HIGH, "ccc", "CVE-2000-0003")],
            },
            {"CVE-2000-0001"},
        )
        # Exploited-in-the-wild outranks severity; severity orders the rest.
        assert [d.vulnerability.id for d in result.actionable] == ["V-KEV", "V-CRIT", "V-HIGH"]

    def test_dependency_with_no_advisories_is_scanned_but_yields_nothing(self):
        clean = dep(name="clean-pkg", version="1.0.0")
        result = triage_all([clean], {}, set())
        assert result.actionable_count == 0
        assert result.suppressed_count == 0
        assert result.dependencies_scanned == 1

    def test_errors_are_carried_through(self):
        result = triage_all([], {}, set(), errors=("OSV timed out",))
        assert result.errors == ("OSV timed out",)
