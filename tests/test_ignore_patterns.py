"""Ignoring by package name, not only by advisory id.

The case ignoring-by-id cannot serve. A private package mirrored under a name
that also exists on the public registry matches advisories written about
somebody else's code, and there is no fixed list of identifiers to enumerate:
the next advisory that other project publishes is a new one nobody has heard of
yet. A glob over the name covers the whole family, including the entries that
do not exist yet.

Glob and not regular expression, which is the decision worth defending. Every
pattern here is evaluated against every dependency on every scan, from input a
user supplies. A regular expression is where that becomes a way to hang the
scanner on a crafted package name; a glob cannot backtrack. `@acme/*` is also
what people actually want to write.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from app.core.matching import DEFAULT_POLICY, normalise_ids, normalise_packages, triage
from app.core.policy import parse_policy
from app.core.types import (
    AffectedPackage,
    AffectedRange,
    Dependency,
    Ecosystem,
    IgnoreKind,
    Reachability,
    Severity,
    SuppressionReason,
    Verdict,
    Vulnerability,
)
from tests.conftest import create_project, set_csrf

CVE = "CVE-2021-23337"


def dependency(name: str = "@acme/logger") -> Dependency:
    return Dependency(
        ecosystem=Ecosystem.NPM,
        name=name,
        version="1.0.0",
        version_spec="1.0.0",
        reachability=Reachability.RUNTIME_DIRECT,
    )


def advisory(name: str = "@acme/logger", *, malicious: bool = False) -> Vulnerability:
    # `is_malicious` is read off the identifier rather than set: OSV publishes
    # malware advisories under a MAL- prefix, and the property is what the
    # product reads.
    return Vulnerability(
        id="MAL-2026-0001" if malicious else "GHSA-xxxx-yyyy-zzzz",
        aliases=(CVE,),
        summary="Prototype pollution",
        details="",
        severity=Severity.CRITICAL,
        affected=(
            AffectedPackage(
                ecosystem=Ecosystem.NPM,
                name=name,
                ranges=(AffectedRange(introduced="0", fixed="2.0.0"),),
            ),
        ),
    )


def decide(policy, name: str = "@acme/logger", **kwargs):
    return triage(dependency(name), advisory(name, **kwargs), policy=policy)


def with_packages(*patterns):
    return replace(DEFAULT_POLICY, ignored_packages=normalise_packages(patterns))


class TestMatching:
    def test_a_glob_silences_the_family(self):
        decision = decide(with_packages("@acme/*"))

        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason is SuppressionReason.IGNORED_BY_RULE

    def test_a_bare_name_is_an_exact_match(self):
        """No wildcards is a perfectly good pattern, and the obvious thing to
        type when you mean one package."""
        assert decide(with_packages("@acme/logger")).verdict is Verdict.SUPPRESSED
        assert decide(with_packages("@acme/logge")).verdict is Verdict.ACTIONABLE

    def test_a_package_outside_the_pattern_is_still_reported(self):
        assert decide(with_packages("@acme/*"), name="lodash").verdict is Verdict.ACTIONABLE

    @pytest.mark.parametrize(
        ("pattern", "name"),
        [
            ("karma-*", "karma-chrome-launcher"),
            ("*-mock", "database-mock"),
            ("eslint-plugin-?", "eslint-plugin-x"),
            ("@acme/*", "@ACME/Logger"),
            ("@ACME/*", "@acme/logger"),
        ],
    )
    def test_these_all_match(self, pattern, name):
        assert decide(with_packages(pattern), name=name).verdict is Verdict.SUPPRESSED

    @pytest.mark.parametrize(
        ("pattern", "name", "why"),
        [
            ("eslint-plugin-?", "eslint-plugin-jest", "? is one character, not any number"),
            ("@acme/*", "acme/logger", "the scope marker is part of the name"),
            ("lodash", "lodash.merge", "an exact pattern does not match a prefix"),
        ],
    )
    def test_these_do_not(self, pattern, name, why):
        assert decide(with_packages(pattern), name=name).verdict is Verdict.ACTIONABLE, why

    def test_several_patterns_are_a_union(self):
        policy = with_packages("karma-*", "@acme/*")

        assert decide(policy, name="karma-runner").verdict is Verdict.SUPPRESSED
        assert decide(policy, name="@acme/logger").verdict is Verdict.SUPPRESSED
        assert decide(policy, name="lodash").verdict is Verdict.ACTIONABLE

    def test_an_advisory_rule_and_a_package_rule_coexist(self):
        policy = replace(
            DEFAULT_POLICY,
            ignored_ids=normalise_ids([CVE]),
            ignored_packages=normalise_packages(["karma-*"]),
        )

        assert decide(policy, name="lodash").verdict is Verdict.SUPPRESSED
        assert decide(policy, name="karma-runner").verdict is Verdict.SUPPRESSED


class TestTheLimitsOfARule:
    """What a package rule cannot silence, which is the part that has to hold."""

    def test_a_known_exploited_advisory_is_reported_anyway(self):
        """Same as an advisory rule. An ignore is a judgement about a risk made
        at a moment in time; a KEV listing is new information about that same
        risk, so the judgement is out of date rather than binding.
        """
        decision = triage(
            dependency(),
            advisory(),
            kev_index={CVE},
            policy=with_packages("@acme/*"),
        )

        assert decision.verdict is Verdict.ACTIONABLE
        assert decision.ignore_overridden is True

    def test_malware_is_reported_anyway(self):
        """This matters more for package rules than for advisory rules.

        `@acme/*` is exactly the pattern somebody writes for their private
        scope. If an attacker publishes a typosquat into that scope, the rule
        written to silence registry-name collisions must not be what hides it.
        """
        decision = decide(with_packages("@acme/*"), malicious=True)

        assert decision.verdict is Verdict.ACTIONABLE
        assert decision.ignore_overridden is True

    def test_a_suppressed_finding_is_filed_not_deleted(self):
        """It stays on the Filtered tab, so "what am I not being told about?"
        keeps having an answer."""
        decision = decide(with_packages("@acme/*"))

        assert decision.verdict is Verdict.SUPPRESSED
        assert decision.suppression_reason.label == "Ignored by a rule on this project"


class TestNormalising:
    def test_case_and_whitespace_are_removed(self):
        assert normalise_packages([" @Acme/* ", "@ACME/*"]) == frozenset({"@acme/*"})

    def test_empty_input_is_an_empty_set(self):
        assert normalise_packages(None) == frozenset()
        assert normalise_packages([]) == frozenset()
        assert normalise_packages(["", "   "]) == frozenset()

    def test_non_strings_are_dropped_rather_than_raising(self):
        """Callers hand this whatever came out of a column or a YAML file."""
        assert normalise_packages(["@acme/*", None, 42]) == frozenset({"@acme/*"})


class TestFromThePolicyFile:
    def test_a_package_entry_is_read(self):
        parsed = parse_policy(
            """
            ignore:
              - package: "@acme/*"
                reason: Internal mirror of a name that also exists publicly.
            """
        )

        assert parsed.ignored_packages == ("@acme/*",)
        assert parsed.ignored_ids == ()
        assert parsed.warnings == ()

    def test_both_kinds_in_one_file(self):
        parsed = parse_policy(
            """
            ignore:
              - cve: CVE-2021-23337
                reason: Not reachable from any entry point we ship.
              - package: karma-*
                reason: Dead test tooling, removed next sprint.
            """
        )

        assert parsed.ignored_ids == ("CVE-2021-23337",)
        assert parsed.ignored_packages == ("karma-*",)
        assert parsed.is_empty is False

    def test_a_package_entry_still_needs_a_reason(self):
        parsed = parse_policy('ignore:\n  - package: "@acme/*"\n')

        assert parsed.ignored_packages == ()
        assert any("reason" in warning for warning in parsed.warnings)

    def test_a_pattern_matching_everything_is_refused(self):
        """Not an ignore rule. That is the product switched off, and a project
        is switched off by deactivating it -- which says so on the dashboard,
        where a rule that happens to match everything does not."""
        parsed = parse_policy('ignore:\n  - package: "*"\n    reason: all of it, thanks\n')

        assert parsed.ignored_packages == ()
        assert any("every package" in warning for warning in parsed.warnings)

    def test_an_entry_naming_both_is_refused_rather_than_guessed(self):
        parsed = parse_policy(
            'ignore:\n  - cve: CVE-2021-23337\n    package: "@acme/*"\n    reason: both please\n'
        )

        assert parsed.ignored_ids == ()
        assert parsed.ignored_packages == ()
        assert any("two entries" in warning for warning in parsed.warnings)

    def test_the_same_name_may_be_both_kinds(self):
        """Contrived, but the de-duplication key has to be the pair rather than
        the string, or one kind silently swallows the other."""
        parsed = parse_policy(
            """
            ignore:
              - cve: GHSA-XXXX
                reason: A specific advisory we have reviewed.
              - package: ghsa-xxxx
                reason: A package that happens to be named that.
            """
        )

        assert parsed.ignored_ids == ("GHSA-XXXX",)
        assert parsed.ignored_packages == ("ghsa-xxxx",)

    def test_a_duplicate_within_one_kind_is_reported(self):
        parsed = parse_policy(
            """
            ignore:
              - package: "@acme/*"
                reason: The first reason, which is the one that applies.
              - package: "@acme/*"
                reason: A second entry that says something else.
            """
        )

        assert parsed.ignored_packages == ("@acme/*",)
        assert any("more than once" in warning for warning in parsed.warnings)

    def test_an_overlong_pattern_is_refused(self):
        parsed = parse_policy(f'ignore:\n  - package: "{"a" * 300}"\n    reason: far too long\n')

        assert parsed.ignored_packages == ()
        assert any("too long" in warning for warning in parsed.warnings)


async def a_project(db, owner, content: str = '{"dependencies":{"@acme/logger":"1.0.0"}}'):
    from app.services.target_service import create_target

    return await create_target(db, owner, filename="package.json", content=content)


def a_package_rule(target_id: int, identifier: str = "@acme/*"):
    from app.models import IgnoreRule

    return IgnoreRule(
        target_id=target_id,
        identifier=identifier,
        kind=IgnoreKind.PACKAGE,
        reason="Internal mirror of a name that also exists publicly.",
    )


class TestThroughTheService:
    async def test_a_stored_package_rule_reaches_the_policy(self, db, pro_user):
        from app.services.rules_service import build_policy

        target = await a_project(db, pro_user)
        db.add(a_package_rule(target.id))
        await db.flush()

        effective = await build_policy(db, target, pro_user)

        assert effective.policy.ignored_packages == frozenset({"@acme/*"})
        assert effective.policy.ignored_ids == frozenset()
        assert effective.packages_from_settings == ("@acme/*",)

    async def test_settings_and_file_are_unioned(self, db, pro_user):
        from app.services.rules_service import build_policy

        target = await a_project(db, pro_user)
        db.add(a_package_rule(target.id))
        target.policy_file = "ignore:\n  - package: karma-*\n    reason: dead test tooling here\n"
        await db.flush()

        effective = await build_policy(db, target, pro_user)

        assert effective.policy.ignored_packages == frozenset({"@acme/*", "karma-*"})
        assert effective.packages_from_file == ("karma-*",)

    async def test_a_free_project_gets_stored_package_rules(self, db, user):
        from app.services.rules_service import build_policy

        target = await a_project(db, user)
        db.add(a_package_rule(target.id))
        await db.flush()

        effective = await build_policy(db, target, user)

        assert effective.policy.ignored_packages == frozenset({"@acme/*"})

    async def test_a_kev_override_does_not_mark_a_package_rule_as_set_aside(self, db, pro_user):
        """An advisory rule that KEV overrides is finished -- the one thing it
        named is now being reported. A package rule still holds for every other
        advisory it covers, so saying it stopped applying would be false.
        """
        from app.services.rules_service import record_overrides

        target = await a_project(db, pro_user)
        rule = a_package_rule(target.id)
        db.add(rule)
        await db.flush()

        assert await record_overrides(db, target.id, {"@ACME/*"}) == 0
        assert rule.overridden_at is None


class TestThroughTheInterface:
    async def _project_id(self, client, content='{"dependencies":{"@acme/logger":"1.0.0"}}'):
        created = await create_project(client, filename="package.json", content=content)
        assert created.status_code in (200, 201), created.text
        return created.json()["data"]["id"]

    async def test_a_package_rule_can_be_added_and_listed(self, pro_client):
        project_id = await self._project_id(pro_client)

        added = await pro_client.post(
            f"/api/internal/projects/{project_id}/rules",
            json={
                "identifier": "@Acme/*",
                "kind": "package",
                "reason": "Internal mirror of a name that also exists publicly.",
            },
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )

        assert added.status_code == 200, added.text
        assert added.json()["data"]["identifier"] == "@acme/*"
        assert added.json()["data"]["kind"] == "package"

        page = await pro_client.get(f"/api/internal/projects/{project_id}")
        rules = page.json()["rules"]
        assert [(rule["identifier"], rule["kind"]) for rule in rules] == [("@acme/*", "package")]

    async def test_an_unknown_kind_is_refused(self, pro_client):
        project_id = await self._project_id(pro_client)

        response = await pro_client.post(
            f"/api/internal/projects/{project_id}/rules",
            json={"identifier": "lodash", "kind": "everything", "reason": "a long enough reason"},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )

        assert response.status_code == 400

    async def test_no_kind_still_means_an_advisory(self, pro_client):
        """Every client written before package rules sends no kind, and means
        an advisory. It is also the safer default: a value misread as a glob
        could silence more than the caller asked for, and one misread as an
        advisory id silences nothing that is not named outright."""
        project_id = await self._project_id(pro_client)

        added = await pro_client.post(
            f"/api/internal/projects/{project_id}/rules",
            json={"identifier": "CVE-2021-23337", "reason": "not reachable from our code"},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )

        assert added.json()["data"]["kind"] == "advisory"

    async def test_a_pattern_that_matches_everything_is_refused(self, pro_client):
        project_id = await self._project_id(pro_client)

        response = await pro_client.post(
            f"/api/internal/projects/{project_id}/rules",
            json={"identifier": "*", "kind": "package", "reason": "silence all of it please"},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )

        assert response.status_code == 400
        assert "every package" in response.text

    async def test_the_two_kinds_do_not_collide(self, pro_client):
        """The unique constraint is keyed on the kind as well, so the same
        string may be both without the second add being refused as a
        duplicate."""
        project_id = await self._project_id(pro_client)
        csrf = set_csrf(pro_client)

        first = await pro_client.post(
            f"/api/internal/projects/{project_id}/rules",
            json={"identifier": "GHSA-XXXX", "reason": "an advisory we have reviewed"},
            headers={"X-CSRF-Token": csrf},
        )
        second = await pro_client.post(
            f"/api/internal/projects/{project_id}/rules",
            json={
                "identifier": "ghsa-xxxx",
                "kind": "package",
                "reason": "a package that happens to be named that",
            },
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )

        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text

    async def test_a_free_project_can_add_one(self, auth_client):
        project_id = await self._project_id(auth_client)

        response = await auth_client.post(
            f"/api/internal/projects/{project_id}/rules",
            json={
                "identifier": "@acme/*",
                "kind": "package",
                "reason": "Internal mirror of a public name.",
            },
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )

        assert response.status_code == 200
