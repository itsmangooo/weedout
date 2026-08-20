"""Malicious packages must never be filtered as noise.

This file exists because they were. OSV publishes malicious-package advisories
with a `MAL-` identifier and no CVSS score -- there is nothing to score, since
the package is malware and the fix is to remove it. Run through a severity
ladder that lands as `unknown`, which falls under every threshold, so the
triage filed it as "Below severity threshold and not exploited".

The mirror holds 231,597 of these. A product whose entire claim is telling you
what matters was filing packages that steal environment variables as noise.

The same omission had propagated: the API's inline-findings query selected on
`severity IN (critical, high) OR is_kev`, so malware never reached the list a
pipeline gates on, and the CLI's `Blocks()` read only severity and exploitation.
The tests below pin every one of those seams.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from app.core.explain import fix_sentence, risk_sentence, why_surfaced
from app.core.matching import DEFAULT_POLICY, normalise_ids, triage
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

MAL_ID = "MAL-2025-137567"


def malware(package: str = "umi-rujaksoto75-sluey") -> Vulnerability:
    """Exactly the shape the mirror holds: MAL- id, no score, no fix."""
    return Vulnerability(
        id=MAL_ID,
        summary=f"Malicious code in {package} (npm)",
        severity=Severity.UNKNOWN,
        affected=(
            AffectedPackage(
                ecosystem=Ecosystem.NPM,
                name=package,
                ranges=(AffectedRange(introduced="0", fixed=None),),
            ),
        ),
    )


def installed(
    package: str = "umi-rujaksoto75-sluey",
    reachability: Reachability = Reachability.RUNTIME_DIRECT,
) -> Dependency:
    return Dependency(
        ecosystem=Ecosystem.NPM,
        name=package,
        version="1.0.0",
        version_spec="1.0.0",
        reachability=reachability,
    )


class TestRecognisingOne:
    def test_a_mal_identifier_marks_the_advisory(self):
        assert malware().is_malicious is True

    def test_an_ordinary_advisory_is_not_marked(self):
        assert Vulnerability(id="GHSA-jf85-cpcp-j695").is_malicious is False
        assert Vulnerability(id="CVE-2021-23337").is_malicious is False

    def test_the_check_is_case_insensitive(self):
        assert Vulnerability(id="mal-2025-1").is_malicious is True


class TestItAlwaysAlerts:
    @pytest.mark.parametrize(
        "reachability",
        [
            Reachability.RUNTIME_DIRECT,
            Reachability.RUNTIME_TRANSITIVE,
            Reachability.DEV_ONLY,
        ],
    )
    def test_wherever_it_sits_in_the_tree(self, reachability):
        """Dev-only included. Malware in a dev dependency runs on developer
        machines and in CI, which is where the credentials are."""
        decision = triage(installed(reachability=reachability), malware(), policy=DEFAULT_POLICY)

        assert decision.verdict is Verdict.ACTIONABLE
        assert decision.actionable_reason is ActionableReason.MALICIOUS_PACKAGE

    def test_the_regression_itself(self):
        """The exact failure: severity `unknown` falling under every threshold
        and being filed as noise."""
        decision = triage(installed(), malware(), policy=DEFAULT_POLICY)

        assert decision.verdict is not Verdict.SUPPRESSED
        assert decision.suppression_reason is None

    def test_raising_the_threshold_cannot_silence_it(self):
        policy = replace(
            DEFAULT_POLICY,
            direct_threshold=Severity.CRITICAL,
            transitive_threshold=Severity.CRITICAL,
        )
        assert triage(installed(), malware(), policy=policy).verdict is Verdict.ACTIONABLE

    def test_an_ignore_rule_cannot_silence_it_either(self):
        """Same reasoning as a KEV listing: an ignore is a judgement about a
        risk, and "this package is malware" is not the risk it judged."""
        policy = replace(DEFAULT_POLICY, ignored_ids=normalise_ids([MAL_ID]))
        decision = triage(installed(), malware(), policy=policy)

        assert decision.verdict is Verdict.ACTIONABLE
        assert decision.ignore_overridden is True

    def test_a_withdrawn_malicious_advisory_is_still_withdrawn(self):
        """The one thing that outranks it. A retraction by the publisher means
        the data is wrong, and acting on data known to be wrong is worse."""
        retracted = replace(malware(), withdrawn=True)
        decision = triage(installed(), retracted, policy=DEFAULT_POLICY)
        assert decision.verdict is Verdict.SUPPRESSED


class TestWhatItTellsThePerson:
    def _decision(self):
        return triage(installed(), malware(), policy=DEFAULT_POLICY)

    def test_it_never_says_upgrade(self):
        """A later release of a malicious package is newer malware."""
        advice = fix_sentence(self._decision())
        assert "upgrade" not in advice.lower().split("upgrading")[0] or "not a fix" in advice
        assert "Remove" in advice

    def test_it_says_to_rotate_credentials(self):
        """Installing it already ran code. The package is the smaller problem."""
        advice = fix_sentence(self._decision())
        assert "rotate" in advice.lower()

    def test_it_explains_that_the_package_is_the_problem(self):
        explanation = why_surfaced(self._decision())
        assert "itself is malicious" in explanation

    def test_the_risk_sentence_does_not_reach_for_a_severity_word(self):
        """With no summary there is no score to describe, and calling it "an
        unknown-severity vulnerability" would be both wrong and reassuring."""
        bare = replace(malware(), summary="")
        decision = triage(installed(), bare, policy=DEFAULT_POLICY)
        assert "published as malware" in risk_sentence(decision)


class TestThePipelineSeesIt:
    async def test_it_reaches_the_findings_a_gate_reads(self, client, db, user):
        """The API selected on severity, so malware never made the inline list
        the CLI and the action decide on."""
        from tests.test_api import make_key, make_target
        from tests.test_scan_pipeline import seed_mirror

        await make_target(db, user)
        await seed_mirror(
            db,
            {
                "id": MAL_ID,
                "summary": "Malicious code in lodash (npm)",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    }
                ],
            },
        )
        token, _ = await make_key(db, user)

        response = await client.post(
            "/api/v1/scan",
            files={"manifest": ("package.json", '{"dependencies":{"lodash":"4.17.15"}}')},
            headers={"Authorization": f"Bearer {token}"},
        )
        body = response.json()

        assert body["counts"]["malicious"] == 1
        listed = [f for f in body["findings"] if f.get("malicious")]
        assert listed, "malware must appear in the findings a pipeline gates on"
        assert listed[0]["package"] == "lodash"

    async def test_malicious_is_its_own_field_not_a_severity(self, client, db, user):
        """A client that predates this reads a severity it understands rather
        than a level it cannot rank."""
        from tests.test_api import make_key, make_target
        from tests.test_scan_pipeline import seed_mirror

        await make_target(db, user)
        await seed_mirror(
            db,
            {
                "id": MAL_ID,
                "summary": "Malicious code in lodash (npm)",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    }
                ],
            },
        )
        token, _ = await make_key(db, user)

        body = (
            await client.post(
                "/api/v1/scan",
                files={"manifest": ("package.json", '{"dependencies":{"lodash":"4.17.15"}}')},
                headers={"Authorization": f"Bearer {token}"},
            )
        ).json()

        for finding in body["findings"]:
            assert finding["severity"] != "malicious"
            assert isinstance(finding["malicious"], bool)

    async def test_a_free_project_is_told_too(self, db, user):
        """Not one of the four Pro signals: this is CVE matching working
        correctly. Putting a malware alert behind a paywall is indefensible.
        """
        import json

        from app.core.types import ManifestKind, Tier
        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import make_target, seed_mirror

        assert user.tier is Tier.FREE

        await seed_mirror(
            db,
            {
                "id": MAL_ID,
                "summary": "Malicious code in lodash (npm)",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    }
                ],
            },
        )
        target = await make_target(db, user)
        target.manifest_kind = ManifestKind.PACKAGE_JSON
        target.manifest_content = json.dumps({"dependencies": {"lodash": "4.17.15"}})

        outcome = await scan_target(db, target)
        assert outcome.actionable_count >= 1
