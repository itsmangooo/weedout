"""The public landing page.

The constraint that matters here is anonymity. The "recently flagged" section
shows real findings from real scans across every account, so these tests assert
what must *never* appear in the response: an email address, a project name, an
account id. Package names, versions and CVE ids are already public information
published by npm, PyPI, Go and OSV.

The second rule is that the section is live or absent — it never falls back to
invented example rows, because "this is real data" is the whole claim.
"""

from __future__ import annotations

import pytest

from app.core.types import (
    AlertStatus,
    Ecosystem,
    ManifestKind,
    Reachability,
    Severity,
    Verdict,
)
from app.models import CVEMatch, TrackedTarget, VulnerabilityRecord
from app.services.public_service import clear_cache, get_landing_data
from tests.factories import attach_manifest


@pytest.fixture(autouse=True)
def _no_cache():
    """The landing snapshot is process-cached; tests must not share it."""
    clear_cache()
    yield
    clear_cache()


async def make_finding(
    db,
    owner,
    *,
    package="lodash",
    version="4.17.15",
    cve="CVE-2020-8203",
    severity=Severity.CRITICAL,
    is_kev=False,
    verdict=Verdict.ACTIONABLE,
    status=None,
    project_name="super-secret-project",
    vuln_id=None,
) -> CVEMatch:
    vuln_id = vuln_id or f"GHSA-{package}-{cve}"
    if await db.get(VulnerabilityRecord, vuln_id) is None:
        db.add(
            VulnerabilityRecord(
                id=vuln_id,
                cve_ids=[cve],
                summary=f"A vulnerability in {package}",
            )
        )
        await db.flush()

    target = TrackedTarget(
        user_id=owner.id,
        name=project_name,
        manifest_kind=ManifestKind.PACKAGE_JSON,
        ecosystem=Ecosystem.NPM,
        manifest_content="{}",
        content_hash=(package + version).ljust(64, "0")[:64],
        dependency_count=25,
    )
    db.add(target)
    await db.flush()
    manifest = await attach_manifest(db, target)

    match = CVEMatch(
        target_id=target.id,
        manifest_id=manifest.id,
        vulnerability_id=vuln_id,
        ecosystem=Ecosystem.NPM,
        package_name=package,
        package_version=version,
        reachability=Reachability.RUNTIME_DIRECT,
        verdict=verdict,
        severity=severity,
        is_kev=is_kev,
        fixed_version="9.9.9",
        actionable_reason="critical_in_production" if verdict is Verdict.ACTIONABLE else None,
        suppression_reason=None if verdict is Verdict.ACTIONABLE else "below_severity_threshold",
        status=status
        or (AlertStatus.FILTERED if verdict is Verdict.SUPPRESSED else AlertStatus.OPEN),
    )
    db.add(match)
    await db.flush()
    return match


class TestAnonymity:
    async def test_no_user_email_reaches_the_landing_page(self, client, db, user):
        """Asserted on the endpoint the page reads.

        The page is React now, so the HTML no longer contains the data — which
        would make an assertion against it pass for the wrong reason. What is
        served is what matters.
        """
        await make_finding(db, user)

        response = await client.get("/api/internal/landing")
        assert response.status_code == 200
        assert user.email not in response.text
        assert "example.com" not in response.text

    async def test_no_project_name_reaches_the_landing_page(self, client, db, user):
        await make_finding(db, user, project_name="acme-internal-billing")

        response = await client.get("/api/internal/landing")
        assert "acme-internal-billing" not in response.text

    async def test_the_finding_itself_is_still_shown(self, client, db, user):
        # Anonymised, not omitted — the section has to carry real information.
        await make_finding(db, user, package="minimist", cve="CVE-2021-44906")

        response = await client.get("/api/internal/landing")
        assert "minimist" in response.text
        assert "CVE-2021-44906" in response.text

    async def test_the_data_object_carries_no_identifying_fields(self, db, user):
        await make_finding(db, user, project_name="private-name")
        data = await get_landing_data(db, ttl=0)

        assert data.findings
        for finding in data.findings:
            serialised = repr(finding)
            assert user.email not in serialised
            assert "private-name" not in serialised
            assert not hasattr(finding, "user_id")
            assert not hasattr(finding, "target_id")

    async def test_suspended_accounts_are_excluded(self, db, user):
        # A closed account's findings are not advertising material.
        await make_finding(db, user, package="only-package")
        user.is_suspended = True
        await db.flush()

        data = await get_landing_data(db, ttl=0)
        assert data.findings == []


class TestSelection:
    async def test_only_critical_or_exploited_findings_appear(self, db, user):
        await make_finding(db, user, package="critical-pkg", severity=Severity.CRITICAL)
        await make_finding(
            db, user, package="kev-pkg", severity=Severity.LOW, is_kev=True, cve="CVE-2000-1"
        )
        await make_finding(db, user, package="high-pkg", severity=Severity.HIGH, cve="CVE-2000-2")

        data = await get_landing_data(db, ttl=0)
        packages = {f.package for f in data.findings}
        assert packages == {"critical-pkg", "kev-pkg"}

    async def test_suppressed_findings_never_appear(self, db, user):
        await make_finding(db, user, package="filtered-pkg", verdict=Verdict.SUPPRESSED)
        data = await get_landing_data(db, ttl=0)
        assert data.findings == []

    async def test_dismissed_and_resolved_findings_never_appear(self, db, user):
        await make_finding(db, user, package="a", status=AlertStatus.DISMISSED)
        await make_finding(db, user, package="b", status=AlertStatus.RESOLVED, cve="CVE-2000-3")
        data = await get_landing_data(db, ttl=0)
        assert data.findings == []

    async def test_withdrawn_advisories_are_excluded(self, db, user):
        match = await make_finding(db, user, package="withdrawn-pkg")
        record = await db.get(VulnerabilityRecord, match.vulnerability_id)
        record.withdrawn = True
        await db.flush()

        data = await get_landing_data(db, ttl=0)
        assert data.findings == []

    async def test_the_same_package_and_cve_appears_once(self, db, user, pro_user):
        # Otherwise one popular vulnerable package fills the whole list — and
        # the repetition would reveal how many customers use it.
        await make_finding(db, user, package="lodash")
        await make_finding(db, pro_user, package="lodash")

        data = await get_landing_data(db, ttl=0)
        assert len([f for f in data.findings if f.package == "lodash"]) == 1


class TestTrends:
    """Aggregates across every account: counts, and nothing that names anyone.

    Two guarantees are load-bearing. Nothing published may identify an account
    or a project, and no row may be published unless enough distinct accounts
    stand behind it — a count of one is a statement about one customer's stack.
    """

    async def _third_user(self, db):
        from app.core.types import Tier
        from app.models import User
        from app.security import hash_password

        record = User(
            email="third@example.com",
            password_hash=hash_password("correct-horse-battery"),
            tier=Tier.FREE,
        )
        db.add(record)
        await db.flush()
        return record

    async def test_a_finding_on_a_single_account_is_not_published(self, db, user):
        await make_finding(db, user, package="niche-internal-lib")

        data = await get_landing_data(db, ttl=0)
        assert data.trending_packages == []
        assert data.trending_cves == []
        assert data.has_trends is False

    async def test_a_package_shared_by_two_accounts_is_published(self, db, user, pro_user):
        await make_finding(db, user, package="lodash")
        await make_finding(db, pro_user, package="lodash")

        data = await get_landing_data(db, ttl=0)
        assert [p.name for p in data.trending_packages] == ["lodash"]
        assert data.trending_packages[0].project_count == 2
        assert data.has_trends is True

    async def test_one_account_with_many_projects_does_not_reach_the_threshold(self, db, user):
        """Five projects on one account is still one customer.

        Gating on projects instead of accounts would let a single user's
        monorepo publish a row about their own dependency list.
        """
        for index in range(5):
            await make_finding(db, user, package="lodash", version=f"4.17.{index}")

        data = await get_landing_data(db, ttl=0)
        assert data.trending_packages == []

    async def test_the_published_counts_are_projects_not_accounts(self, db, user, pro_user):
        third = await self._third_user(db)
        # Two projects for one account, one each for the others.
        await make_finding(db, user, package="lodash", version="4.17.1")
        await make_finding(db, user, package="lodash", version="4.17.2")
        await make_finding(db, pro_user, package="lodash", version="4.17.3")
        await make_finding(db, third, package="lodash", version="4.17.4")

        data = await get_landing_data(db, ttl=0)
        assert data.trending_packages[0].project_count == 4

    async def test_no_account_count_is_exposed(self, db, user, pro_user):
        await make_finding(db, user, package="lodash")
        await make_finding(db, pro_user, package="lodash")

        data = await get_landing_data(db, ttl=0)
        row = data.trending_packages[0]
        # The account count is the gate, never the output — publishing it would
        # be a running total of how many customers exist.
        assert not hasattr(row, "user_count")
        assert not hasattr(row, "account_count")

    async def test_packages_are_ranked_by_reach(self, db, user, pro_user):
        third = await self._third_user(db)
        for owner in (user, pro_user, third):
            await make_finding(db, owner, package="widespread")
        for owner in (user, pro_user):
            await make_finding(db, owner, package="narrower", cve="CVE-2000-7")

        data = await get_landing_data(db, ttl=0)
        assert [p.name for p in data.trending_packages] == ["widespread", "narrower"]

    async def test_suppressed_findings_are_not_counted(self, db, user, pro_user):
        # The filtered noise is not a trend; counting it would contradict the
        # number printed directly above it on the page.
        await make_finding(db, user, package="quiet", verdict=Verdict.SUPPRESSED)
        await make_finding(db, pro_user, package="quiet", verdict=Verdict.SUPPRESSED)

        data = await get_landing_data(db, ttl=0)
        assert data.trending_packages == []

    async def test_suspended_accounts_do_not_count_toward_the_threshold(self, db, user, pro_user):
        await make_finding(db, user, package="lodash")
        await make_finding(db, pro_user, package="lodash")
        pro_user.is_suspended = True
        await db.flush()

        data = await get_landing_data(db, ttl=0)
        assert data.trending_packages == []

    async def test_findings_outside_the_window_are_not_counted(self, db, user, pro_user):
        from datetime import timedelta

        from app.models import utcnow

        first = await make_finding(db, user, package="lodash")
        second = await make_finding(db, pro_user, package="lodash")
        for match in (first, second):
            match.first_seen_at = utcnow() - timedelta(days=45)
        await db.flush()

        data = await get_landing_data(db, ttl=0)
        assert data.trending_packages == []

    async def test_a_month_window_sees_what_the_week_missed(self, db, user, pro_user):
        from datetime import timedelta

        from app.models import utcnow
        from app.services.public_service import trending_packages

        first = await make_finding(db, user, package="lodash")
        second = await make_finding(db, pro_user, package="lodash")
        for match in (first, second):
            match.first_seen_at = utcnow() - timedelta(days=14)
        await db.flush()

        assert await trending_packages(db, days=7) == []
        assert [p.name for p in await trending_packages(db, days=30)] == ["lodash"]

    async def test_trending_cves_carry_their_severity_not_a_sorted_string(self, db, user, pro_user):
        await make_finding(db, user, package="lodash", severity=Severity.CRITICAL)
        await make_finding(db, pro_user, package="lodash", severity=Severity.CRITICAL)

        data = await get_landing_data(db, ttl=0)
        assert data.trending_cves[0].severity is Severity.CRITICAL
        assert data.trending_cves[0].cve_id == "CVE-2020-8203"

    async def test_the_rendered_section_names_no_project(self, client, db, user, pro_user):
        await make_finding(db, user, package="lodash", project_name="acme-billing")
        await make_finding(db, pro_user, package="lodash", project_name="acme-payroll")

        response = await client.get("/api/internal/landing")
        trending = response.json()["data"]["trending_packages"]

        assert any(entry["name"] == "lodash" for entry in trending)
        assert "acme-billing" not in response.text
        assert "acme-payroll" not in response.text
        assert user.email not in response.text

    async def test_the_section_is_absent_rather_than_padded(self, client, db, user):
        await make_finding(db, user, package="lonely")

        response = await client.get("/api/internal/landing")

        # Absent rather than padded. One account is not a trend, and inventing
        # rows to fill the section would make the only factual thing on the
        # page fiction.
        body = response.json()["data"]
        assert body["trending_packages"] == []
        assert body["trending_cves"] == []


class TestEmptyState:
    async def test_no_findings_means_the_section_is_absent(self, client, db):
        response = await client.get("/api/internal/landing")

        assert response.status_code == 200
        # Never a fabricated placeholder row: the claim is that it is live.
        assert response.json()["data"]["findings"] == []

    async def test_the_page_still_renders_with_no_data_at_all(self, client):
        """The section is an extra on a marketing page. It must never be the
        reason the page itself does not appear."""
        page = await client.get("/")
        assert page.status_code == 200

        data = await client.get("/api/internal/landing")
        assert data.status_code == 200


class TestCaching:
    async def test_repeat_calls_reuse_the_snapshot(self, db, user):
        await make_finding(db, user, package="first")
        first = await get_landing_data(db)

        # A new finding is not picked up until the snapshot expires — that is
        # the trade the cache buys, and it is deliberate.
        await make_finding(db, user, package="second", cve="CVE-2000-9")
        second = await get_landing_data(db)

        assert second is first

    async def test_a_zero_ttl_always_refetches(self, db, user):
        await make_finding(db, user, package="first")
        await get_landing_data(db, ttl=0)

        await make_finding(db, user, package="second", cve="CVE-2000-9")
        refreshed = await get_landing_data(db, ttl=0)

        assert {f.package for f in refreshed.findings} == {"first", "second"}


class TestLandingContent:
    async def test_pricing_comes_from_the_tiers_module(self, client):
        import html

        from app.tiers import PLANS

        # /pricing rather than /: the landing page is React now and does not
        # render the plan table. The property — that the copy comes from the
        # same table the limits are enforced from, so the page cannot drift
        # from the product — belongs to whichever page shows it.
        response = await client.get("/api/internal/pricing")
        for plan in PLANS.values():
            assert plan.display_name in response.text
            assert plan.price_label in response.text
            # Feature copy is rendered from the same table the limits are
            # enforced from, so the page cannot drift from the product.
            # Compared escaped, since Jinja autoescapes "&" and friends.
            for feature in plan.features:
                assert html.escape(feature) in response.text

    async def test_signed_in_users_skip_the_landing_page(self, auth_client):
        response = await auth_client.get("/")
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"


class TestPricingCopyMatchesTheProduct:
    """The public pricing contract stays aligned with the single Free plan."""

    async def test_it_does_not_claim_the_plans_see_the_same_things(self, client):
        for path in ("/", "/pricing"):
            body = (await client.get(path)).text
            assert "does not show you a different set of vulnerabilities" not in body
            assert "same filtering rules" not in body

    async def test_the_free_card_matches_the_full_tree_capability(self, client):
        from app.core.types import Tier
        from app.tiers import PLANS

        # The plan copy and the prose beside it both come from tiers.py, so
        # the endpoint that serves the table is where the agreement is
        # checkable. The prose lives in the React page and is covered there.
        body = (await client.get("/api/internal/pricing")).text
        assert "Full dependency tree analysis" in body
        # And the claim is still true of the plan table it describes.
        assert PLANS[Tier.FREE].scan_depth is None
        assert PLANS[Tier.PRO] is PLANS[Tier.FREE]
