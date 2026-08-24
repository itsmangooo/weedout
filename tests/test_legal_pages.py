"""The terms and the privacy policy.

Two kinds of test here, and the second kind is unusual enough to explain.

The ordinary kind checks the pages are served, are public, and render. The
other kind checks the *content* — specifically, that the factual claims in the
privacy policy are still true of the code. A privacy policy is a promise, and a
promise nothing verifies is one that quietly becomes false the first time
somebody adds an analytics snippet "just to see the numbers".

So: the policy says there is no analytics, and `test_the_no_analytics_claim_is_true`
fails if any appears. The policy says a scan reaches no third party, and
`test_the_local_matching_claim_is_true` fails if the scan path grows an
outbound call. These are not tests of the document. They are tests that the
document is not lying.

`TestNothingShipsHalfFinished` is the release gate: every `[[PLACEHOLDER]]`
must be replaced before these pages can be published.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.content.legal import PRIVACY, TERMS, unresolved_placeholders

ROOT = Path(__file__).resolve().parent.parent


def flat(text: str) -> str:
    """The document with its line wrapping removed.

    Every assertion below is about what the document *says*. Where the prose
    happens to wrap is a formatting detail, and matching the raw string would
    mean a reflow breaking a test that is checking a promise.
    """
    return " ".join(text.split())


class TestNothingShipsHalfFinished:
    """A privacy policy with `[[JURISDICTION]]` in it is worse than none.

    These are expected to fail until somebody fills the placeholders in, and
    that is the point: the failure is the reminder. Mark them xfail or delete
    them when the documents are finished, in the same commit that finishes
    them.
    """

    @pytest.mark.xfail(
        reason="Placeholders are unresolved until the legal details are decided. "
        "Remove this marker in the commit that fills them in.",
        strict=False,
    )
    def test_the_terms_have_no_placeholders(self):
        remaining = sorted(set(unresolved_placeholders(TERMS)))

        assert remaining == [], f"still to decide: {remaining}"

    @pytest.mark.xfail(
        reason="Placeholders are unresolved until the legal details are decided. "
        "Remove this marker in the commit that fills them in.",
        strict=False,
    )
    def test_the_privacy_policy_has_no_placeholders(self):
        remaining = sorted(set(unresolved_placeholders(PRIVACY)))

        assert remaining == [], f"still to decide: {remaining}"

    def test_every_placeholder_is_a_decision_and_not_a_typo(self):
        """A `[[...]]` that is not in this list is probably a mistake in the
        markup rather than a question for a lawyer."""
        known = {
            "BREACH NOTIFICATION PERIOD",
            "COMPANY NUMBER",
            "DATE",
            "EMAIL PROVIDER",
            "FINANCIAL RECORD RETENTION",
            "HOSTING PROVIDER",
            "HOSTING REGION",
            "INTERNATIONAL TRANSFER BASIS, IF ANY",
            "JURISDICTION",
            "LEGAL ENTITY NAME",
            "LOG RETENTION PERIOD",
            "NOTICE PERIOD",
            "PAYMENT PROVIDER",
            "PRIVACY CONTACT EMAIL",
            "REFUND POLICY",
            "REGISTERED ADDRESS",
            "SUPERVISORY AUTHORITY",
            "SUPPORT EMAIL",
        }
        found = set(unresolved_placeholders(TERMS)) | set(unresolved_placeholders(PRIVACY))

        assert found <= known, f"unexpected placeholders: {sorted(found - known)}"


class TestThePrivacyPolicyIsNotLying:
    """Tests of the code, phrased as tests of the promises made about it."""

    def test_the_no_analytics_claim_is_true(self):
        """The policy says: no analytics, no tracking pixel, no third-party
        script. Not a reduced set — none.

        The most load-bearing sentence in the document, and the easiest to
        falsify by accident.
        """
        assert "no analytics" in flat(PRIVACY).lower()

        suspects = re.compile(
            # Hostnames and API surfaces rather than bare product names.
            # A bare 'plausible' matched the English word in a comment about
            # EPSS thresholds, and that is the kind of false positive that
            # gets a guardrail deleted rather than fixed.
            r"googletagmanager|google-analytics|gtag\(|posthog\.|mixpanel\."
            r"|segment\.com|plausible\.io|usefathom\.com|hotjar\.|fullstory\."
            r"|amplitude\.com|heap\.io|facebook\.net|clarity\.ms",
            re.IGNORECASE,
        )

        offenders = []
        for directory in ("app", "frontend/src"):
            for path in (ROOT / directory).rglob("*"):
                if path.suffix not in {".py", ".js", ".jsx", ".html", ".css"}:
                    continue
                if "node_modules" in path.parts or path.name.endswith(".test.js"):
                    continue
                # This file names them all, by necessity.
                if path.name == "test_legal_pages.py":
                    continue
                if suspects.search(path.read_text(encoding="utf-8", errors="ignore")):
                    offenders.append(str(path.relative_to(ROOT)))

        assert offenders == [], (
            f"the privacy policy promises no analytics, and these look like some: {offenders}. "
            f"Either remove it or change the policy -- but the policy is the promise, "
            f"so removing it is almost certainly the right answer."
        )

    def test_the_local_matching_claim_is_true(self):
        """The policy says scanning does not tell OSV or anybody else what you
        depend on, because matching happens against a local mirror.

        Falsified the moment the scan path grows an outbound call, which would
        be an easy thing to add for a good reason and a serious thing to add
        silently.
        """
        assert "never leaves our servers during a scan" in flat(PRIVACY)

        scan_path = (ROOT / "app/services/scan_service.py").read_text(encoding="utf-8")

        for outbound in ("httpx.", "requests.", "urlopen", "aiohttp"):
            assert outbound not in scan_path, (
                f"{outbound} appears in the scan path, and the privacy policy promises "
                f"a scan reaches no third party."
            )

    def test_the_cookies_listed_are_the_cookies_set(self):
        """A cookie table that has drifted from reality is the kind of small
        inaccuracy that makes a reader doubt the rest of the page."""
        from app.config import get_settings

        settings = get_settings()
        assert settings.session_cookie_name in PRIVACY
        assert "weedout_csrf" in PRIVACY
        assert "weedout_mfa" in PRIVACY

    def test_the_retention_windows_match_the_plan_table(self):
        """The policy quotes 30 days and a year for the findings archive.
        Those numbers live in `app/tiers.py`, and two copies of a number is one
        copy too many."""
        from app.core.types import Tier
        from app.tiers import history_cutoff_days

        assert f"{history_cutoff_days(Tier.FREE)} days on Free" in flat(PRIVACY)
        assert history_cutoff_days(Tier.PRO) == 365
        assert "a year on Pro" in flat(PRIVACY)

    def test_the_password_hashing_claim_is_true(self):
        assert "Argon2" in PRIVACY

        security = (ROOT / "app/security.py").read_text(encoding="utf-8")
        assert "argon2" in security.lower()


class TestTheTermsSayWhatItIsNot:
    """The section that matters most for a security product."""

    def test_they_refuse_to_promise_security(self):
        assert "not a guarantee that your software is secure" in flat(TERMS)

    def test_they_list_what_it_will_miss(self):
        """A limitations section that says "may not catch everything" is
        boilerplate. One that names the cases is a warning somebody can act
        on."""
        for case in ("no advisory has been published", "did not tell us about", "stale"):
            assert case in flat(TERMS), f"the limits section does not mention: {case}"

    def test_they_point_at_the_status_page(self):
        """So "was it working when it told me I was clean?" is a checkable
        question rather than a rhetorical one."""
        assert "/status" in TERMS

    def test_they_do_not_claim_uptime(self):
        assert "no uptime commitment" in flat(TERMS)

    def test_they_say_a_customer_is_named_only_on_request(self):
        assert "explicitly asked to be named" in flat(TERMS)


class TestThroughTheEndpoint:
    async def test_both_pages_are_public(self, client):
        """They have to be readable before somebody has an account to read
        them with — which is the moment they matter, since they are what that
        person is agreeing to."""
        for slug in ("terms", "privacy"):
            response = await client.get(f"/api/internal/legal/{slug}")
            assert response.status_code == 200, slug
            assert response.json()["data"]["body_html"]

    async def test_an_unknown_page_is_a_404(self, client):
        assert (await client.get("/api/internal/legal/refunds")).status_code == 404

    async def test_they_are_cacheable(self, client):
        response = await client.get("/api/internal/legal/terms")

        assert "public" in response.headers["cache-control"]

    async def test_the_body_is_rendered_html_not_markdown(self, client):
        body = (await client.get("/api/internal/legal/privacy")).json()["data"]["body_html"]

        assert "<h2" in body
        assert "## The short version" not in body

    @pytest.mark.parametrize("path", ["/terms", "/privacy"])
    async def test_the_shell_is_served(self, client, path):
        response = await client.get(path)

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
