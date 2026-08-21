"""Discord webhook alerts.

The security-relevant part is that a user supplies a URL and the server then
makes a request to it. That is server-side request forgery in its textbook
shape, so the URL parser gets tested against the ways people actually attack
one -- userinfo before an allowlisted host, a port, a redirect parameter, a
newline -- rather than only against "not a discord link".

The rest is about not lying: a broken webhook must not stop the email, and a
finding nobody was told about must not be marked as notified.
"""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from app.core.discord import (
    DigestFinding,
    InvalidWebhookURL,
    build_digest_payload,
    build_test_payload,
    mask_webhook_url,
    parse_webhook_url,
)
from app.core.types import Ecosystem
from app.models import Alert, TrackedTarget
from app.security import hash_password
from tests.conftest import set_csrf, sign_in

VALID = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz012345"


class TestTheURLIsNotTrusted:
    """An allowlist of Discord's own hosts, not a blocklist of private ranges.

    A blocklist has to anticipate every spelling of "localhost"; an allowlist
    has to be right once.
    """

    def test_a_real_webhook_is_accepted(self):
        webhook = parse_webhook_url(VALID)
        assert webhook.webhook_id == "123456789012345678"
        assert webhook.host == "discord.com"

    def test_the_legacy_domain_still_works(self):
        """Webhooks created years ago carry discordapp.com and still deliver."""
        url = VALID.replace("discord.com", "discordapp.com")
        assert parse_webhook_url(url).host == "discordapp.com"

    @pytest.mark.parametrize(
        ("url", "why"),
        [
            (VALID.replace("https", "http"), "plaintext"),
            (
                "https://discord.com@evil.example/api/webhooks/123456789012345678/"
                "abcdefghijklmnopqrstuvwxyz012345",
                "userinfo before the real host",
            ),
            (
                "https://evil.example/api/webhooks/123456789012345678/"
                "abcdefghijklmnopqrstuvwxyz012345",
                "wrong host entirely",
            ),
            (
                "https://notdiscord.com/api/webhooks/123456789012345678/"
                "abcdefghijklmnopqrstuvwxyz012345",
                "host that merely contains the name",
            ),
            (
                "https://discord.com.evil.example/api/webhooks/123456789012345678/"
                "abcdefghijklmnopqrstuvwxyz012345",
                "host with the name as a prefix",
            ),
            (VALID.replace("discord.com", "discord.com:8080"), "a port"),
            (
                "https://127.0.0.1/api/webhooks/123456789012345678/"
                "abcdefghijklmnopqrstuvwxyz012345",
                "loopback",
            ),
            (
                "https://169.254.169.254/api/webhooks/123456789012345678/"
                "abcdefghijklmnopqrstuvwxyz012345",
                "cloud metadata",
            ),
            (VALID + "?next=http://169.254.169.254/", "a query string"),
            (VALID + "#fragment", "a fragment"),
            (VALID + "\nX-Injected: 1", "a newline"),
            ("https://discord.com/channels/123/456", "a channel link, not a webhook"),
            ("https://discord.com/api/webhooks/1/x", "implausibly short ids"),
            ("", "nothing at all"),
            ("   ", "whitespace"),
        ],
    )
    def test_these_are_all_refused(self, url, why):
        with pytest.raises(InvalidWebhookURL):
            parse_webhook_url(url)

    def test_the_refusal_says_something_useful(self):
        with pytest.raises(InvalidWebhookURL) as caught:
            parse_webhook_url("https://discord.com/channels/123/456")
        assert "Copy Webhook URL" in str(caught.value)

    def test_masking_hides_the_token(self):
        masked = mask_webhook_url(VALID)
        assert "abcdefghijklmnopqrstuvwxyz012345" not in masked
        # Still recognisable as which webhook it is.
        assert "123456789012345678" in masked

    def test_masking_an_invalid_url_reveals_nothing(self):
        assert "secret" not in mask_webhook_url("https://evil.example/secret")


class TestThePayload:
    def _finding(self, **overrides):
        base = {
            "package": "lodash",
            "version": "4.17.15",
            "cve": "CVE-2021-23337",
            "severity": "high",
            "exploited": False,
            "fixed_version": "4.17.21",
        }
        base.update(overrides)
        return DigestFinding(**base)

    def test_exploited_findings_come_first_and_set_the_colour(self):
        payload = build_digest_payload(
            project="acme",
            findings=[
                self._finding(),
                self._finding(package="systeminformation", exploited=True, severity="high"),
            ],
            dashboard_url="https://weedout.dev/targets/1",
        )
        embed = payload["embeds"][0]
        assert embed["fields"][0]["name"].startswith("systeminformation")
        assert "actively exploited" in embed["title"]

    def test_a_finding_with_no_fix_says_so(self):
        payload = build_digest_payload(
            project="acme",
            findings=[self._finding(fixed_version=None)],
            dashboard_url="https://weedout.dev/targets/1",
        )
        assert "No fix published yet" in payload["embeds"][0]["fields"][0]["value"]

    def test_the_filtered_count_is_mentioned(self):
        """The number this product is proud of is the one it did not send."""
        payload = build_digest_payload(
            project="acme",
            findings=[self._finding()],
            dashboard_url="https://weedout.dev/targets/1",
            filtered_count=47,
        )
        assert "47" in payload["embeds"][0]["description"]

    def test_a_long_list_is_capped_rather_than_rejected(self):
        """Discord answers an over-long payload with a 400, so the limits are
        applied here rather than discovered in production."""
        payload = build_digest_payload(
            project="acme",
            findings=[self._finding(package=f"pkg-{n}") for n in range(60)],
            dashboard_url="https://weedout.dev/targets/1",
        )
        embed = payload["embeds"][0]
        assert len(embed["fields"]) <= 25
        assert "35 more on the dashboard" in embed["description"]

    def test_every_field_is_within_discords_limits(self):
        payload = build_digest_payload(
            project="x" * 400,
            findings=[
                DigestFinding(
                    package="p" * 400,
                    version="1.0.0",
                    cve="CVE-2021-1",
                    severity="critical",
                    exploited=True,
                    fixed_version="y" * 2000,
                )
            ],
            dashboard_url="https://weedout.dev/targets/1",
        )
        embed = payload["embeds"][0]
        assert len(embed["title"]) <= 256
        assert len(embed["description"]) <= 4096
        for field in embed["fields"]:
            assert len(field["name"]) <= 256
            assert len(field["value"]) <= 1024

    def test_a_test_message_says_it_is_a_test(self):
        """Otherwise it trains the channel to ignore the real ones."""
        payload = build_test_payload(project="acme")
        assert "test" in payload["embeds"][0]["description"].lower()

    def test_an_empty_digest_is_a_programming_error(self):
        with pytest.raises(ValueError):
            build_digest_payload(project="acme", findings=[], dashboard_url="x")


@pytest.fixture
async def pro_target(db, pro_user) -> TrackedTarget:
    target = TrackedTarget(
        user_id=pro_user.id, name="acme-store", ecosystem=Ecosystem.NPM, is_active=True
    )
    db.add(target)
    await db.flush()
    return target


@pytest.fixture
async def pro_client(client, pro_user, db) -> httpx.AsyncClient:
    pro_user.password_hash = hash_password("correct-horse-battery")
    await db.flush()
    response = await sign_in(client, pro_user.email)
    assert response.status_code == 200, response.text
    return client


class TestSavingAWebhook:
    async def test_a_pro_user_can_save_one(self, pro_client, db, pro_target):
        response = await pro_client.post(
            f"/api/internal/projects/{pro_target.id}/webhook",
            json={"url": VALID},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )
        assert response.status_code == 200
        await db.refresh(pro_target)
        assert pro_target.discord_webhook_url == VALID

    async def test_the_saved_url_is_never_rendered_in_full(self, pro_client, db, pro_target):
        pro_target.discord_webhook_url = VALID
        await db.commit()

        response = await pro_client.get(f"/api/internal/projects/{pro_target.id}")

        # Stronger than the masking the template used to do: the secret is not
        # in the response at all, only the host, which is enough to show the
        # webhook is configured and where it points.
        assert "abcdefghijklmnopqrstuvwxyz012345" not in response.text
        assert response.json()["webhook"]["configured"] is True
        assert response.json()["webhook"]["host"] == "discord.com"

    async def test_a_hostile_url_is_refused_and_nothing_is_stored(self, pro_client, db, pro_target):
        response = await pro_client.post(
            f"/api/internal/projects/{pro_target.id}/webhook",
            json={
                "url": "https://169.254.169.254/api/webhooks/123456789012345678/"
                "abcdefghijklmnopqrstuvwxyz012345"
            },
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )
        assert response.status_code == 400
        await db.refresh(pro_target)
        assert pro_target.discord_webhook_url is None

    async def test_a_free_user_cannot_save_one(self, auth_client, db, user):
        target = TrackedTarget(
            user_id=user.id, name="free-project", ecosystem=Ecosystem.NPM, is_active=True
        )
        db.add(target)
        await db.commit()

        response = await auth_client.post(
            f"/api/internal/projects/{target.id}/webhook",
            json={"url": VALID},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )
        assert response.status_code == 402
        assert "Pro" in response.text
        await db.refresh(target)
        assert target.discord_webhook_url is None

    async def test_somebody_elses_project_is_a_404(self, pro_client, db, user):
        theirs = TrackedTarget(
            user_id=user.id, name="not-yours", ecosystem=Ecosystem.NPM, is_active=True
        )
        db.add(theirs)
        await db.commit()

        response = await pro_client.post(
            f"/api/internal/projects/{theirs.id}/webhook",
            json={"url": VALID},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )
        assert response.status_code == 404
        await db.refresh(theirs)
        assert theirs.discord_webhook_url is None

    async def test_removing_it_clears_the_error_too(self, pro_client, db, pro_target):
        pro_target.discord_webhook_url = VALID
        pro_target.discord_last_error = "That webhook no longer exists in Discord."
        await db.commit()

        await pro_client.post(
            f"/api/internal/projects/{pro_target.id}/webhook/remove",
            json={},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )
        await db.refresh(pro_target)
        assert pro_target.discord_webhook_url is None
        assert pro_target.discord_last_error is None


class TestTheDispatcher:
    """`send_new_match_digest` over two channels.

    The property worth pinning is independence: neither channel can take the
    other down, and a finding nobody heard about is not marked as notified.
    """

    async def _scanned_project(self, db, owner, *, webhook: str | None = None):
        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import LODASH_ADVISORY, make_target, seed_mirror

        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, owner)
        target.discord_webhook_url = webhook
        outcome = await scan_target(db, target)
        assert outcome.new_matches, "the fixture should produce a finding"
        return target, outcome

    async def test_a_pro_project_posts_to_discord_as_well_as_email(self, db, pro_user, monkeypatch):
        from app.services.alert_service import send_new_match_digest
        from app.services.discord_service import DeliveryResult

        posted = {}

        async def fake_post(url, payload, **kwargs):
            posted["url"] = url
            posted["payload"] = payload
            return DeliveryResult(ok=True, status=204)

        monkeypatch.setattr("app.services.alert_service.post_webhook", fake_post)

        target, outcome = await self._scanned_project(db, pro_user, webhook=VALID)
        assert await send_new_match_digest(db, pro_user, target, outcome.new_matches) == 1

        assert posted["url"] == VALID
        assert "lodash" in str(posted["payload"])

        await db.commit()
        await db.refresh(target)
        assert target.discord_last_sent_at is not None
        assert target.discord_last_error is None

        alerts = (await db.scalars(select(Alert).where(Alert.user_id == pro_user.id))).all()
        channels = sorted(alert.channel for alert in alerts)
        assert channels == ["discord", "email"]
        assert all(alert.status == "sent" for alert in alerts)

    async def test_the_webhook_url_is_not_copied_onto_every_alert_row(
        self, db, pro_user, monkeypatch
    ):
        """A credential scattered across a table nobody thinks of as holding
        one is a credential that leaks out of a support query."""
        from app.services.alert_service import send_new_match_digest
        from app.services.discord_service import DeliveryResult

        async def fake_post(url, payload, **kwargs):
            return DeliveryResult(ok=True, status=204)

        monkeypatch.setattr("app.services.alert_service.post_webhook", fake_post)

        target, outcome = await self._scanned_project(db, pro_user, webhook=VALID)
        await send_new_match_digest(db, pro_user, target, outcome.new_matches)

        alerts = (await db.scalars(select(Alert).where(Alert.user_id == pro_user.id))).all()
        for alert in alerts:
            assert "abcdefghijklmnopqrstuvwxyz012345" not in alert.destination

    async def test_a_free_project_never_posts_even_with_a_url_saved(self, db, user, monkeypatch):
        """Tier is checked at send time, not only when the URL is saved, so a
        lapsed subscription stops the posts without anybody clearing a field."""
        from app.services.alert_service import send_new_match_digest
        from app.services.discord_service import DeliveryResult

        called = False

        async def fake_post(url, payload, **kwargs):
            nonlocal called
            called = True
            return DeliveryResult(ok=True, status=204)

        monkeypatch.setattr("app.services.alert_service.post_webhook", fake_post)

        target, outcome = await self._scanned_project(db, user, webhook=VALID)
        assert await send_new_match_digest(db, user, target, outcome.new_matches) == 1

        assert called is False, "a free-tier project posted to Discord"
        alerts = (await db.scalars(select(Alert).where(Alert.user_id == user.id))).all()
        assert [alert.channel for alert in alerts] == ["email"]

    async def test_a_broken_webhook_does_not_stop_the_email(self, db, pro_user, monkeypatch):
        from app.services.alert_service import send_new_match_digest
        from app.services.discord_service import DeliveryResult

        async def fake_post(url, payload, **kwargs):
            return DeliveryResult(ok=False, status=404, error="Gone.", permanent=True)

        monkeypatch.setattr("app.services.alert_service.post_webhook", fake_post)

        target, outcome = await self._scanned_project(db, pro_user, webhook=VALID)
        # Still 1: the user was told, by email.
        assert await send_new_match_digest(db, pro_user, target, outcome.new_matches) == 1

        await db.commit()
        await db.refresh(target)
        assert target.discord_last_error == "Gone."

        alerts = (await db.scalars(select(Alert).where(Alert.user_id == pro_user.id))).all()
        by_channel = {alert.channel: alert.status for alert in alerts}
        assert by_channel == {"email": "sent", "discord": "failed"}

        # And the finding is marked notified, so the next scan does not re-email
        # somebody who already got the message.
        assert all(match.notified_at is not None for match in outcome.new_matches)

    async def test_discord_alone_is_enough_to_count_as_told(self, db, pro_user, monkeypatch):
        """Email off, webhook on. The finding was delivered; it must not be
        retried forever as though nobody heard."""
        from app.mail import EmailError
        from app.services.alert_service import send_new_match_digest
        from app.services.discord_service import DeliveryResult

        async def fake_post(url, payload, **kwargs):
            return DeliveryResult(ok=True, status=204)

        async def broken_email(*args, **kwargs):
            raise EmailError("the relay is down")

        monkeypatch.setattr("app.services.alert_service.post_webhook", fake_post)
        monkeypatch.setattr("app.services.alert_service.send_email", broken_email)

        target, outcome = await self._scanned_project(db, pro_user, webhook=VALID)
        assert await send_new_match_digest(db, pro_user, target, outcome.new_matches) == 1

        assert all(match.notified_at is not None for match in outcome.new_matches)

    async def test_both_channels_failing_leaves_it_unnotified(self, db, pro_user, monkeypatch):
        """Nobody heard, so the next scan tries again rather than dropping it."""
        from app.mail import EmailError
        from app.services.alert_service import send_new_match_digest
        from app.services.discord_service import DeliveryResult

        async def fake_post(url, payload, **kwargs):
            return DeliveryResult(ok=False, error="Discord is down.")

        async def broken_email(*args, **kwargs):
            raise EmailError("the relay is down")

        monkeypatch.setattr("app.services.alert_service.post_webhook", fake_post)
        monkeypatch.setattr("app.services.alert_service.send_email", broken_email)

        target, outcome = await self._scanned_project(db, pro_user, webhook=VALID)
        assert await send_new_match_digest(db, pro_user, target, outcome.new_matches) == 0
        assert all(match.notified_at is None for match in outcome.new_matches)

    async def test_a_project_with_no_webhook_posts_nothing(self, db, pro_user, monkeypatch):
        from app.services.alert_service import send_new_match_digest
        from app.services.discord_service import DeliveryResult

        called = False

        async def fake_post(url, payload, **kwargs):
            nonlocal called
            called = True
            return DeliveryResult(ok=True)

        monkeypatch.setattr("app.services.alert_service.post_webhook", fake_post)

        target, outcome = await self._scanned_project(db, pro_user, webhook=None)
        await send_new_match_digest(db, pro_user, target, outcome.new_matches)
        assert called is False


class TestDelivery:
    async def test_a_deleted_webhook_is_reported_as_permanent(self):
        """Distinct from a transient failure, because it needs the user to act."""
        from app.services.discord_service import post_webhook

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"message": "Unknown Webhook", "code": 10015})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await post_webhook(VALID, {"content": "hi"}, client=client)

        assert result.ok is False
        assert result.permanent is True
        assert "no longer exists" in result.error

    async def test_rate_limiting_is_transient_and_carries_the_delay(self):
        from app.services.discord_service import post_webhook

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, json={"retry_after": 4.5})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await post_webhook(VALID, {"content": "hi"}, client=client)

        assert result.ok is False
        assert result.permanent is False
        assert result.retry_after == 4.5

    async def test_a_204_is_success(self):
        from app.services.discord_service import post_webhook

        async def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["content-type"] == "application/json"
            return httpx.Response(204)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await post_webhook(VALID, {"content": "hi"}, client=client)

        assert result.ok is True

    async def test_a_stored_url_is_revalidated_before_the_request(self):
        """The value has been through a database since the form checked it."""
        from app.services.discord_service import post_webhook

        reached = False

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal reached
            reached = True
            return httpx.Response(204)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await post_webhook("https://evil.example/steal", {}, client=client)

        assert result.ok is False
        assert reached is False, "an invalid stored URL was still requested"

    async def test_a_timeout_is_not_an_exception_at_the_caller(self):
        """A webhook that hangs must not take down the scan that produced the
        finding, nor the email carrying the same news."""
        from app.services.discord_service import post_webhook

        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("too slow", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await post_webhook(VALID, {"content": "hi"}, client=client)

        assert result.ok is False
        assert "in time" in result.error

    async def test_the_error_never_contains_the_webhook_url(self):
        """It is a credential, and this string is stored and shown on a page."""
        from app.services.discord_service import post_webhook

        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("nope", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await post_webhook(VALID, {"content": "hi"}, client=client)

        assert "abcdefghijklmnopqrstuvwxyz012345" not in (result.error or "")


class TestCustomEndpoints:
    """The other kind, where an allowlist is not available.

    A custom endpoint is somebody else's server, so the host cannot be known in
    advance and the guard has to be a deny-list of where a request must never
    go. That is a weaker control than the Discord allowlist, which is exactly
    why it gets its own tests.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com/hook",
            "https://127.0.0.1/hook",
            "https://10.0.0.5/hook",
            "https://192.168.1.1/hook",
            "https://172.16.0.1/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://0.0.0.0/hook",
            "https://example.com:8080/hook",
            "https://user:pass@example.com/hook",
            "https://example.com/hook\nX-Injected: 1",
            "",
        ],
    )
    def test_internal_and_malformed_destinations_are_refused(self, url):
        from app.core.webhooks import InvalidWebhookURL, validate_custom_url

        with pytest.raises(InvalidWebhookURL):
            validate_custom_url(url, resolve=False)

    def test_the_metadata_address_is_named_as_private(self):
        """169.254.169.254 is the one an SSRF is usually aiming at."""
        from app.core.webhooks import InvalidWebhookURL, validate_custom_url

        with pytest.raises(InvalidWebhookURL) as caught:
            validate_custom_url("https://169.254.169.254/latest/", resolve=False)
        assert "private network" in str(caught.value)

    def test_a_public_https_endpoint_is_allowed(self):
        from app.core.webhooks import validate_custom_url

        target = validate_custom_url("https://hooks.example.com/a/b", resolve=False)
        assert target.host == "hooks.example.com"

    def test_the_custom_payload_is_flat_json(self):
        from app.core.discord import DigestFinding
        from app.core.webhooks import build_custom_payload

        payload = build_custom_payload(
            project="acme",
            findings=[
                DigestFinding(
                    package="lodash",
                    version="4.17.15",
                    cve="CVE-2021-23337",
                    severity="critical",
                    exploited=True,
                    fixed_version="4.17.21",
                )
            ],
            dashboard_url="https://weedout.dev/targets/1",
        )
        assert payload["event"] == "findings.new"
        assert payload["counts"] == {"total": 1, "exploited": 1, "critical": 1, "high": 0}
        assert payload["findings"][0]["fixed_in"] == "4.17.21"
        # No Discord shapes leaking into a body somebody else has to parse.
        assert "embeds" not in payload

    def test_describe_url_hides_the_query_string(self):
        """Which is where people put tokens."""
        from app.core.webhooks import describe_url

        assert "secret" not in describe_url("https://hooks.example.com/a?token=secret")

    async def test_a_custom_endpoint_gets_json_not_an_embed(self, db, pro_user, monkeypatch):
        from app.services.alert_service import send_new_match_digest
        from app.services.discord_service import DeliveryResult

        seen = {}

        async def fake_post(url, payload, **kwargs):
            seen["payload"] = payload
            seen["kind"] = kwargs.get("kind")
            return DeliveryResult(ok=True, status=200)

        monkeypatch.setattr("app.services.alert_service.post_webhook", fake_post)

        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import LODASH_ADVISORY, make_target, seed_mirror

        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, pro_user)
        target.discord_webhook_url = "https://hooks.example.com/weedout"
        target.webhook_kind = "custom"
        outcome = await scan_target(db, target)

        await send_new_match_digest(db, pro_user, target, outcome.new_matches)

        assert seen["kind"] == "custom"
        assert seen["payload"]["source"] == "weedout"
        assert "embeds" not in seen["payload"]

    async def test_the_alert_row_records_which_kind(self, db, pro_user, monkeypatch):
        from app.services.alert_service import send_new_match_digest
        from app.services.discord_service import DeliveryResult

        async def fake_post(url, payload, **kwargs):
            return DeliveryResult(ok=True, status=200)

        monkeypatch.setattr("app.services.alert_service.post_webhook", fake_post)

        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import LODASH_ADVISORY, make_target, seed_mirror

        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, pro_user)
        target.discord_webhook_url = "https://hooks.example.com/weedout"
        target.webhook_kind = "custom"
        outcome = await scan_target(db, target)

        await send_new_match_digest(db, pro_user, target, outcome.new_matches)

        alerts = (await db.scalars(select(Alert).where(Alert.user_id == pro_user.id))).all()
        assert sorted(a.channel for a in alerts) == ["custom", "email"]
        for alert in alerts:
            assert "hooks.example.com" not in alert.destination
