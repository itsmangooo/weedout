"""Dodo Payments webhook handling and signature verification.



The webhook is the only thing that grants paid access, so a forged or replayed

request must never move a user to Pro. Signature verification follows the

Standard Webhooks spec, which Dodo implements.

"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from app.core.types import Tier
from app.security import verify_dodo_signature

SECRET = "whsec_" + base64.b64encode(b"dodo-test-signing-key-0123456789").decode()

WEBHOOK_ID = "msg_2abcDEF"


def sign(
    body: bytes,
    secret: str = SECRET,
    webhook_id: str = WEBHOOK_ID,
    timestamp: int | None = None,
) -> tuple[str, str, str]:
    """Produce the three Standard Webhooks headers for a body."""

    ts = str(timestamp if timestamp is not None else int(time.time()))

    key = base64.b64decode(secret.removeprefix("whsec_"))

    signed = b".".join([webhook_id.encode(), ts.encode(), body])

    digest = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()

    return webhook_id, ts, f"v1,{digest}"


def check(body: bytes, **overrides) -> bool:

    webhook_id, ts, signature = sign(body)

    return verify_dodo_signature(
        raw_body=overrides.get("raw_body", body),
        webhook_id=overrides.get("webhook_id", webhook_id),
        webhook_timestamp=overrides.get("webhook_timestamp", ts),
        signature_header=overrides.get("signature_header", signature),
        secret=overrides.get("secret", SECRET),
    )


class TestVerifyDodoSignature:
    def test_valid_signature_is_accepted(self):

        assert check(b'{"type":"subscription.active"}') is True

    def test_tampered_body_is_rejected(self):

        assert check(b'{"type":"subscription.active"}', raw_body=b'{"type":"hacked"}') is False

    def test_wrong_secret_is_rejected(self):

        body = b"{}"

        _, ts, signature = sign(body, secret="whsec_" + base64.b64encode(b"another-key").decode())

        assert (
            verify_dodo_signature(
                raw_body=body,
                webhook_id=WEBHOOK_ID,
                webhook_timestamp=ts,
                signature_header=signature,
                secret=SECRET,
            )
            is False
        )

    def test_a_different_webhook_id_is_rejected(self):

        # The id is part of the signed content, so swapping it must invalidate

        # the signature — otherwise one captured body could be replayed under a

        # fresh id to dodge idempotency.

        assert check(b"{}", webhook_id="msg_somethingelse") is False

    def test_missing_headers_are_rejected(self):

        body = b"{}"

        assert check(body, signature_header=None) is False

        assert check(body, webhook_id=None) is False

        assert check(body, webhook_timestamp=None) is False

    def test_missing_secret_is_rejected(self):

        assert check(b"{}", secret="") is False

    @pytest.mark.parametrize("header", ["garbage", "v1", "v1,", ",abc", "v2,abc", "", "abc"])
    def test_malformed_signature_headers_are_rejected(self, header):

        assert check(b"{}", signature_header=header) is False

    @pytest.mark.parametrize("timestamp", ["not-a-number", "", "12.5"])
    def test_malformed_timestamps_are_rejected(self, timestamp):

        assert check(b"{}", webhook_timestamp=timestamp) is False

    def test_old_timestamp_is_rejected(self):

        # Without this, a captured webhook could be replayed forever to keep

        # resetting a cancelled subscription back to active.

        body = b"{}"

        webhook_id, ts, signature = sign(body, timestamp=int(time.time()) - 3600)

        assert (
            verify_dodo_signature(
                raw_body=body,
                webhook_id=webhook_id,
                webhook_timestamp=ts,
                signature_header=signature,
                secret=SECRET,
            )
            is False
        )

    def test_future_timestamp_beyond_tolerance_is_rejected(self):

        body = b"{}"

        webhook_id, ts, signature = sign(body, timestamp=int(time.time()) + 3600)

        assert (
            verify_dodo_signature(
                raw_body=body,
                webhook_id=webhook_id,
                webhook_timestamp=ts,
                signature_header=signature,
                secret=SECRET,
            )
            is False
        )

    def test_recent_timestamp_is_accepted(self):

        body = b"{}"

        webhook_id, ts, signature = sign(body, timestamp=int(time.time()) - 60)

        assert (
            verify_dodo_signature(
                raw_body=body,
                webhook_id=webhook_id,
                webhook_timestamp=ts,
                signature_header=signature,
                secret=SECRET,
            )
            is True
        )

    def test_multiple_signatures_accepts_any_match(self):

        # Sent during secret rotation.

        body = b"{}"

        _, _, good = sign(body)

        assert check(body, signature_header=f"v1,deadbeef {good}") is True

    def test_secret_without_the_whsec_prefix_works(self):

        raw = base64.b64encode(b"dodo-test-signing-key-0123456789").decode()

        body = b"{}"

        _, ts, signature = sign(body, secret=raw)

        assert (
            verify_dodo_signature(
                raw_body=body,
                webhook_id=WEBHOOK_ID,
                webhook_timestamp=ts,
                signature_header=signature,
                secret=raw,
            )
            is True
        )

    def test_byte_exact_body_matters(self):

        # Re-serialising parsed JSON changes whitespace and key order, which is

        # why the handler must sign over the raw request body.

        original = b'{"a": 1, "b": 2}'

        reserialised = json.dumps(json.loads(original), separators=(",", ":")).encode()

        assert check(original, raw_body=reserialised) is False


class TestDodoWebhookRoute:
    async def test_webhook_is_404_when_billing_is_off(self, client):

        response = await client.post("/webhooks/dodo", json={"type": "subscription.active"})

        assert response.status_code == 404


class TestSubscriptionStateMapping:
    """The status → tier mapping, exercised through the handler directly."""

    async def _handle(self, db, data, event_type="subscription.updated"):

        from app.routes import billing

        return await billing._handle_subscription_event(db, event_type, data)

    def _payload(self, user, status, **extra):

        return {
            "subscription_id": "sub_1",
            "status": status,
            "reference_id": str(user.id),
            **extra,
        }

    @pytest.mark.parametrize("status", ["active", "trialing", "on_hold"])
    async def test_paying_statuses_grant_pro(self, db, user, status):

        await self._handle(db, self._payload(user, status))

        assert user.tier is Tier.PRO

    @pytest.mark.parametrize("status", ["cancelled", "expired", "failed", "paused"])
    async def test_ended_statuses_drop_to_free(self, db, user, status):

        user.tier = Tier.PRO

        await self._handle(db, self._payload(user, status))

        assert user.tier is Tier.FREE

    async def test_on_hold_keeps_access_during_dunning(self, db, user):

        # Locking someone out while their bank retries loses a customer who was

        # about to pay.

        user.tier = Tier.PRO

        await self._handle(db, self._payload(user, "on_hold"))

        assert user.tier is Tier.PRO

    async def test_an_unknown_status_does_not_revoke_access(self, db, user):

        # A status Dodo adds later must not silently cancel paying customers.

        user.tier = Tier.PRO

        await self._handle(db, self._payload(user, "some_new_state"))

        assert user.tier is Tier.PRO

        assert user.subscription_status == "some_new_state"

    async def test_identifiers_are_recorded(self, db, user):

        await self._handle(
            db,
            self._payload(
                user,
                "active",
                customer={"customer_id": "cus_xyz", "email": user.email},
                product_id="pdt_pro",
            ),
        )

        assert user.dodo_subscription_id == "sub_1"

        assert user.dodo_customer_id == "cus_xyz"

        assert user.dodo_product_id == "pdt_pro"

    async def test_user_is_found_by_metadata_when_reference_is_absent(self, db, user):

        assert await self._handle(
            db,
            {
                "subscription_id": "sub_1",
                "status": "active",
                "metadata": {"user_id": str(user.id)},
            },
        )

        assert user.tier is Tier.PRO

    async def test_user_is_found_by_stored_customer_id(self, db, user):

        user.dodo_customer_id = "cus_known"

        await db.flush()

        assert await self._handle(
            db,
            {
                "subscription_id": "sub_1",
                "status": "active",
                "customer": {"customer_id": "cus_known"},
            },
        )

        assert user.tier is Tier.PRO

    async def test_user_is_found_by_email(self, db, user):

        assert await self._handle(
            db,
            {
                "subscription_id": "sub_1",
                "status": "active",
                "customer": {"email": user.email.upper()},
            },
        )

        assert user.tier is Tier.PRO

    async def test_unknown_subscription_is_reported_not_crashed(self, db):

        assert (
            await self._handle(db, {"subscription_id": "sub_nobody", "status": "active"}) is False
        )

    async def test_cancellation_with_a_future_end_date_keeps_access(self, db, user):

        from datetime import UTC, datetime, timedelta

        user.tier = Tier.PRO

        future = (datetime.now(UTC) + timedelta(days=20)).isoformat()

        await self._handle(db, self._payload(user, "cancelled", next_billing_date=future))

        # Time already paid for is honoured; the expiry job downgrades later.

        assert user.tier is Tier.PRO

        assert user.subscription_ends_at is not None

    async def test_cancellation_with_no_end_date_downgrades_immediately(self, db, user):

        user.tier = Tier.PRO

        await self._handle(db, self._payload(user, "cancelled"))

        assert user.tier is Tier.FREE


class TestSubscriptionPriceCapture:
    """The amount fields the admin revenue snapshot sums."""

    async def _handle(self, db, data):

        from app.routes import billing

        return await billing._handle_subscription_event(db, "subscription.active", data)

    def _payload(self, user, **extra):

        return {
            "subscription_id": "sub_1",
            "status": "active",
            "reference_id": str(user.id),
            "currency": "USD",
            "payment_frequency_interval": "Month",
            "payment_frequency_count": 1,
            **extra,
        }

    async def test_captures_amount_currency_and_interval(self, db, user):

        await self._handle(db, self._payload(user, recurring_pre_tax_amount=1200))

        assert user.subscription_amount_cents == 1200

        assert user.subscription_currency == "USD"

        assert user.subscription_interval == "month"

        assert user.monthly_value_cents == 1200

    async def test_annual_plans_normalise_to_a_monthly_value(self, db, user):

        await self._handle(
            db,
            self._payload(user, recurring_pre_tax_amount=12000, payment_frequency_interval="Year"),
        )

        assert user.subscription_amount_cents == 12000

        assert user.monthly_value_cents == 1000

    async def test_a_multi_period_cadence_is_folded_into_the_interval(self, db, user):

        # Billed 3600 every 3 months is 1200/month, not 3600/month.

        await self._handle(
            db,
            self._payload(user, recurring_pre_tax_amount=3600, payment_frequency_count=3),
        )

        assert user.subscription_amount_cents == 1200

        assert user.monthly_value_cents == 1200

    async def test_falls_back_to_the_product_cart(self, db, user):

        await self._handle(
            db, self._payload(user, product_cart=[{"product_id": "pdt", "amount": 900}])
        )

        assert user.subscription_amount_cents == 900

    @pytest.mark.parametrize(
        "extra",
        [
            {},
            {"recurring_pre_tax_amount": None},
            {"recurring_pre_tax_amount": "not-a-number"},
            {"recurring_pre_tax_amount": -500},
            {"product_cart": "not-a-list"},
            {"product_cart": []},
        ],
    )
    async def test_unrecognised_shapes_leave_stored_values_untouched(self, db, user, extra):

        # A parsing miss must not zero the amount — MRR silently dropping to

        # zero is worse than MRR being briefly stale.

        user.subscription_amount_cents = 1200

        user.subscription_currency = "USD"

        await db.flush()

        await self._handle(db, self._payload(user, **extra))

        assert user.subscription_amount_cents == 1200

        assert user.subscription_currency == "USD"


class TestCheckoutUrl:
    def test_returns_none_when_billing_is_disabled(self, user):

        from app.config import get_settings
        from app.routes.billing import build_checkout_url

        assert build_checkout_url(get_settings(), user) is None

    def test_builds_a_test_mode_url_with_the_account_reference(self, user, monkeypatch):

        from app.config import get_settings
        from app.routes.billing import build_checkout_url

        settings = get_settings()

        monkeypatch.setattr(settings, "dodo_enabled", True)

        monkeypatch.setattr(settings, "dodo_product_id_pro_monthly", "pdt_pro")

        monkeypatch.setattr(settings, "dodo_environment", "test")

        url = build_checkout_url(settings, user)

        assert url.startswith("https://test.checkout.dodopayments.com/buy/pdt_pro?")

        # The reference is how a payment is tied back to an account even when

        # the customer pays with a different email.

        assert f"reference_id={user.id}" in url

    def test_live_mode_uses_the_production_host(self, user, monkeypatch):

        from app.config import get_settings
        from app.routes.billing import build_checkout_url

        settings = get_settings()

        monkeypatch.setattr(settings, "dodo_enabled", True)

        monkeypatch.setattr(settings, "dodo_product_id_pro_monthly", "pdt_pro")

        monkeypatch.setattr(settings, "dodo_environment", "live")

        assert build_checkout_url(settings, user).startswith(
            "https://checkout.dodopayments.com/buy/pdt_pro?"
        )


class TestFailFastConfiguration:
    """Billing enabled with a missing credential must not boot."""

    @pytest.mark.parametrize(
        "missing", ["dodo_api_key", "dodo_webhook_secret", "dodo_product_id_pro_monthly"]
    )
    def test_enabling_dodo_requires_every_credential(self, missing):

        from pydantic import ValidationError

        from app.config import Settings

        values = {
            "secret_key": "x" * 40,
            "database_url": "postgresql+psycopg://u:p@localhost:5432/db",
            "dodo_enabled": True,
            "dodo_api_key": "key",
            "dodo_webhook_secret": "whsec_abc",
            "dodo_product_id_pro_monthly": "pdt_pro",
        }

        values[missing] = None

        with pytest.raises(ValidationError, match="DODO_ENABLED"):
            Settings(**values)

    def test_disabled_billing_needs_no_credentials(self):

        from app.config import Settings

        settings = Settings(
            secret_key="x" * 40,
            database_url="postgresql+psycopg://u:p@localhost:5432/db",
            dodo_enabled=False,
        )

        assert settings.dodo_enabled is False


class TestExpireSubscriptionsJob:
    async def test_downgrades_users_whose_paid_period_ended(self, db, user, monkeypatch):

        from contextlib import asynccontextmanager
        from datetime import timedelta

        from app.jobs import tasks
        from app.models import utcnow

        user.tier = Tier.PRO

        user.subscription_status = "cancelled"

        user.subscription_ends_at = utcnow() - timedelta(days=1)

        await db.flush()

        @asynccontextmanager
        async def fake_scope():

            yield db

        monkeypatch.setattr(tasks, "session_scope", fake_scope)

        assert await tasks.expire_subscriptions_task() == 1

        assert user.tier is Tier.FREE

    async def test_leaves_paying_subscribers_alone(self, db, user, monkeypatch):

        from contextlib import asynccontextmanager
        from datetime import timedelta

        from app.jobs import tasks
        from app.models import utcnow

        user.tier = Tier.PRO

        # Dunning: the billing date has passed but retries are in progress.

        user.subscription_status = "on_hold"

        user.subscription_ends_at = utcnow() - timedelta(days=1)

        await db.flush()

        @asynccontextmanager
        async def fake_scope():

            yield db

        monkeypatch.setattr(tasks, "session_scope", fake_scope)

        assert await tasks.expire_subscriptions_task() == 0

        assert user.tier is Tier.PRO
