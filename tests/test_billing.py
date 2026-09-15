"""Security and compatibility tests for legacy payment webhooks.

Subscriptions no longer control product access. The signed endpoint remains so
historical invoice, refund, and dispute data can be reconciled by admins.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from app.config import get_settings
from app.core.types import Tier
from app.routes.billing import _handle_subscription_event
from app.security import verify_dodo_signature

SECRET = "whsec_" + base64.b64encode(b"dodo-test-signing-key-0123456789").decode()
WEBHOOK_ID = "msg_2abcDEF"


def sign(
    body: bytes,
    secret: str = SECRET,
    webhook_id: str = WEBHOOK_ID,
    timestamp: int | None = None,
) -> tuple[str, str, str]:
    ts = str(timestamp if timestamp is not None else int(time.time()))
    key = base64.b64decode(secret.removeprefix("whsec_"))
    signed = b".".join([webhook_id.encode(), ts.encode(), body])
    digest = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return webhook_id, ts, f"v1,{digest}"


def check(body: bytes, **overrides) -> bool:
    webhook_id, timestamp, signature = sign(body)
    return verify_dodo_signature(
        raw_body=overrides.get("raw_body", body),
        webhook_id=overrides.get("webhook_id", webhook_id),
        webhook_timestamp=overrides.get("webhook_timestamp", timestamp),
        signature_header=overrides.get("signature_header", signature),
        secret=overrides.get("secret", SECRET),
    )


class TestVerifyDodoSignature:
    def test_valid_signature_is_accepted(self):
        assert check(b'{"type":"subscription.active"}') is True

    def test_tampered_body_is_rejected(self):
        assert check(b'{"type":"subscription.active"}', raw_body=b'{"type":"hacked"}') is False

    def test_wrong_secret_and_webhook_id_are_rejected(self):
        body = b"{}"
        other = "whsec_" + base64.b64encode(b"another-key").decode()
        _, timestamp, signature = sign(body, secret=other)
        assert not verify_dodo_signature(
            raw_body=body,
            webhook_id=WEBHOOK_ID,
            webhook_timestamp=timestamp,
            signature_header=signature,
            secret=SECRET,
        )
        assert check(body, webhook_id="msg_different") is False

    @pytest.mark.parametrize(
        "overrides",
        [
            {"signature_header": None},
            {"webhook_id": None},
            {"webhook_timestamp": None},
            {"secret": ""},
            {"signature_header": "garbage"},
            {"webhook_timestamp": "not-a-number"},
        ],
    )
    def test_missing_and_malformed_inputs_are_rejected(self, overrides):
        assert check(b"{}", **overrides) is False

    @pytest.mark.parametrize("offset", [-3600, 3600])
    def test_replayed_or_future_requests_are_rejected(self, offset):
        body = b"{}"
        webhook_id, timestamp, signature = sign(body, timestamp=int(time.time()) + offset)
        assert not verify_dodo_signature(
            raw_body=body,
            webhook_id=webhook_id,
            webhook_timestamp=timestamp,
            signature_header=signature,
            secret=SECRET,
        )

    def test_recent_request_and_rotated_signature_are_accepted(self):
        body = b"{}"
        webhook_id, timestamp, signature = sign(body, timestamp=int(time.time()) - 60)
        assert verify_dodo_signature(
            raw_body=body,
            webhook_id=webhook_id,
            webhook_timestamp=timestamp,
            signature_header=f"v1,deadbeef {signature}",
            secret=SECRET,
        )


@pytest.fixture
def billing_on(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "dodo_enabled", True)
    monkeypatch.setattr(settings, "dodo_webhook_secret", SECRET)
    return settings


async def post_signed(client, payload: dict, *, secret: str = SECRET):
    body = json.dumps(payload, separators=(",", ":")).encode()
    webhook_id, timestamp, signature = sign(body, secret=secret)
    return await client.post(
        "/webhooks/dodo",
        content=body,
        headers={
            "content-type": "application/json",
            "webhook-id": webhook_id,
            "webhook-timestamp": timestamp,
            "webhook-signature": signature,
        },
    )


class TestWebhookRoute:
    async def test_disabled_endpoint_is_not_exposed(self, client):
        response = await client.post("/webhooks/dodo", json={"type": "subscription.active"})
        assert response.status_code == 404

    async def test_valid_signature_is_accepted(self, client, billing_on):
        response = await post_signed(
            client,
            {"type": "subscription.active", "data": {"subscription_id": "sub_unknown"}},
        )
        assert response.status_code == 200

    async def test_unsigned_forged_and_tampered_requests_are_rejected(self, client, billing_on):
        unsigned = await client.post(
            "/webhooks/dodo",
            content=b"{}",
            headers={"content-type": "application/json"},
        )
        forged = await post_signed(
            client,
            {"type": "subscription.active", "data": {}},
            secret="whsec_" + base64.b64encode(b"wrong-secret").decode(),
        )

        signed_body = b'{"type":"subscription.active","data":{}}'
        webhook_id, timestamp, signature = sign(signed_body)
        tampered = await client.post(
            "/webhooks/dodo",
            content=b'{"type":"subscription.active","data":{"status":"active"}}',
            headers={
                "content-type": "application/json",
                "webhook-id": webhook_id,
                "webhook-timestamp": timestamp,
                "webhook-signature": signature,
            },
        )

        assert unsigned.status_code == forged.status_code == tampered.status_code == 401
        assert "secret" not in forged.text.lower()

    async def test_signed_payment_cannot_recreate_pro(self, client, db, user, billing_on):
        user.tier = Tier.PRO
        await db.commit()

        response = await post_signed(
            client,
            {
                "type": "subscription.active",
                "data": {
                    "subscription_id": "sub_legacy",
                    "status": "active",
                    "reference_id": str(user.id),
                    "product_id": "pdt_retired",
                },
            },
        )

        assert response.status_code == 200
        await db.refresh(user)
        assert user.tier is Tier.FREE
        assert user.subscription_status == "active"
        assert user.dodo_subscription_id == "sub_legacy"


class TestLegacySubscriptionMapping:
    @pytest.mark.parametrize("status", ["active", "trialing", "on_hold", "cancelled", "expired"])
    async def test_every_known_state_has_free_entitlement(self, db, user, status):
        user.tier = Tier.PRO
        handled = await _handle_subscription_event(
            db,
            f"subscription.{status}",
            {"reference_id": str(user.id), "status": status, "subscription_id": "sub_old"},
        )
        assert handled is True
        assert user.tier is Tier.FREE

    async def test_unknown_state_is_recorded_without_granting_access(self, db, user):
        handled = await _handle_subscription_event(
            db,
            "subscription.changed",
            {"reference_id": str(user.id), "status": "new-provider-state"},
        )
        assert handled is True
        assert user.subscription_status == "new-provider-state"
        assert user.tier is Tier.FREE

    async def test_price_and_customer_metadata_are_retained_for_admin_reconciliation(
        self, db, user
    ):
        await _handle_subscription_event(
            db,
            "subscription.active",
            {
                "reference_id": str(user.id),
                "status": "active",
                "subscription_id": "sub_history",
                "customer": {"customer_id": "cus_history"},
                "recurring_pre_tax_amount": 12000,
                "payment_frequency_interval": "Year",
                "currency": "usd",
            },
        )
        assert user.dodo_customer_id == "cus_history"
        assert user.subscription_amount_cents == 12000
        assert user.subscription_interval == "year"
        assert user.subscription_currency == "USD"


class TestConfiguration:
    def test_legacy_webhook_needs_only_a_secret(self):
        settings = get_settings()
        assert not hasattr(settings, "dodo_api_key")
        assert not hasattr(settings, "dodo_product_id_pro_monthly")
