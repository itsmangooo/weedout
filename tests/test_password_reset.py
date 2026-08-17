"""Forgotten-password reset.

Two properties carry this feature, and both are the kind that fail silently:

* **A token is usable exactly once, and only for an hour.** Expiry and reuse
  are tested from both the service and the HTTP route, because a token that
  survives its own use is an account takeover with a long tail.
* **The flow leaks nothing.** Every response on the request step must be
  byte-identical whether or not the address is registered.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import PasswordResetToken, Session, utcnow
from app.security import hash_reset_token, verify_password
from app.services.auth_service import (
    InvalidCredentials,
    WeakPassword,
    authenticate,
    create_session,
    session_user,
)
from app.services.password_reset_service import (
    InvalidResetToken,
    complete_password_reset,
    purge_expired_reset_tokens,
    request_password_reset,
    validate_reset_token,
)
from tests.conftest import set_csrf

PASSWORD = "correct-horse-battery"
NEW_PASSWORD = "a-brand-new-password"


async def issue_token(db, user, **overrides) -> tuple[str, PasswordResetToken]:
    """Create a reset token directly and return (plaintext, row)."""
    from app.security import generate_reset_token

    token = generate_reset_token()
    record = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_reset_token(token),
        expires_at=utcnow() + timedelta(hours=1),
        **overrides,
    )
    db.add(record)
    await db.flush()
    return token, record


class TestRequestingAReset:
    async def test_creates_a_token_for_a_known_address(self, db, user):
        await request_password_reset(db, user.email)
        record = await db.scalar(
            select(PasswordResetToken).where(PasswordResetToken.user_id == user.id)
        )
        assert record is not None
        assert record.is_usable is True

    async def test_only_the_hash_is_stored(self, db, user, monkeypatch):
        captured: dict[str, str] = {}

        async def fake_send(to, subject, text, html=None, settings=None):
            captured["text"] = text

        monkeypatch.setattr("app.services.password_reset_service.send_email", fake_send)

        await request_password_reset(db, user.email)
        record = await db.scalar(select(PasswordResetToken))

        raw = captured["text"].split("token=")[1].split()[0]
        assert record.token_hash != raw
        assert record.token_hash == hash_reset_token(raw)

    async def test_email_normalisation_matches_stored_addresses(self, db, user):
        await request_password_reset(db, "  DEV@EXAMPLE.COM  ")
        assert await db.scalar(select(PasswordResetToken)) is not None

    async def test_unknown_address_creates_nothing_and_does_not_raise(self, db):
        await request_password_reset(db, "nobody@example.com")
        assert (await db.scalars(select(PasswordResetToken))).all() == []

    async def test_suspended_accounts_cannot_be_reset(self, db, user):
        # Otherwise a reset hands back an account an admin deliberately closed.
        user.is_suspended = True
        await db.flush()

        await request_password_reset(db, user.email)
        assert (await db.scalars(select(PasswordResetToken))).all() == []

    async def test_deactivated_accounts_cannot_be_reset(self, db, user):
        user.is_active = False
        await db.flush()

        await request_password_reset(db, user.email)
        assert (await db.scalars(select(PasswordResetToken))).all() == []

    async def test_requests_are_throttled_per_account(self, db, user):
        from app.config import get_settings

        limit = get_settings().password_reset_max_per_hour
        for _ in range(limit):
            await request_password_reset(db, user.email)

        assert len((await db.scalars(select(PasswordResetToken))).all()) == limit

        # Beyond the cap, nothing more is created — the endpoint is otherwise a
        # free mailbox-flooding tool aimed at any known address.
        await request_password_reset(db, user.email)
        assert len((await db.scalars(select(PasswordResetToken))).all()) == limit

    async def test_a_mail_failure_leaves_the_token_valid(self, db, user, monkeypatch):
        from app.mail import EmailError

        async def boom(**kwargs):
            raise EmailError("smtp down")

        monkeypatch.setattr("app.services.password_reset_service.send_email", boom)

        await request_password_reset(db, user.email)
        record = await db.scalar(select(PasswordResetToken))
        assert record is not None and record.is_usable


class TestTokenValidation:
    async def test_a_fresh_token_validates(self, db, user):
        token, _ = await issue_token(db, user)
        assert (await validate_reset_token(db, token)) is not None

    async def test_an_unknown_token_does_not_validate(self, db, user):
        await issue_token(db, user)
        assert await validate_reset_token(db, "not-a-real-token") is None
        assert await validate_reset_token(db, "") is None

    async def test_an_expired_token_does_not_validate(self, db, user):
        token, record = await issue_token(db, user)
        record.expires_at = utcnow() - timedelta(seconds=1)
        await db.flush()

        assert record.is_expired is True
        assert await validate_reset_token(db, token) is None

    async def test_a_used_token_does_not_validate(self, db, user):
        token, _ = await issue_token(db, user, used_at=utcnow())
        await db.flush()
        assert await validate_reset_token(db, token) is None

    async def test_a_token_for_a_suspended_account_does_not_validate(self, db, user):
        # Suspending someone must invalidate a link already in their inbox.
        token, _ = await issue_token(db, user)
        user.is_suspended = True
        await db.flush()

        assert await validate_reset_token(db, token) is None


class TestCompletingAReset:
    async def test_sets_the_new_password(self, db, user):
        token, _ = await issue_token(db, user)
        await complete_password_reset(db, token, NEW_PASSWORD)

        assert verify_password(NEW_PASSWORD, user.password_hash)
        assert not verify_password(PASSWORD, user.password_hash)

    async def test_the_new_password_actually_works_for_login(self, db, user):
        token, _ = await issue_token(db, user)
        await complete_password_reset(db, token, NEW_PASSWORD)
        await db.flush()

        assert (await authenticate(db, user.email, NEW_PASSWORD)).id == user.id
        with pytest.raises(InvalidCredentials):
            await authenticate(db, user.email, PASSWORD)

    async def test_the_token_is_spent(self, db, user):
        token, record = await issue_token(db, user)
        await complete_password_reset(db, token, NEW_PASSWORD)

        assert record.used_at is not None
        assert record.is_usable is False

    async def test_the_same_token_cannot_be_used_twice(self, db, user):
        token, _ = await issue_token(db, user)
        await complete_password_reset(db, token, NEW_PASSWORD)
        await db.flush()

        with pytest.raises(InvalidResetToken):
            await complete_password_reset(db, token, "yet-another-password")

        # And the first reset stands.
        assert verify_password(NEW_PASSWORD, user.password_hash)

    async def test_other_outstanding_tokens_are_invalidated(self, db, user):
        # Otherwise one forgotten request stays redeemable after the password
        # has already been changed.
        first, first_row = await issue_token(db, user)
        second, _ = await issue_token(db, user)

        await complete_password_reset(db, second, NEW_PASSWORD)
        await db.flush()
        await db.refresh(first_row)

        assert first_row.used_at is not None
        assert await validate_reset_token(db, first) is None

    async def test_every_session_is_revoked(self, db, user):
        # "I forgot my password" and "someone else is in my account" overlap
        # often enough to assume the worse one.
        session_token = await create_session(db, user)
        assert await session_user(db, session_token) is not None

        token, _ = await issue_token(db, user)
        await complete_password_reset(db, token, NEW_PASSWORD)
        await db.flush()

        assert await session_user(db, session_token) is None
        revoked = (await db.scalars(select(Session).where(Session.user_id == user.id))).all()
        assert all(s.revoked_at is not None for s in revoked)

    async def test_an_expired_token_is_rejected(self, db, user):
        token, record = await issue_token(db, user)
        record.expires_at = utcnow() - timedelta(minutes=1)
        await db.flush()

        with pytest.raises(InvalidResetToken):
            await complete_password_reset(db, token, NEW_PASSWORD)
        assert verify_password(PASSWORD, user.password_hash), "password must be untouched"

    async def test_a_weak_password_does_not_burn_the_token(self, db, user):
        token, record = await issue_token(db, user)

        with pytest.raises(WeakPassword):
            await complete_password_reset(db, token, "short")

        assert record.used_at is None
        assert await validate_reset_token(db, token) is not None

    async def test_an_unknown_token_is_rejected(self, db, user):
        with pytest.raises(InvalidResetToken):
            await complete_password_reset(db, "made-up", NEW_PASSWORD)


class TestPurge:
    async def test_removes_long_expired_tokens_only(self, db, user):
        _, old = await issue_token(db, user)
        old.expires_at = utcnow() - timedelta(days=30)
        _, recent = await issue_token(db, user)
        await db.flush()

        assert await purge_expired_reset_tokens(db) == 1
        remaining = (await db.scalars(select(PasswordResetToken))).all()
        assert [r.id for r in remaining] == [recent.id]


class TestResetRoutes:
    async def test_request_page_renders(self, client):
        response = await client.get("/forgot-password")
        assert response.status_code == 200
        assert "Reset your password" in response.text

    async def test_known_and_unknown_addresses_get_identical_responses(self, client, user):
        """The core anti-enumeration property, asserted on the actual bytes."""
        csrf = set_csrf(client)
        known = await client.post(
            "/forgot-password", data={"email": user.email, "csrf_token": csrf}
        )
        csrf = set_csrf(client)
        unknown = await client.post(
            "/forgot-password", data={"email": "nobody@example.com", "csrf_token": csrf}
        )

        assert known.status_code == unknown.status_code == 200
        # The address is echoed back, so compare with it removed.
        assert known.text.replace(user.email, "X") == unknown.text.replace(
            "nobody@example.com", "X"
        )

    async def test_a_suspended_account_gets_the_same_response(self, client, db, user):
        user.is_suspended = True
        await db.flush()

        csrf = set_csrf(client)
        response = await client.post(
            "/forgot-password", data={"email": user.email, "csrf_token": csrf}
        )
        assert response.status_code == 200
        assert "Check your email" in response.text

    async def test_a_malformed_address_gets_the_same_response(self, client):
        # A validation error here would leak that the address format check ran
        # against a real lookup.
        csrf = set_csrf(client)
        response = await client.post(
            "/forgot-password", data={"email": "not-an-email", "csrf_token": csrf}
        )
        assert response.status_code == 200
        assert "Check your email" in response.text

    async def test_request_requires_csrf(self, client, user):
        response = await client.post("/forgot-password", data={"email": user.email})
        assert response.status_code == 403

    async def test_reset_page_renders_for_a_valid_token(self, client, db, user):
        token, _ = await issue_token(db, user)
        response = await client.get(f"/reset-password?token={token}")
        assert response.status_code == 200
        assert "Choose a new password" in response.text

    @pytest.mark.parametrize("bad", ["", "nonsense", "a" * 200])
    async def test_reset_page_rejects_a_bad_token(self, client, bad):
        response = await client.get(f"/reset-password?token={bad}")
        assert response.status_code == 400
        assert "expired" in response.text.lower()

    async def test_reset_page_rejects_an_expired_token(self, client, db, user):
        token, record = await issue_token(db, user)
        record.expires_at = utcnow() - timedelta(seconds=1)
        await db.flush()

        response = await client.get(f"/reset-password?token={token}")
        assert response.status_code == 400

    async def test_full_reset_through_the_routes(self, client, db, user):
        token, _ = await issue_token(db, user)
        csrf = set_csrf(client)

        response = await client.post(
            "/reset-password",
            data={
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 200
        assert "password has been changed" in response.text

        await db.refresh(user)
        assert verify_password(NEW_PASSWORD, user.password_hash)

    async def test_reset_does_not_sign_the_user_in(self, client, db, user):
        # The reset revoked every session; handing out a new one silently would
        # skip proving the new password works.
        token, _ = await issue_token(db, user)
        csrf = set_csrf(client)

        response = await client.post(
            "/reset-password",
            data={
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "csrf_token": csrf,
            },
        )
        assert "weedout_session" not in response.cookies

    async def test_mismatched_confirmation_is_rejected_but_keeps_the_token(self, client, db, user):
        token, record = await issue_token(db, user)
        csrf = set_csrf(client)

        response = await client.post(
            "/reset-password",
            data={
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirm": "something-else-entirely",
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 400
        # Jinja escapes the apostrophe, so match on the unambiguous words.
        assert "passwords" in response.text.lower()
        assert "match" in response.text.lower()

        await db.refresh(record)
        assert record.used_at is None, "a typo must not cost the user their link"
        assert verify_password(PASSWORD, user.password_hash)

    async def test_replaying_the_token_through_the_route_fails(self, client, db, user):
        token, _ = await issue_token(db, user)
        body = {"token": token, "password": NEW_PASSWORD, "password_confirm": NEW_PASSWORD}

        csrf = set_csrf(client)
        first = await client.post("/reset-password", data={**body, "csrf_token": csrf})
        assert first.status_code == 200

        csrf = set_csrf(client)
        second = await client.post(
            "/reset-password",
            data={
                **body,
                "password": "third-password-here",
                "password_confirm": "third-password-here",
                "csrf_token": csrf,
            },
        )
        assert second.status_code == 400
        assert "expired" in second.text.lower()

        await db.refresh(user)
        assert verify_password(NEW_PASSWORD, user.password_hash)

    async def test_reset_requires_csrf(self, client, db, user):
        token, _ = await issue_token(db, user)
        response = await client.post(
            "/reset-password",
            data={"token": token, "password": NEW_PASSWORD, "password_confirm": NEW_PASSWORD},
        )
        assert response.status_code == 403

    async def test_signed_in_users_are_sent_to_settings(self, auth_client):
        response = await auth_client.get("/forgot-password")
        assert response.status_code == 303
        assert response.headers["location"] == "/settings"

    async def test_login_page_links_to_the_reset_flow(self, client):
        response = await client.get("/login")
        assert "/forgot-password" in response.text

    async def test_the_success_banner_renders_exactly_once(self, client, db, user):
        # Every page renders its own notice; a generic copy in the base layout
        # used to render each of them twice.
        token, _ = await issue_token(db, user)
        csrf = set_csrf(client)

        response = await client.post(
            "/reset-password",
            data={
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "csrf_token": csrf,
            },
        )
        assert response.text.count("Your password has been changed") == 1

    async def test_an_error_banner_renders_exactly_once(self, client, user):
        csrf = set_csrf(client)
        response = await client.post(
            "/login",
            data={"email": user.email, "password": "wrong", "csrf_token": csrf},
        )
        assert response.text.count("Incorrect email or password") == 1


class TestChangePasswordStillRequiresTheCurrentOne:
    """Regression cover for the settings flow, which predates this work."""

    async def test_wrong_current_password_is_rejected(self, auth_client, db, user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/settings/password",
            data={
                "current_password": "not-my-password",
                "new_password": NEW_PASSWORD,
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 400

        await db.refresh(user)
        assert verify_password(PASSWORD, user.password_hash)

    async def test_correct_current_password_changes_it(self, auth_client, db, user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/settings/password",
            data={
                "current_password": PASSWORD,
                "new_password": NEW_PASSWORD,
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 303

        await db.refresh(user)
        assert verify_password(NEW_PASSWORD, user.password_hash)

    async def test_changing_the_password_revokes_other_sessions(self, auth_client, db, user):
        other = await create_session(db, user)
        assert await session_user(db, other) is not None

        csrf = set_csrf(auth_client)
        await auth_client.post(
            "/settings/password",
            data={
                "current_password": PASSWORD,
                "new_password": NEW_PASSWORD,
                "csrf_token": csrf,
            },
        )

        assert await session_user(db, other) is None
        # The acting session is reissued, so the admin is not logged out mid-flow.
        assert (await auth_client.get("/settings")).status_code == 200
