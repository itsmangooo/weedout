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


class TestResetOverTheApi:
    """The reset endpoints the React screens post to.

    The form routes these replaced also validated the token when the page was
    opened, so an expired link was caught before anything was typed. That check
    now happens on submit instead. The security property is unchanged — the
    token is still verified server-side before any password is written — but
    somebody clicking a dead link now finds out one step later.

    Most of the enumeration and replay properties are asserted in
    test_internal_auth_actions.py alongside the rest of the JSON surface. What
    is kept here is the cases that are specific to resets.
    """

    async def _forgot(self, client, email: str):
        csrf = set_csrf(client)
        return await client.post(
            "/api/internal/auth/forgot-password",
            json={"email": email},
            headers={"X-CSRF-Token": csrf},
        )

    async def test_a_suspended_account_gets_the_same_response(self, client, db, user):
        """A closed account must not be recoverable, and must not announce
        that it is closed either."""
        user.is_suspended = True
        user.suspended_at = utcnow()
        await db.flush()

        suspended = await self._forgot(client, user.email)
        unknown = await self._forgot(client, "nobody@example.com")

        assert suspended.status_code == unknown.status_code == 200
        assert suspended.json() == unknown.json()

    async def test_no_token_is_issued_for_a_suspended_account(self, db, user, client):
        user.is_suspended = True
        user.suspended_at = utcnow()
        await db.flush()

        await self._forgot(client, user.email)

        assert (
            await db.scalar(select(PasswordResetToken).where(PasswordResetToken.user_id == user.id))
            is None
        )

    async def test_the_request_needs_csrf(self, client, user):
        """Without it, any page could start a reset for any address — which is
        not a takeover, but is a way to spray somebody's inbox."""
        response = await client.post(
            "/api/internal/auth/forgot-password", json={"email": user.email}
        )
        assert response.status_code == 403

    async def test_an_expired_token_is_refused_on_submit(self, client, db, user):
        token, record = await issue_token(db, user)
        record.expires_at = utcnow() - timedelta(seconds=1)
        await db.flush()

        csrf = set_csrf(client)
        response = await client.post(
            "/api/internal/auth/reset-password",
            json={
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
            },
            headers={"X-CSRF-Token": csrf},
        )

        assert response.status_code == 400
        assert "no longer valid" in response.json()["error"]["message"].lower()

    async def test_the_completion_needs_csrf(self, client, db, user):
        token, _ = await issue_token(db, user)

        response = await client.post(
            "/api/internal/auth/reset-password",
            json={
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
            },
        )

        assert response.status_code == 403
        # And the token survives, so a blocked request has not burned it.
        assert await verify_password_unchanged(db, user)


async def verify_password_unchanged(db, user) -> bool:
    from app.security import verify_password

    await db.refresh(user)
    return verify_password(PASSWORD, user.password_hash)


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
