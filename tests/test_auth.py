"""Authentication: registration, login, sessions, CSRF."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.types import Tier
from app.models import Session
from app.security import hash_session_token
from app.services.auth_service import (
    EmailAlreadyRegistered,
    InvalidCredentials,
    WeakPassword,
    authenticate,
    create_session,
    register_user,
    revoke_session,
    session_user,
)
from tests.conftest import FIXTURE_PASSWORD, set_csrf, sign_in


class TestRegistration:
    async def test_creates_a_free_tier_user(self, db):
        user = await register_user(db, "New@Example.COM", "a-good-long-password")
        assert user.tier is Tier.FREE
        assert user.is_active is True

    async def test_email_is_normalised_to_lowercase(self, db):
        user = await register_user(db, "  MiXeD@Example.COM  ", "a-good-long-password")
        assert user.email == "mixed@example.com"

    async def test_password_is_hashed_not_stored(self, db):
        password = "a-good-long-password"
        user = await register_user(db, "hash@example.com", password)
        assert user.password_hash
        assert password not in user.password_hash
        assert user.password_hash.startswith("$argon2id$")

    async def test_duplicate_email_is_rejected(self, db):
        await register_user(db, "dupe@example.com", "a-good-long-password")
        with pytest.raises(EmailAlreadyRegistered):
            await register_user(db, "dupe@example.com", "another-long-password")

    async def test_duplicate_check_is_case_insensitive(self, db):
        await register_user(db, "case@example.com", "a-good-long-password")
        with pytest.raises(EmailAlreadyRegistered):
            await register_user(db, "CASE@EXAMPLE.COM", "another-long-password")

    @pytest.mark.parametrize("password", ["short", "123456789", "password123"])
    async def test_weak_passwords_are_rejected(self, db, password):
        with pytest.raises(WeakPassword):
            await register_user(db, "weak@example.com", password)


class TestAuthentication:
    async def test_correct_credentials_succeed(self, db, user):
        authenticated = await authenticate(db, user.email, "correct-horse-battery")
        assert authenticated.id == user.id
        assert authenticated.last_login_at is not None

    async def test_wrong_password_is_rejected(self, db, user):
        with pytest.raises(InvalidCredentials):
            await authenticate(db, user.email, "wrong-password")

    async def test_unknown_email_raises_the_same_error(self, db):
        # Identical error text and type, so the response cannot be used to work
        # out which addresses are registered.
        with pytest.raises(InvalidCredentials) as exc:
            await authenticate(db, "nobody@example.com", "any-password")
        assert "Incorrect email or password" in str(exc.value)

    async def test_deactivated_account_cannot_sign_in(self, db, user):
        user.is_active = False
        await db.flush()
        with pytest.raises(InvalidCredentials):
            await authenticate(db, user.email, "correct-horse-battery")


class TestSessions:
    async def test_token_is_stored_only_as_a_hash(self, db, user):
        token = await create_session(db, user)
        stored = await db.scalar(select(Session).where(Session.user_id == user.id))
        assert stored is not None
        assert stored.token_hash != token
        assert stored.token_hash == hash_session_token(token)

    async def test_valid_token_resolves_to_the_user(self, db, user):
        token = await create_session(db, user)
        assert (await session_user(db, token)).id == user.id

    async def test_unknown_token_resolves_to_none(self, db, user):
        await create_session(db, user)
        assert await session_user(db, "not-a-real-token") is None
        assert await session_user(db, None) is None
        assert await session_user(db, "") is None

    async def test_revocation_takes_effect_immediately(self, db, user):
        # The whole reason for server-side sessions: no window in which a
        # revoked credential still works.
        token = await create_session(db, user)
        assert await session_user(db, token) is not None

        await revoke_session(db, token)
        assert await session_user(db, token) is None

    async def test_expired_session_is_rejected(self, db, user):
        from datetime import timedelta

        from app.models import utcnow

        token = await create_session(db, user)
        stored = await db.scalar(select(Session).where(Session.user_id == user.id))
        stored.expires_at = utcnow() - timedelta(seconds=1)
        await db.flush()

        assert await session_user(db, token) is None

    async def test_deactivating_a_user_invalidates_their_sessions(self, db, user):
        token = await create_session(db, user)
        user.is_active = False
        await db.flush()
        assert await session_user(db, token) is None


class TestAuthRoutes:
    async def test_login_rejects_bad_credentials_with_401(self, client, user):
        response = await sign_in(client, user.email, "wrong")
        assert response.status_code == 401
        assert "weedout_session" not in response.cookies

    async def test_login_honours_a_local_next_parameter(self, client, user):
        """Where to go afterwards now comes back in the body rather than as a
        redirect, because the client does the navigating. The validation of it
        did not move."""
        csrf = set_csrf(client)
        response = await client.post(
            "/api/internal/auth/login",
            json={"email": user.email, "password": FIXTURE_PASSWORD, "next": "/alerts"},
            headers={"X-CSRF-Token": csrf},
        )

        assert response.status_code == 200
        assert response.json()["next"] == "/alerts"

    @pytest.mark.parametrize(
        "hostile", ["https://evil.example/steal", "//evil.example", "http://evil.example"]
    )
    async def test_login_refuses_to_send_you_off_site(self, client, user, hostile):
        """`next` arrives from a query string, so it is attacker-controlled.

        Checked on the server and not only in the browser: a client can be
        made to skip its own validation, and the consequence here is our own
        sign-in page delivering people to somebody else's.
        """
        csrf = set_csrf(client)
        response = await client.post(
            "/api/internal/auth/login",
            json={"email": user.email, "password": FIXTURE_PASSWORD, "next": hostile},
            headers={"X-CSRF-Token": csrf},
        )

        assert response.status_code == 200
        assert response.json()["next"] == "/dashboard"

    async def test_logout_clears_the_session(self, auth_client):
        assert (await auth_client.get("/api/internal/dashboard")).status_code == 200

        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/api/internal/auth/logout", json={}, headers={"X-CSRF-Token": csrf}
        )
        assert response.status_code == 200

        after = await auth_client.get("/api/internal/auth/me")
        assert after.status_code == 200
        assert after.json()["data"]["authenticated"] is False

    async def test_anonymous_visitor_cannot_read_dashboard_data(self, client):
        response = await client.get("/api/internal/dashboard")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHENTICATED"
