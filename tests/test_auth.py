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


class TestApiKeySettings:
    """The API-key panel on the Settings page.

    These render the real template against real data. The panel is the only
    place a key is ever legible, and the only route in the app whose response
    body is a credential — both are worth asserting on rather than trusting.
    """

    async def _add_project(self, auth_client, db, user, name="demo-app"):
        from app.core.types import ManifestKind
        from app.models import TrackedTarget
        from app.security import content_hash

        target = TrackedTarget(
            user_id=user.id,
            name=name,
            manifest_kind=ManifestKind.PACKAGE_JSON,
            ecosystem="npm",
            manifest_content="{}",
            content_hash=content_hash(name),
        )
        db.add(target)
        await db.flush()
        return target

    async def test_the_panel_renders_with_no_projects(self, auth_client):
        response = await auth_client.get("/settings")
        assert response.status_code == 200
        assert "API keys" in response.text
        # Nothing to issue a key against yet, so it points at the next step.
        assert "Add a project" in response.text

    async def test_the_panel_lists_the_users_projects(self, auth_client, db, user):
        await self._add_project(auth_client, db, user, name="my-service")

        response = await auth_client.get("/settings")
        assert "my-service" in response.text

    async def test_creating_a_key_shows_it_exactly_once(self, auth_client, db, user):
        from sqlalchemy import select

        from app.models import ApiKey

        target = await self._add_project(auth_client, db, user)
        csrf = set_csrf(auth_client)

        created = await auth_client.post(
            "/settings/api-keys",
            data={"target_id": str(target.id), "name": "ci", "csrf_token": csrf},
        )
        assert created.status_code == 200

        record = await db.scalar(select(ApiKey))
        assert record is not None
        assert record.prefix in created.text

        # Reloading the page must not show it again. There is no code path that
        # could — this asserts none appears.
        again = await auth_client.get("/settings")
        assert "will not be shown again" not in again.text

    async def test_the_plaintext_key_never_reaches_the_database(self, auth_client, db, user):
        from sqlalchemy import select

        from app.models import ApiKey
        from app.security import hash_api_key

        target = await self._add_project(auth_client, db, user)
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/settings/api-keys", data={"target_id": str(target.id), "csrf_token": csrf}
        )

        record = await db.scalar(select(ApiKey))
        # Recover the key from the page and confirm only its hash was stored.
        assert record.token_hash not in response.text
        assert record.token_hash == hash_api_key(_extract_key(response.text))

    async def test_a_key_cannot_be_created_for_another_users_project(
        self, auth_client, db, user, pro_user
    ):
        from sqlalchemy import select

        from app.models import ApiKey

        theirs = await self._add_project(auth_client, db, pro_user, name="not-yours")
        csrf = set_csrf(auth_client)

        response = await auth_client.post(
            "/settings/api-keys", data={"target_id": str(theirs.id), "csrf_token": csrf}
        )
        assert response.status_code == 404
        assert await db.scalar(select(ApiKey)) is None

    async def test_creating_a_key_requires_a_csrf_token(self, auth_client, db, user):
        target = await self._add_project(auth_client, db, user)
        response = await auth_client.post("/settings/api-keys", data={"target_id": str(target.id)})
        assert response.status_code == 403

    async def test_creating_a_key_requires_authentication(self, client):
        csrf = set_csrf(client)
        response = await client.post(
            "/settings/api-keys", data={"target_id": "1", "csrf_token": csrf}
        )
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    async def test_revoking_a_key_marks_it_revoked(self, auth_client, db, user):
        from app.services.api_key_service import issue_api_key

        target = await self._add_project(auth_client, db, user)
        issued = await issue_api_key(db, user, target)
        await db.commit()

        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/settings/api-keys/{issued.record.id}/revoke", data={"csrf_token": csrf}
        )
        assert response.status_code == 303

        await db.refresh(issued.record)
        assert issued.record.revoked_at is not None

    async def test_a_revoked_key_stays_listed(self, auth_client, db, user):
        # The record that a credential existed and when it stopped working is
        # worth more than a tidy table.
        from app.services.api_key_service import issue_api_key, revoke_api_key

        target = await self._add_project(auth_client, db, user)
        issued = await issue_api_key(db, user, target)
        await revoke_api_key(db, user, issued.record.id)
        await db.commit()

        response = await auth_client.get("/settings")
        assert issued.record.prefix in response.text
        assert "Revoked" in response.text

    async def test_cannot_revoke_another_users_key(self, auth_client, db, user, pro_user):
        from app.services.api_key_service import issue_api_key

        target = await self._add_project(auth_client, db, pro_user, name="theirs")
        issued = await issue_api_key(db, pro_user, target)
        await db.commit()

        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            f"/settings/api-keys/{issued.record.id}/revoke", data={"csrf_token": csrf}
        )
        assert response.status_code == 404

        await db.refresh(issued.record)
        assert issued.record.revoked_at is None

    async def test_a_missing_project_is_a_friendly_error_not_a_crash(self, auth_client, db, user):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/settings/api-keys", data={"target_id": "", "csrf_token": csrf}
        )
        assert response.status_code == 400
        assert "API keys" in response.text  # the page still renders


def _extract_key(html: str) -> str:
    """Pull the one-time key out of the rendered reveal panel."""
    import re

    match = re.search(r'class="keyreveal__value mono">([^<]+)<', html)
    assert match, "the new key was not rendered"
    return match.group(1).strip()
