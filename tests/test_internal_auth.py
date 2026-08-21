"""Browser-session bootstrap contract for the React application."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app.config import get_settings
from app.models import Session, utcnow
from app.services.auth_service import create_session


async def attach_session(client, db, user) -> str:
    token = await create_session(db, user)
    await db.flush()
    client.cookies.set(get_settings().session_cookie_name, token)
    return token


def assert_csrf_bootstrap(response) -> None:
    cookie = response.cookies.get("weedout_csrf")
    assert cookie

    header = response.headers["set-cookie"]
    assert "weedout_csrf=" in header
    assert "Max-Age=43200" in header
    assert "Path=/" in header
    assert "SameSite=lax" in header
    # The double-submit value must be readable so React can echo it in the
    # X-CSRF-Token header. It is not an authentication credential.
    csrf_segment = next(part for part in header.split(", ") if "weedout_csrf=" in part)
    assert "HttpOnly" not in csrf_segment


class TestCurrentUserBoundary:
    async def test_anonymous_bootstrap_is_a_clean_json_state(self, client):
        response = await client.get("/api/internal/auth/me", headers={"Accept": "text/html"})

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["cache-control"] == "private, no-store"
        assert response.headers["vary"] == "Cookie"
        assert response.json() == {
            "data": {
                "authenticated": False,
                "session_state": "anonymous",
                "user": None,
            }
        }
        assert get_settings().session_cookie_name not in response.cookies
        assert_csrf_bootstrap(response)

    async def test_authenticated_bootstrap_returns_only_safe_explicit_fields(
        self, client, db, user
    ):
        await attach_session(client, db, user)

        response = await client.get("/api/internal/auth/me")

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["authenticated"] is True
        assert data["session_state"] == "authenticated"
        assert data["user"] == {
            "id": user.id,
            "email": user.email,
            "is_admin": False,
            "tier": "free",
            "account_state": "active",
        }
        assert set(data["user"]) == {
            "id",
            "email",
            "is_admin",
            "tier",
            "account_state",
        }
        assert_csrf_bootstrap(response)

    async def test_admin_state_is_explicit_without_exposing_more_user_data(self, client, db, user):
        user.is_admin = True
        await db.flush()
        await attach_session(client, db, user)

        response = await client.get("/api/internal/auth/me")

        assert response.status_code == 200
        safe_user = response.json()["data"]["user"]
        assert safe_user["is_admin"] is True
        assert set(safe_user) == {
            "id",
            "email",
            "is_admin",
            "tier",
            "account_state",
        }

    async def test_expired_session_is_json_native_and_clears_the_stale_cookie(
        self, client, db, user
    ):
        await attach_session(client, db, user)
        session = await db.scalar(select(Session).where(Session.user_id == user.id))
        assert session is not None
        session.expires_at = utcnow() - timedelta(seconds=1)
        await db.flush()

        response = await client.get("/api/internal/auth/me", headers={"Accept": "text/html"})

        assert response.status_code == 401
        assert response.headers["content-type"].startswith("application/json")
        assert response.json() == {
            "error": {
                "code": "SESSION_EXPIRED",
                "message": "Your session has expired. Sign in again.",
            }
        }
        assert "weedout_session=" in response.headers["set-cookie"]
        assert "Max-Age=0" in response.headers["set-cookie"]
        assert_csrf_bootstrap(response)

    async def test_revoked_or_unknown_session_does_not_reveal_why_it_failed(self, client):
        client.cookies.set(get_settings().session_cookie_name, "not-a-real-session")

        response = await client.get("/api/internal/auth/me")

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "SESSION_EXPIRED"
