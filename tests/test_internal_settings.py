"""The settings endpoints the React account page uses.

This is the most dangerous surface in the application, so the tests are about
what must not happen rather than what should.

Three things carry the weight:

  * A secret is returned once and never again. A TOTP secret, a set of backup
    codes and a new API key's plaintext each exist in exactly one response. A
    secret that can be re-read is a secret sitting in whatever cache, history
    or log touched the page.
  * Turning the second factor off costs a password. A session left open on a
    shared machine must not be enough to remove the control that protects the
    account when a password leaks.
  * Changing a password ends every other session but not this one. Being
    signed out of the page you just used reads as a bug; leaving everyone else
    signed in defeats the point of the change.
"""

from __future__ import annotations

from sqlalchemy import select

from app.core import totp
from app.core.types import KeyScope
from app.models import ApiKey, Session, TrackedTarget
from app.security import verify_password
from tests.conftest import FIXTURE_PASSWORD, set_csrf, sign_in

SETTINGS = "/api/internal/settings"


async def post(client, path: str, body=None):
    csrf = set_csrf(client)
    return await client.post(
        path, json=body if body is not None else {}, headers={"X-CSRF-Token": csrf}
    )


async def enable_two_factor(client, db, user) -> str:
    """Complete a real setup and return the secret."""
    started = await post(client, f"{SETTINGS}/2fa/start")
    secret = started.json()["data"]["secret"]

    await post(client, f"{SETTINGS}/2fa/confirm", {"code": totp.current_code(secret)})
    await db.refresh(user)
    return secret


class TestReading:
    async def test_it_returns_what_the_page_shows(self, auth_client, db, user):
        response = await auth_client.get(SETTINGS)

        assert response.status_code == 200
        body = response.json()
        assert body["data"]["email"] == user.email
        for section in ("projects", "api_keys", "sessions"):
            assert section in body

    async def test_it_never_returns_a_password_hash(self, auth_client, db, user):
        response = await auth_client.get(SETTINGS)

        assert user.password_hash not in response.text
        assert "password_hash" not in response.text

    async def test_it_never_returns_a_session_token(self, auth_client, db, user):
        """The list names devices; it does not hand out the credentials that
        identify them. A token in this response would let an XSS bug read every
        session the account has open."""
        response = await auth_client.get(SETTINGS)

        stored = (await db.scalars(select(Session).where(Session.user_id == user.id))).all()
        assert stored, "the fixture should have a live session"
        for session in stored:
            assert session.token_hash not in response.text

    async def test_it_marks_the_session_you_are_using(self, auth_client, db, user):
        """Somebody about to sign out everything else needs to know which row
        is the one they are sitting at."""
        response = await auth_client.get(SETTINGS)

        sessions = response.json()["sessions"]
        assert sum(1 for session in sessions if session["is_current"]) == 1

    async def test_it_is_never_shared_cache(self, auth_client):
        response = await auth_client.get(SETTINGS)

        assert "no-store" in response.headers["cache-control"]
        assert response.headers["vary"] == "Cookie"

    async def test_signed_out_callers_get_nothing(self, client):
        assert (await client.get(SETTINGS)).status_code == 401


class TestAlertPreferences:
    async def test_it_can_be_turned_off_and_on(self, auth_client, db, user):
        await post(auth_client, f"{SETTINGS}/alerts", {"email_alerts": False})
        await db.refresh(user)
        assert user.email_alerts_enabled is False

        await post(auth_client, f"{SETTINGS}/alerts", {"email_alerts": True})
        await db.refresh(user)
        assert user.email_alerts_enabled is True

    async def test_it_needs_csrf(self, auth_client, db, user):
        await auth_client.post(f"{SETTINGS}/alerts", json={"email_alerts": False})

        await db.refresh(user)
        assert user.email_alerts_enabled is True


class TestChangingPassword:
    async def test_the_current_password_is_required(self, auth_client, db, user):
        before = user.password_hash

        response = await post(
            auth_client,
            f"{SETTINGS}/password",
            {"current_password": "not-it", "new_password": "a-brand-new-password"},
        )

        assert response.status_code == 400
        await db.refresh(user)
        assert user.password_hash == before

    async def test_a_correct_change_takes_effect(self, auth_client, db, user):
        response = await post(
            auth_client,
            f"{SETTINGS}/password",
            {"current_password": FIXTURE_PASSWORD, "new_password": "a-brand-new-password"},
        )

        assert response.status_code == 200
        await db.refresh(user)
        assert verify_password("a-brand-new-password", user.password_hash)

    async def test_this_session_survives_it(self, auth_client, db, user):
        """Being signed out of the page you just used to change your password
        reads as a bug, not as a security measure."""
        await post(
            auth_client,
            f"{SETTINGS}/password",
            {"current_password": FIXTURE_PASSWORD, "new_password": "a-brand-new-password"},
        )

        assert (await auth_client.get(SETTINGS)).status_code == 200

    async def test_every_other_session_is_ended(self, other_client, auth_client, db, user):
        """And this is the point of the change. A password that leaked has to
        stop being useful to whoever has it."""
        elsewhere = await sign_in(other_client, user.email)
        assert elsewhere.status_code == 200

        await post(
            auth_client,
            f"{SETTINGS}/password",
            {"current_password": FIXTURE_PASSWORD, "new_password": "a-brand-new-password"},
        )

        assert (await other_client.get(SETTINGS)).status_code == 401

    async def test_a_weak_new_password_is_refused(self, auth_client, db, user):
        before = user.password_hash

        response = await post(
            auth_client,
            f"{SETTINGS}/password",
            {"current_password": FIXTURE_PASSWORD, "new_password": "short"},
        )

        assert response.status_code == 400
        await db.refresh(user)
        assert user.password_hash == before


class TestSessions:
    async def test_signing_out_everywhere_else_keeps_this_one(
        self, other_client, auth_client, db, user
    ):
        await sign_in(other_client, user.email)

        response = await post(auth_client, f"{SETTINGS}/sessions/revoke-others")

        assert response.status_code == 200
        # Still signed in here...
        assert (await auth_client.get(SETTINGS)).status_code == 200
        # ...and not there.
        assert (await other_client.get(SETTINGS)).status_code == 401

    async def test_another_accounts_session_cannot_be_revoked(
        self, auth_client, other_client, db, user, pro_user
    ):
        """The id comes from the URL, so the only thing standing between a
        signed-in stranger and somebody else's session is the lookup being
        scoped to the caller."""
        await sign_in(other_client, pro_user.email)
        theirs = await db.scalar(select(Session).where(Session.user_id == pro_user.id))
        assert theirs is not None

        response = await post(auth_client, f"{SETTINGS}/sessions/{theirs.id}/revoke")

        assert response.status_code == 404
        await db.refresh(theirs)
        assert theirs.revoked_at is None


class TestTwoFactor:
    async def test_starting_setup_does_not_switch_it_on(self, auth_client, db, user):
        """A mis-scanned QR code must not lock somebody out of their own
        account, so the secret is held unconfirmed until a code proves the
        authenticator actually has it."""
        response = await post(auth_client, f"{SETTINGS}/2fa/start")

        assert response.status_code == 200
        assert response.json()["data"]["secret"]
        await db.refresh(user)
        assert user.two_factor_enabled is False

    async def test_a_correct_code_switches_it_on(self, auth_client, db, user):
        started = await post(auth_client, f"{SETTINGS}/2fa/start")
        secret = started.json()["data"]["secret"]

        response = await post(
            auth_client, f"{SETTINGS}/2fa/confirm", {"code": totp.current_code(secret)}
        )

        assert response.status_code == 200
        await db.refresh(user)
        assert user.two_factor_enabled is True

    async def test_a_wrong_code_does_not(self, auth_client, db, user):
        await post(auth_client, f"{SETTINGS}/2fa/start")

        response = await post(auth_client, f"{SETTINGS}/2fa/confirm", {"code": "000000"})

        assert response.status_code == 400
        await db.refresh(user)
        assert user.two_factor_enabled is False

    async def test_the_secret_is_returned_once_and_never_again(self, auth_client, db, user):
        started = await post(auth_client, f"{SETTINGS}/2fa/start")
        secret = started.json()["data"]["secret"]
        await post(auth_client, f"{SETTINGS}/2fa/confirm", {"code": totp.current_code(secret)})

        # Reading the page back must not hand it over. A secret that can be
        # re-read is a secret in every cache between here and the browser.
        page = await auth_client.get(SETTINGS)
        assert secret not in page.text

    async def test_backup_codes_are_returned_once_and_never_again(self, auth_client, db, user):
        await enable_two_factor(auth_client, db, user)

        response = await post(auth_client, f"{SETTINGS}/2fa/codes")
        codes = response.json()["data"]["backup_codes"]
        assert codes

        page = await auth_client.get(SETTINGS)
        for code in codes:
            assert code not in page.text

    async def test_new_backup_codes_retire_the_old_ones(self, auth_client, db, user):
        await enable_two_factor(auth_client, db, user)

        first = (await post(auth_client, f"{SETTINGS}/2fa/codes")).json()["data"]["backup_codes"]
        second = (await post(auth_client, f"{SETTINGS}/2fa/codes")).json()["data"]["backup_codes"]

        # Otherwise a set somebody thought they had replaced still opens the
        # account.
        assert set(first).isdisjoint(second)

    async def test_codes_cannot_be_generated_without_two_factor(self, auth_client, db, user):
        response = await post(auth_client, f"{SETTINGS}/2fa/codes")

        assert response.status_code == 400

    async def test_turning_it_off_costs_a_password(self, auth_client, db, user):
        """The control that survives a stolen password cannot be removable by
        whoever is holding a session on a shared machine."""
        await enable_two_factor(auth_client, db, user)

        response = await post(auth_client, f"{SETTINGS}/2fa/disable", {"password": "not-it"})

        assert response.status_code == 400
        await db.refresh(user)
        assert user.two_factor_enabled is True

    async def test_the_right_password_turns_it_off(self, auth_client, db, user):
        await enable_two_factor(auth_client, db, user)

        response = await post(
            auth_client, f"{SETTINGS}/2fa/disable", {"password": FIXTURE_PASSWORD}
        )

        assert response.status_code == 200
        await db.refresh(user)
        assert user.two_factor_enabled is False

    async def test_switching_it_off_needs_csrf(self, auth_client, db, user):
        await enable_two_factor(auth_client, db, user)

        response = await auth_client.post(
            f"{SETTINGS}/2fa/disable", json={"password": FIXTURE_PASSWORD}
        )

        assert response.status_code == 403
        await db.refresh(user)
        assert user.two_factor_enabled is True


class TestApiKeys:
    async def _project(self, db, owner) -> TrackedTarget:
        target = TrackedTarget(user_id=owner.id, name="proj", ecosystem="npm", is_active=True)
        db.add(target)
        await db.flush()
        return target

    async def test_a_key_is_issued_for_a_project(self, auth_client, db, user):
        target = await self._project(db, user)
        await db.commit()

        response = await post(
            auth_client, f"{SETTINGS}/api-keys", {"target_id": target.id, "name": "ci"}
        )

        assert response.status_code == 200
        assert response.json()["data"]["token"].startswith("wo_")

    async def test_the_plaintext_is_stored_nowhere(self, auth_client, db, user):
        target = await self._project(db, user)
        await db.commit()

        token = (
            await post(auth_client, f"{SETTINGS}/api-keys", {"target_id": target.id, "name": "ci"})
        ).json()["data"]["token"]

        stored = await db.scalar(select(ApiKey).where(ApiKey.target_id == target.id))
        assert token not in stored.token_hash
        assert token not in (await auth_client.get(SETTINGS)).text

    async def test_it_defaults_to_the_narrowest_scope(self, auth_client, db, user):
        target = await self._project(db, user)
        await db.commit()

        await post(auth_client, f"{SETTINGS}/api-keys", {"target_id": target.id, "name": "ci"})

        stored = await db.scalar(select(ApiKey).where(ApiKey.target_id == target.id))
        assert stored.scope is KeyScope.SCAN

    async def test_a_key_cannot_be_scoped_to_someone_elses_project(
        self, auth_client, db, user, pro_user
    ):
        theirs = await self._project(db, pro_user)
        await db.commit()

        response = await post(
            auth_client, f"{SETTINGS}/api-keys", {"target_id": theirs.id, "name": "ci"}
        )

        assert response.status_code == 404
        assert await db.scalar(select(ApiKey).where(ApiKey.target_id == theirs.id)) is None

    async def test_a_revoked_key_stays_listed(self, auth_client, db, user):
        """The record that a credential existed, and when it stopped working,
        is worth more than a tidy table."""
        target = await self._project(db, user)
        await db.commit()

        created = await post(
            auth_client, f"{SETTINGS}/api-keys", {"target_id": target.id, "name": "old"}
        )
        key_id = created.json()["data"]["id"]
        await post(auth_client, f"{SETTINGS}/api-keys/{key_id}/revoke")

        listed = (await auth_client.get(SETTINGS)).json()["api_keys"]
        revoked = next(entry for entry in listed if entry["id"] == key_id)
        assert revoked["is_active"] is False
        assert revoked["revoked_at"] is not None

    async def test_no_project_chosen_is_a_friendly_error(self, auth_client, db, user):
        response = await post(auth_client, f"{SETTINGS}/api-keys", {"name": "nowhere"})

        assert response.status_code in {400, 404}
        assert response.json()["error"]["message"]

    async def test_another_accounts_key_cannot_be_revoked(self, auth_client, db, user, pro_user):
        theirs = await self._project(db, pro_user)
        key = ApiKey(
            user_id=pro_user.id,
            target_id=theirs.id,
            name="theirs",
            prefix="wo_theirs",
            token_hash="h" * 64,
        )
        db.add(key)
        await db.commit()

        response = await post(auth_client, f"{SETTINGS}/api-keys/{key.id}/revoke")

        assert response.status_code == 404
        await db.refresh(key)
        assert key.revoked_at is None
