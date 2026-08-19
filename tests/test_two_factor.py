"""Two-factor authentication: the algorithm, the setup flow, and the gate.

The point of these is not that TOTP arithmetic is hard — it is that the ways
2FA usually fails are behavioural: a code that can be replayed, a recovery code
that works twice, a setup that locks somebody out before it is confirmed, or a
gate that can be walked around by going straight to the page.
"""

from __future__ import annotations

import time

import pytest
from sqlalchemy import select

from app.core import totp
from app.models import BackupCode, User
from app.services.twofactor_service import (
    TwoFactorError,
    begin_setup,
    confirm_setup,
    disable,
    verify_code,
)
from tests.conftest import set_csrf


class TestTotpAlgorithm:
    def test_matches_the_rfc_6238_reference_vector(self):
        # RFC 6238 Appendix B: the SHA-1 test key is the ASCII "12345678901234567890".
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        # T = 59s falls in step 1, whose reference 8-digit value is 94287082;
        # the low six digits are what a 6-digit authenticator shows.
        assert totp.code_at(secret, 1) == "287082"
        assert totp.code_at(secret, 37037036) == "081804"

    def test_accepts_a_code_from_one_step_either_side(self):
        secret = totp.generate_secret()
        now = time.time()
        assert totp.verify(secret, totp.current_code(secret, now=now), now=now) is not None
        # A phone 25 seconds slow, and one 25 seconds fast.
        assert totp.verify(secret, totp.current_code(secret, now=now - 25), now=now) is not None
        assert totp.verify(secret, totp.current_code(secret, now=now + 25), now=now) is not None

    def test_rejects_a_code_from_two_steps_away(self):
        secret = totp.generate_secret()
        now = time.time()
        stale = totp.current_code(secret, now=now - 90)
        assert totp.verify(secret, stale, now=now) is None

    def test_rejects_malformed_input_without_raising(self):
        secret = totp.generate_secret()
        for junk in ("", "abc", "12345", "1234567", None):
            assert totp.verify(secret, junk) is None

    def test_provisioning_uri_names_the_issuer_twice(self):
        # Old apps read the issuer out of the label, current ones read the
        # parameter, and an entry that disagrees with itself shows up twice.
        uri = totp.provisioning_uri("ABC234", account="a@b.com", issuer="Weedout")
        assert uri.startswith("otpauth://totp/Weedout%3Aa%40b.com?")
        assert "issuer=Weedout" in uri
        assert "secret=ABC234" in uri

    def test_backup_codes_are_distinct_and_normalise(self):
        codes = {totp.generate_backup_code() for _ in range(50)}
        assert len(codes) == 50
        one = codes.pop()
        # Entered without its dash, in lower case, it still matches.
        assert totp.hash_backup_code(one.lower().replace("-", "")) == totp.hash_backup_code(one)


class TestSetupFlow:
    async def test_secret_alone_does_not_turn_two_factor_on(self, db, user):
        # Somebody who scans the QR and closes the tab must not be locked out.
        await begin_setup(db, user)
        await db.flush()
        assert user.totp_secret is not None
        assert user.two_factor_enabled is False

    async def test_confirming_enables_it_and_issues_recovery_codes(self, db, user):
        offer = await begin_setup(db, user)
        issued = await confirm_setup(db, user, totp.current_code(offer.secret))
        await db.flush()

        assert user.two_factor_enabled is True
        assert len(issued.codes) == totp.BACKUP_CODE_COUNT

        stored = (await db.scalars(select(BackupCode).where(BackupCode.user_id == user.id))).all()
        assert len(stored) == totp.BACKUP_CODE_COUNT
        # Only hashes are kept.
        assert all(row.code_hash not in issued.codes for row in stored)

    async def test_a_wrong_code_does_not_enable_it(self, db, user):
        await begin_setup(db, user)
        with pytest.raises(TwoFactorError):
            await confirm_setup(db, user, "000000")
        assert user.two_factor_enabled is False

    async def test_the_same_code_cannot_be_used_twice(self, db, user):
        offer = await begin_setup(db, user)
        code = totp.current_code(offer.secret)
        await confirm_setup(db, user, code)
        await db.flush()

        # Within the same 30-second step the code is still arithmetically
        # valid. It must still be refused, or anything that saw it once — a
        # shoulder, a screen share, a proxy log — can use it again.
        assert await verify_code(db, user, code) is False

    async def test_a_recovery_code_works_once(self, db, user):
        offer = await begin_setup(db, user)
        issued = await confirm_setup(db, user, totp.current_code(offer.secret))
        await db.flush()

        spare = issued.codes[3]
        assert await verify_code(db, user, spare) is True
        await db.flush()
        assert await verify_code(db, user, spare) is False

    async def test_disabling_destroys_the_secret_and_the_codes(self, db, user):
        offer = await begin_setup(db, user)
        await confirm_setup(db, user, totp.current_code(offer.secret))
        await db.flush()

        await disable(db, user)
        await db.flush()

        assert user.totp_secret is None
        assert user.two_factor_enabled is False
        assert (
            await db.scalars(select(BackupCode).where(BackupCode.user_id == user.id))
        ).all() == []


class TestLoginGate:
    async def _enable(self, db, account: User) -> str:
        offer = await begin_setup(db, account)
        await confirm_setup(db, account, totp.current_code(offer.secret))
        await db.commit()
        return offer.secret

    async def test_password_alone_does_not_produce_a_session(self, client, db, user):
        await self._enable(db, user)

        csrf = set_csrf(client)
        response = await client.post(
            "/login",
            data={"email": user.email, "password": "correct-horse-battery", "csrf_token": csrf},
        )
        assert response.status_code == 200
        assert "authenticator" in response.text.lower()

        # And the challenge is not a session: the dashboard is still shut.
        dashboard = await client.get("/dashboard")
        assert dashboard.status_code == 303
        assert "/login" in dashboard.headers["location"]

    async def test_the_code_completes_the_sign_in(self, client, db, user):
        secret = await self._enable(db, user)

        csrf = set_csrf(client)
        await client.post(
            "/login",
            data={"email": user.email, "password": "correct-horse-battery", "csrf_token": csrf},
        )

        # The next step's code, not this one's: confirming setup consumed the
        # current counter, and the replay guard is right to refuse it a second
        # time. A real sign-in is never in the same 30 seconds as the setup.
        csrf = set_csrf(client)
        response = await client.post(
            "/login/2fa",
            data={
                "code": totp.current_code(secret, now=time.time() + totp.STEP_SECONDS),
                "next": "/dashboard",
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        assert (await client.get("/dashboard")).status_code == 200

    async def test_a_wrong_code_is_refused(self, client, db, user):
        await self._enable(db, user)

        csrf = set_csrf(client)
        await client.post(
            "/login",
            data={"email": user.email, "password": "correct-horse-battery", "csrf_token": csrf},
        )

        csrf = set_csrf(client)
        response = await client.post(
            "/login/2fa",
            data={"code": "000000", "next": "/dashboard", "csrf_token": csrf},
        )
        assert response.status_code == 401
        assert (await client.get("/dashboard")).status_code == 303

    async def test_the_second_step_cannot_be_reached_without_the_first(self, client, db, user):
        secret = await self._enable(db, user)

        # A correct code, but no challenge cookie: posting straight to the
        # second step must not be a way past the password.
        csrf = set_csrf(client)
        response = await client.post(
            "/login/2fa",
            data={"code": totp.current_code(secret), "next": "/dashboard", "csrf_token": csrf},
        )
        assert response.status_code == 400
        assert (await client.get("/dashboard")).status_code == 303
