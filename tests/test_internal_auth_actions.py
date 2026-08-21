"""The JSON sign-in surface the React application uses.

The property under test throughout is that this door is no weaker than the
form it sits beside. It is a second entrance to the same building, and the
interesting failures are the ones where the two disagree: a different answer
for a wrong password tells somebody which addresses are registered, and a
missing rate limit on one of them makes the other's irrelevant.

The flow itself is tested in `test_auth.py` against the form routes. What is
tested here is the JSON contract and the things that are easy to get wrong when
adding a second caller: cookies, CSRF, status codes, and what is said back.
"""

from __future__ import annotations

from sqlalchemy import select

from app.models import User


async def enable_two_factor(db, user) -> None:
    """Put an account into the confirmed-TOTP state.

    `two_factor_enabled` is derived from `totp_confirmed_at` rather than being
    a flag, so a test that sets the property is testing nothing.
    """
    from app.models import utcnow

    user.totp_secret = "JBSWY3DPEHPK3PXP"
    user.totp_confirmed_at = utcnow()
    await db.commit()


LOGIN = "/api/internal/auth/login"
SIGNUP = "/api/internal/auth/signup"
SECOND_FACTOR = "/api/internal/auth/login/2fa"
LOGOUT = "/api/internal/auth/logout"
FORGOT = "/api/internal/auth/forgot-password"
RESET = "/api/internal/auth/reset-password"
ME = "/api/internal/auth/me"

PASSWORD = "correct-horse-battery"


async def csrf(client) -> str:
    """Bootstrap the double-submit cookie the way the React client does."""
    await client.get(ME)
    return client.cookies.get("weedout_csrf")


async def post(client, path: str, body: dict, *, token: str | None = None):
    headers = {"X-CSRF-Token": token if token is not None else await csrf(client)}
    return await client.post(path, json=body, headers=headers)


class TestSigningIn:
    async def test_a_correct_password_returns_the_user_and_sets_a_session(self, client, db, user):
        response = await post(client, LOGIN, {"email": user.email, "password": PASSWORD})

        assert response.status_code == 200
        body = response.json()
        assert body["data"]["authenticated"] is True
        assert body["data"]["user"]["email"] == user.email
        assert client.cookies.get("weedout_session")

    async def test_the_session_cookie_is_not_readable_by_javascript(self, client, user):
        """An XSS bug should not be able to walk off with the session. The
        React client never needs it -- only the CSRF cookie, which is
        deliberately readable."""
        response = await post(client, LOGIN, {"email": user.email, "password": PASSWORD})

        cookie = next(
            value
            for key, value in response.headers.items()
            if key.lower() == "set-cookie" and "weedout_session" in value
        )
        assert "httponly" in cookie.lower()

    async def test_the_password_is_never_echoed_back(self, client, user):
        response = await post(client, LOGIN, {"email": user.email, "password": PASSWORD})
        assert PASSWORD not in response.text

    async def test_a_wrong_password_says_what_the_form_says(self, client, user):
        """Not "no such account" and not "wrong password" -- one answer, so
        neither door can be used to discover who is registered."""
        response = await post(client, LOGIN, {"email": user.email, "password": "wrong"})

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"

    async def test_an_unknown_address_answers_identically(self, client, user):
        known = await post(client, LOGIN, {"email": user.email, "password": "wrong"})
        unknown = await post(client, LOGIN, {"email": "nobody@example.com", "password": "wrong"})

        assert known.status_code == unknown.status_code
        assert known.json() == unknown.json()

    async def test_no_session_is_set_on_a_failure(self, client, user):
        await post(client, LOGIN, {"email": user.email, "password": "wrong"})
        assert not client.cookies.get("weedout_session")

    async def test_a_request_without_a_csrf_token_is_refused(self, client, user):
        """The reason this endpoint is safe to expose to a browser. Without
        it, any page on the internet could post a login and set a cookie."""
        response = await client.post(LOGIN, json={"email": user.email, "password": PASSWORD})

        assert response.status_code == 403
        assert not client.cookies.get("weedout_session")

    async def test_a_forged_csrf_token_is_refused(self, client, user):
        await csrf(client)
        response = await client.post(
            LOGIN,
            json={"email": user.email, "password": PASSWORD},
            headers={"X-CSRF-Token": "not-the-real-one"},
        )

        assert response.status_code == 403


class TestRateLimiting:
    async def test_repeated_failures_are_throttled_before_hashing(
        self, client, db, user, monkeypatch
    ):
        """The limit has to bite before the password is verified.

        Argon2id costs 19 MiB and real CPU per call, so an unthrottled endpoint
        is a memory-exhaustion lever as well as a credential-stuffing target.
        Counting the hashes proves the check happens first rather than merely
        happening.
        """
        hashes = 0
        import app.services.auth_service as auth_service

        original = auth_service.verify_password

        def counting(*args, **kwargs):
            nonlocal hashes
            hashes += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(auth_service, "verify_password", counting)

        statuses = []
        for _ in range(30):
            response = await post(client, LOGIN, {"email": user.email, "password": "wrong"})
            statuses.append(response.status_code)
            if response.status_code == 429:
                break

        assert 429 in statuses, "the endpoint never throttled"

        before = hashes
        throttled = await post(client, LOGIN, {"email": user.email, "password": "wrong"})
        assert throttled.status_code == 429
        assert hashes == before, "a throttled attempt still paid for a password hash"

    async def test_a_throttled_reply_says_when_to_come_back(self, client, user):
        for _ in range(30):
            response = await post(client, LOGIN, {"email": user.email, "password": "wrong"})
            if response.status_code == 429:
                break

        assert response.status_code == 429
        assert response.json()["error"]["code"] == "RATE_LIMITED"


class TestSecondFactor:
    async def test_a_2fa_account_is_not_signed_in_by_a_password_alone(self, client, db, user):
        await enable_two_factor(db, user)

        response = await post(client, LOGIN, {"email": user.email, "password": PASSWORD})

        assert response.status_code == 200
        body = response.json()
        # A step, not a failure. Reporting an error here would tell somebody
        # whose password was right that it was wrong.
        assert body["data"]["two_factor_required"] is True
        assert body["data"]["authenticated"] is False
        assert not client.cookies.get("weedout_session")

    async def test_the_challenge_cookie_is_not_a_session(self, client, db, user):
        await enable_two_factor(db, user)

        await post(client, LOGIN, {"email": user.email, "password": PASSWORD})

        # It names the account and an expiry and nothing else, so a stolen one
        # buys only the remaining minutes of a code prompt.
        assert client.cookies.get("weedout_mfa")
        assert not client.cookies.get("weedout_session")

        blocked = await client.get("/api/internal/dashboard")
        assert blocked.status_code == 401

    async def test_a_wrong_code_does_not_produce_a_session(self, client, db, user):
        """Regression. The first version of this endpoint wrapped verify_code
        in a try/except for a TwoFactorError it never raises — verify_code
        answers with a bool — so every rejected code fell straight through to
        creating a session. Any wrong code signed you in.
        """
        await enable_two_factor(db, user)
        await post(client, LOGIN, {"email": user.email, "password": PASSWORD})

        response = await post(client, SECOND_FACTOR, {"code": "000000"})

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "INVALID_CODE"
        assert not client.cookies.get("weedout_session")
        assert (await client.get("/api/internal/dashboard")).status_code == 401

    async def test_an_empty_code_does_not_produce_a_session(self, client, db, user):
        await enable_two_factor(db, user)
        await post(client, LOGIN, {"email": user.email, "password": PASSWORD})

        response = await post(client, SECOND_FACTOR, {"code": ""})

        assert response.status_code == 401
        assert not client.cookies.get("weedout_session")


class TestSigningUp:
    async def test_an_account_is_created_and_signed_in(self, client, db):
        response = await post(client, SIGNUP, {"email": "new@example.com", "password": PASSWORD})

        assert response.status_code == 201
        assert response.json()["data"]["user"]["email"] == "new@example.com"
        assert client.cookies.get("weedout_session")

        created = await db.scalar(select(User).where(User.email == "new@example.com"))
        assert created is not None

    async def test_a_duplicate_address_is_refused(self, client, db, user):
        response = await post(client, SIGNUP, {"email": user.email, "password": PASSWORD})

        assert response.status_code == 409
        assert response.json()["error"]["code"] == "EMAIL_IN_USE"

    async def test_a_weak_password_is_refused_with_the_reason(self, client, db):
        """Refused, and the message says what would be acceptable.

        The code is INVALID_REQUEST rather than WEAK_PASSWORD because the
        length rule lives on the form schema and fires before the service is
        reached -- the same order the rendered signup uses. What matters to
        somebody typing is that they are told the requirement, not which layer
        caught them.
        """
        response = await post(client, SIGNUP, {"email": "x@example.com", "password": "short"})

        assert response.status_code == 400
        assert response.json()["error"]["message"]
        assert await db.scalar(select(User).where(User.email == "x@example.com")) is None

    async def test_the_honeypot_answers_as_though_it_worked(self, client, db):
        """Telling a bot which field caught it only helps the next one."""
        response = await post(
            client,
            SIGNUP,
            {"email": "bot@example.com", "password": PASSWORD, "website": "spam"},
        )

        assert response.status_code == 200
        assert await db.scalar(select(User).where(User.email == "bot@example.com")) is None

    async def test_signup_without_a_csrf_token_is_refused(self, client, db):
        """Ported from the form route this replaced. Without it, any page on
        the internet could create an account in somebody's browser."""
        response = await client.post(
            SIGNUP, json={"email": "drive-by@example.com", "password": PASSWORD}
        )

        assert response.status_code == 403
        assert await db.scalar(select(User).where(User.email == "drive-by@example.com")) is None

    async def test_signup_with_a_mismatched_csrf_token_is_refused(self, client, db):
        await csrf(client)
        response = await client.post(
            SIGNUP,
            json={"email": "drive-by@example.com", "password": PASSWORD},
            headers={"X-CSRF-Token": "not-the-cookie"},
        )

        assert response.status_code == 403
        assert await db.scalar(select(User).where(User.email == "drive-by@example.com")) is None

    async def test_signing_up_while_signed_in_is_refused(self, client, db, user):
        await post(client, LOGIN, {"email": user.email, "password": PASSWORD})

        response = await post(client, SIGNUP, {"email": "other@example.com", "password": PASSWORD})

        assert response.status_code == 409


class TestSigningOut:
    async def test_the_session_is_revoked_and_the_cookie_cleared(self, client, db, user):
        await post(client, LOGIN, {"email": user.email, "password": PASSWORD})
        assert client.cookies.get("weedout_session")

        response = await post(client, LOGOUT, {})

        assert response.status_code == 200
        assert response.json()["data"]["authenticated"] is False
        assert not client.cookies.get("weedout_session")

    async def test_the_revoked_session_no_longer_opens_anything(self, client, db, user):
        await post(client, LOGIN, {"email": user.email, "password": PASSWORD})
        stolen = client.cookies.get("weedout_session")
        await post(client, LOGOUT, {})

        # Signing out must invalidate the token server-side, not merely drop
        # the cookie. Otherwise a copied token outlives the sign-out.
        client.cookies.set("weedout_session", stolen)
        response = await client.get("/api/internal/dashboard")
        assert response.status_code == 401

    async def test_signing_out_without_a_session_is_still_fine(self, client):
        response = await post(client, LOGOUT, {})
        assert response.status_code == 200


class TestRecovery:
    async def test_the_answer_is_the_same_for_known_and_unknown_addresses(self, client, db, user):
        known = await post(client, FORGOT, {"email": user.email})
        unknown = await post(client, FORGOT, {"email": "nobody@example.com"})

        assert known.status_code == unknown.status_code == 200
        assert known.json() == unknown.json()

    async def test_a_malformed_address_also_answers_the_same(self, client):
        """A validation error here would still be a different answer, and a
        different answer is the whole leak."""
        response = await post(client, FORGOT, {"email": "not-an-address"})

        assert response.status_code == 200
        assert response.json()["data"]["sent"] is True

    async def test_an_invalid_reset_token_is_refused(self, client):
        response = await post(
            client, RESET, {"token": "made-up", "password": PASSWORD, "password_confirm": PASSWORD}
        )

        assert response.status_code == 400
        assert response.json()["error"]["code"] in {"INVALID_TOKEN", "INVALID_REQUEST"}

    async def test_a_valid_token_changes_the_password(self, client, db, user):
        from tests.test_password_reset import issue_token

        token, _ = await issue_token(db, user)
        await db.commit()

        response = await post(
            client,
            RESET,
            {
                "token": token,
                "password": "a-brand-new-password",
                "password_confirm": "a-brand-new-password",
            },
        )

        assert response.status_code == 200
        assert response.json()["data"]["reset"] is True

        # The new password works, which is the only proof that matters.
        signed_in = await post(
            client, LOGIN, {"email": user.email, "password": "a-brand-new-password"}
        )
        assert signed_in.status_code == 200

    async def test_completing_a_reset_does_not_sign_you_in(self, client, db, user):
        """Proving control of a mailbox is not proving control of the account,
        and every other session was just revoked. The next step is a normal
        sign-in with the new password."""
        from tests.test_password_reset import issue_token

        token, _ = await issue_token(db, user)
        await db.commit()

        await post(
            client,
            RESET,
            {
                "token": token,
                "password": "a-brand-new-password",
                "password_confirm": "a-brand-new-password",
            },
        )

        assert not client.cookies.get("weedout_session")

    async def test_a_token_cannot_be_used_twice(self, client, db, user):
        from tests.test_password_reset import issue_token

        token, _ = await issue_token(db, user)
        await db.commit()

        first = await post(
            client,
            RESET,
            {
                "token": token,
                "password": "a-brand-new-password",
                "password_confirm": "a-brand-new-password",
            },
        )
        second = await post(
            client,
            RESET,
            {
                "token": token,
                "password": "another-password-here",
                "password_confirm": "another-password-here",
            },
        )

        assert first.status_code == 200
        assert second.status_code == 400

    async def test_a_mistyped_confirmation_is_refused(self, client, db, user):
        """The property the confirmation field exists for. Validated here and
        not only in the browser, because a client can skip its own checks and
        this is the screen where a typo locks somebody out for good."""
        from tests.test_password_reset import issue_token

        token, _ = await issue_token(db, user)
        await db.commit()

        response = await post(
            client,
            RESET,
            {
                "token": token,
                "password": "a-brand-new-password",
                "password_confirm": "a-brand-new-passwrod",
            },
        )

        assert response.status_code == 400
        # And the original password still works, so nothing was half-applied.
        assert (
            await post(client, LOGIN, {"email": user.email, "password": PASSWORD})
        ).status_code == 200
