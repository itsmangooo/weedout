"""Rate limiting on the endpoints an anonymous caller can reach.

These exist because "rate limiting is implemented" and "rate limiting is
enforced" are different claims, and only the second one protects anything. Each
test drives the real HTTP route rather than the service, so a limiter that was
written but never wired in fails here.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from app.config import get_settings
from app.models import RateLimitHit, User, utcnow
from app.security import hash_password
from app.services.rate_limit_service import (
    MAX_RETENTION,
    bucket_for,
    check_rate_limit,
    client_ip,
    purge_expired_rate_limits,
    record_attempt,
)
from tests.conftest import set_csrf

PASSWORD = "correct-horse-battery"


async def attempt_login(client, email="dev@example.com", password="wrong-password"):  # noqa: S107
    csrf = set_csrf(client)
    return await client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": csrf},
    )


class TestLoginRateLimit:
    async def test_repeated_failures_are_eventually_refused(self, client, db, user):
        settings = get_settings()
        limit = settings.login_rate_limit_per_account

        for index in range(limit):
            response = await attempt_login(client)
            assert response.status_code == 401, f"attempt {index} should still be allowed"

        blocked = await attempt_login(client)
        assert blocked.status_code == 429
        assert "Retry-After" in blocked.headers
        assert int(blocked.headers["Retry-After"]) > 0

    async def test_the_message_tells_a_real_person_what_to_do(self, client, db, user):
        for _ in range(get_settings().login_rate_limit_per_account + 1):
            response = await attempt_login(client)

        assert response.status_code == 429
        # Somebody who mistyped their password is going to read this.
        assert "Try again in about" in response.text

    async def test_a_successful_sign_in_is_never_counted(self, client, db, user):
        """A legitimate user must not be throttled by their own logins.

        Counting successes would lock out a shared office address for everyone
        behind it, which turns the protection into the outage.
        """
        for _ in range(get_settings().login_rate_limit_per_account + 3):
            csrf = set_csrf(client)
            response = await client.post(
                "/login",
                data={"email": user.email, "password": PASSWORD, "csrf_token": csrf},
            )
            assert response.status_code == 303

        assert await db.scalar(select(func.count(RateLimitHit.id))) == 0

    async def test_the_check_runs_before_the_password_is_verified(
        self, client, db, user, monkeypatch
    ):
        """The Argon2 verification is the expensive part, and an unlimited
        login endpoint is a memory-exhaustion lever as well as a guessing one.
        A throttled request must not reach the hash at all."""
        import app.services.auth_service as auth_service

        for _ in range(get_settings().login_rate_limit_per_account):
            await attempt_login(client)

        def explode(*args, **kwargs):
            raise AssertionError("verify_password must not run once throttled")

        monkeypatch.setattr(auth_service, "verify_password", explode)

        assert (await attempt_login(client)).status_code == 429

    async def test_a_throttled_account_does_not_block_a_different_one(self, client, db, user):
        """The account bucket must be per-account.

        One person locking themselves out must not take everyone else with
        them — and an attacker must not be able to lock a victim out of their
        own account by choosing to fail against it. The IP bucket is the
        broader backstop; this one has to stay narrow.
        """
        other = User(email="other@example.com", password_hash=hash_password(PASSWORD), tier="free")
        db.add(other)
        await db.flush()

        for _ in range(get_settings().login_rate_limit_per_account + 1):
            await attempt_login(client, email=user.email)

        # Same client, same IP — only the account bucket should be exhausted,
        # and the IP limit is set higher than the account limit for exactly this.
        csrf = set_csrf(client)
        response = await client.post(
            "/login",
            data={"email": other.email, "password": PASSWORD, "csrf_token": csrf},
        )
        assert response.status_code == 303

    async def test_failures_are_recorded_against_both_buckets(self, client, db, user):
        await attempt_login(client)

        buckets = set((await db.scalars(select(RateLimitHit.bucket))).all())
        assert len(buckets) == 2
        assert any(b.startswith("login:ip:") for b in buckets)
        assert any(b.startswith("login:account:") for b in buckets)

    async def test_the_email_is_never_stored_in_the_clear(self, client, db, user):
        """The bucket key must not turn this table into a list of who has an
        account here."""
        await attempt_login(client, email="victim@example.com")

        for (bucket,) in (await db.execute(select(RateLimitHit.bucket))).all():
            assert "victim@example.com" not in bucket
            assert "victim" not in bucket


class TestSignupRateLimit:
    async def _signup(self, client, email):
        csrf = set_csrf(client)
        return await client.post(
            "/signup",
            data={"email": email, "password": "a-long-enough-password", "csrf_token": csrf},
        )

    async def test_mass_account_creation_is_refused(self, client, db):
        limit = get_settings().signup_rate_limit_per_ip

        for index in range(limit):
            response = await self._signup(client, f"user{index}@example.com")
            assert response.status_code == 303, f"signup {index} should be allowed"

        blocked = await self._signup(client, "one-too-many@example.com")
        assert blocked.status_code == 429

    async def test_malformed_submissions_still_count(self, client, db):
        """Otherwise the limit is bypassed by sending garbage: rejected input
        would be free, and only the successful signups would be metered."""
        for _ in range(get_settings().signup_rate_limit_per_ip):
            csrf = set_csrf(client)
            await client.post(
                "/signup", data={"email": "not-an-email", "password": "x", "csrf_token": csrf}
            )

        blocked = await self._signup(client, "real@example.com")
        assert blocked.status_code == 429


class TestPasswordResetRateLimit:
    async def _request_reset(self, client, email="dev@example.com"):
        csrf = set_csrf(client)
        return await client.post("/forgot-password", data={"email": email, "csrf_token": csrf})

    async def test_an_enumeration_sweep_is_refused(self, client, db, user):
        limit = get_settings().password_reset_rate_limit_per_ip

        for index in range(limit):
            response = await self._request_reset(client, f"probe{index}@example.com")
            assert response.status_code == 200, f"request {index} should be allowed"

        assert (await self._request_reset(client, "probe999@example.com")).status_code == 429

    async def test_the_limit_is_keyed_on_ip_not_on_the_address(self, client, db, user):
        """The identical-response guarantee has to survive rate limiting.

        A limit keyed on the submitted address would make the throttle depend
        on how often that specific account had been targeted — which is exactly
        the enumeration oracle the identical wording exists to close.
        """
        assert await db.scalar(select(func.count(RateLimitHit.id))) == 0

        await self._request_reset(client, "known@example.com")
        buckets = list((await db.scalars(select(RateLimitHit.bucket))).all())

        assert len(buckets) == 1
        assert buckets[0].startswith("pwreset:ip:")

    async def test_rate_limiting_did_not_break_the_identical_response(self, client, db, user):
        """Adding a limit must not have introduced a distinguishing branch.

        The page echoes whichever address was submitted, so the responses are
        compared with that one substitution removed — everything else has to
        match byte for byte, exactly as it did before the limit existed.
        """
        registered = await self._request_reset(client, user.email)
        unregistered = await self._request_reset(client, "nobody@example.com")

        assert registered.status_code == 200
        assert unregistered.status_code == 200
        assert registered.text.replace(user.email, "X") == unregistered.text.replace(
            "nobody@example.com", "X"
        )


class TestClientIdentity:
    """Which address a limit is keyed on decides whether it protects anyone."""

    def _request(self, headers: dict, host: str | None = "203.0.113.9"):
        class _Client:
            def __init__(self, h):
                self.host = h

        class _Request:
            def __init__(self):
                self.headers = headers
                self.client = _Client(host) if host else None

        return _Request()

    def test_the_configured_header_is_used(self):
        settings = get_settings().model_copy(
            update={"trusted_client_ip_header": "cf-connecting-ip"}
        )
        request = self._request({"cf-connecting-ip": "198.51.100.7"})

        assert client_ip(request, settings) == "198.51.100.7"

    def test_an_unconfigured_header_is_ignored_even_if_present(self):
        """Trusting a header nobody configured would let anyone spoof a fresh
        bucket per request, which removes the limit rather than loosening it."""
        settings = get_settings().model_copy(update={"trusted_client_ip_header": None})
        request = self._request({"cf-connecting-ip": "1.2.3.4", "x-forwarded-for": "5.6.7.8"})

        assert client_ip(request, settings) == "203.0.113.9"

    def test_a_forwarded_chain_takes_the_originating_client(self):
        settings = get_settings().model_copy(
            update={"trusted_client_ip_header": "cf-connecting-ip"}
        )
        request = self._request({"cf-connecting-ip": "198.51.100.7, 10.0.0.1"})

        assert client_ip(request, settings) == "198.51.100.7"

    def test_an_unidentifiable_caller_shares_one_bucket(self):
        # Falling back to a constant keeps them limited; returning something
        # unique per request would let them out of the limit entirely.
        settings = get_settings().model_copy(update={"trusted_client_ip_header": None})

        assert client_ip(self._request({}, host=None), settings) == "unknown"

    def test_behind_a_proxy_every_visitor_would_otherwise_share_a_bucket(self):
        """The reason this setting exists.

        With the header unread, two different visitors arriving through the
        same tunnel are indistinguishable, and one attacker's failures would
        exhaust the limit for everyone.
        """
        settings = get_settings().model_copy(update={"trusted_client_ip_header": None})
        first = self._request({"cf-connecting-ip": "198.51.100.1"}, host="172.18.0.1")
        second = self._request({"cf-connecting-ip": "198.51.100.2"}, host="172.18.0.1")

        assert client_ip(first, settings) == client_ip(second, settings)

        configured = get_settings().model_copy(
            update={"trusted_client_ip_header": "cf-connecting-ip"}
        )
        assert client_ip(first, configured) != client_ip(second, configured)


class TestBookkeeping:
    async def test_a_window_that_has_passed_no_longer_counts(self, db):
        bucket = bucket_for("login", "ip", "203.0.113.1")
        for _ in range(5):
            await record_attempt(db, bucket)
        await db.flush()

        # Age every hit past the window.
        for hit in (await db.scalars(select(RateLimitHit))).all():
            hit.created_at = utcnow() - timedelta(hours=2)
        await db.flush()

        decision = await check_rate_limit(db, bucket, limit=3, window=timedelta(minutes=15))
        assert decision.allowed is True

    async def test_retry_after_is_measured_from_the_oldest_hit(self, db):
        bucket = bucket_for("login", "ip", "203.0.113.2")
        for _ in range(3):
            await record_attempt(db, bucket)
        await db.flush()

        for hit in (await db.scalars(select(RateLimitHit))).all():
            hit.created_at = utcnow() - timedelta(minutes=10)
        await db.flush()

        decision = await check_rate_limit(db, bucket, limit=3, window=timedelta(minutes=15))
        assert decision.allowed is False
        # Roughly five minutes left, not the full fifteen.
        assert 200 < decision.retry_after_seconds <= 300

    async def test_a_zero_limit_disables_the_check(self, db):
        # Lets an operator switch a limit off without a code change.
        decision = await check_rate_limit(
            db, bucket_for("login", "ip", "x"), limit=0, window=timedelta(minutes=15)
        )
        assert decision.allowed is True

    async def test_old_hits_are_pruned(self, db):
        bucket = bucket_for("login", "ip", "203.0.113.3")
        await record_attempt(db, bucket)
        await record_attempt(db, bucket)
        await db.flush()

        hits = (await db.scalars(select(RateLimitHit))).all()
        hits[0].created_at = utcnow() - MAX_RETENTION - timedelta(hours=1)
        await db.flush()

        removed = await purge_expired_rate_limits(db)
        assert removed == 1
        assert await db.scalar(select(func.count(RateLimitHit.id))) == 1

    async def test_the_sweep_job_prunes_them(self, monkeypatch):
        """The table grows on every failed sign-in, so something has to clear
        it — and that something is the daily job that already exists.

        Asserted by wiring rather than by row count: the task opens its own
        session on its own connection, which cannot see this test's rolled-back
        transaction. What matters here is that the sweep calls the pruner at
        all — `test_old_hits_are_pruned` covers what the pruner then does.
        """
        import app.jobs.tasks as tasks

        called = False

        async def spy(db):
            nonlocal called
            called = True
            return 0

        monkeypatch.setattr(tasks, "purge_expired_rate_limits", spy)
        await tasks.sweep_sessions_task()

        assert called, "sweep_sessions_task must prune rate-limit hits"
