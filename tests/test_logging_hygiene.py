"""What must never reach the log stream.

Logs get shipped to aggregators, retained for months, and read by people who
are not thinking about secrets when they read them. A credential written into
one is a credential with a much longer life and a much wider audience than
anyone intended.
"""

from __future__ import annotations

import logging

from app.logging_config import configure_logging


class TestUvicornAccessLog:
    """The access log is silenced, and that is a security control.

    It logs the full request target *including the query string*, so a
    password-reset visit writes `GET /reset-password?token=<the real token>`
    into the stream in plaintext — a live account-takeover credential handed to
    anyone with log access.
    """

    def test_the_access_logger_is_disabled(self):
        configure_logging("INFO", "console")

        access = logging.getLogger("uvicorn.access")
        # `disabled` and `propagate` are what actually stop the record; the
        # handler list is not asserted on because pytest's own logging plugin
        # attaches capture handlers to every logger while the suite runs.
        # `test_a_record_it_emits_reaches_no_handler` is the behavioural proof.
        assert access.disabled is True
        assert access.propagate is False

    def test_a_record_it_emits_reaches_no_handler(self, caplog):
        configure_logging("INFO", "console")
        access = logging.getLogger("uvicorn.access")

        with caplog.at_level(logging.INFO):
            access.info('%s - "%s %s HTTP/1.1" %d', "1.2.3.4", "GET", "/x?token=SECRET", 200)

        assert "SECRET" not in caplog.text

    def test_the_error_logger_still_works(self):
        """Silencing access logging must not also silence uvicorn's real
        errors — a server that fails to bind should still say so."""
        configure_logging("INFO", "console")

        error = logging.getLogger("uvicorn.error")
        assert error.disabled is False
        assert error.propagate is True


class TestRequestLogging:
    async def test_the_query_string_is_never_logged(self, client, caplog):
        """The app's own request line carries method, path, status and
        duration — everything useful — and deliberately not the query."""
        with caplog.at_level(logging.INFO):
            await client.get("/login?next=/dashboard&token=SHOULD-NOT-APPEAR")

        assert "SHOULD-NOT-APPEAR" not in caplog.text

    async def test_a_password_reset_visit_does_not_log_its_token(self, client, caplog):
        with caplog.at_level(logging.DEBUG):
            await client.get("/reset-password?token=live-token-value-12345")

        assert "live-token-value-12345" not in caplog.text

    async def test_a_submitted_password_is_never_logged(self, client, db, user, caplog):
        from tests.conftest import set_csrf

        csrf = set_csrf(client)
        with caplog.at_level(logging.DEBUG):
            await client.post(
                "/login",
                data={
                    "email": user.email,
                    "password": "hunter2-should-not-appear",
                    "csrf_token": csrf,
                },
            )

        assert "hunter2-should-not-appear" not in caplog.text

    async def test_a_server_error_shows_the_user_nothing_internal(self):
        import httpx
        from fastapi import APIRouter

        from app.main import create_app

        app = create_app()
        router = APIRouter()

        @router.get("/__boom_leak")
        async def boom():
            raise RuntimeError("connection failed for user weedout password s3cr3t")

        app.include_router(router)

        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            for accept in ("text/html", "application/json"):
                response = await c.get("/__boom_leak", headers={"accept": accept})

                assert response.status_code == 500
                for leak in ("s3cr3t", "RuntimeError", "Traceback", "weedout password"):
                    assert leak not in response.text, f"{leak} leaked with accept={accept}"

    async def test_an_api_key_is_never_logged(self, client, caplog):
        with caplog.at_level(logging.DEBUG):
            await client.post(
                "/api/v1/scan",
                files={"manifest": ("package.json", "{}", "application/json")},
                headers={"Authorization": "Bearer wo_secret-key-value-98765"},
            )

        # The rejection is logged, but with `presented=True`, not the token.
        assert "wo_secret-key-value-98765" not in caplog.text
