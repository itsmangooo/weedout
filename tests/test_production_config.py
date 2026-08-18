"""Guardrails that stop a development configuration reaching production.

Every check here is for something *silent*: the app boots, serves pages and
looks healthy while a session cookie goes out without `Secure`, or the whole
deployment runs on the secret key printed in a public example file. Nothing
about the running system announces it, so the only place to catch it is before
the process accepts its first request.

`ENVIRONMENT` is the switch. Local and staging get to be convenient.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings, _is_placeholder_secret

GOOD_SECRET = "Mh0aJ0uAKmg5oCVUM4NHFY3iVXfZWKpQm8jkPFPBFYYzXcYb7tRdW2gLnQ"
DB = "postgresql+psycopg://weedout:weedout@db:5432/weedout"


def build(**overrides) -> Settings:
    """A production settings object with sane values, minus the overrides.

    Every field the suite's own environment sets (see `conftest`) is passed
    explicitly, because those env vars would otherwise bleed in and make these
    tests assert against a configuration nobody wrote.
    """
    base = {
        "environment": "production",
        "debug": False,
        "base_url": "https://weedout.dev",
        "secret_key": GOOD_SECRET,
        "database_url": DB,
        "session_cookie_secure": None,
        "log_level": "INFO",
        "db_echo": False,
        "_env_file": None,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def message_of(exc: pytest.ExceptionInfo) -> str:
    return str(exc.value)


class TestProductionRefusals:
    def test_a_sane_production_config_is_accepted(self):
        settings = build()
        assert settings.environment == "production"
        assert settings.cookie_secure is True

    def test_debug_is_refused(self):
        with pytest.raises(ValidationError) as exc:
            build(debug=True)
        assert "DEBUG must be false" in message_of(exc)

    def test_a_placeholder_secret_key_is_refused(self):
        with pytest.raises(ValidationError) as exc:
            build(secret_key="change-me-to-a-long-random-value-at-least-32-chars")
        assert "SECRET_KEY" in message_of(exc)

    def test_the_committed_compose_default_is_refused(self):
        # The exact string in docker-compose.yml, which is the one most likely
        # to reach production by being copied.
        with pytest.raises(ValidationError) as exc:
            build(secret_key="local-development-secret-key-change-me-please")
        assert "SECRET_KEY" in message_of(exc)

    def test_the_committed_dotenv_default_is_refused(self):
        with pytest.raises(ValidationError) as exc:
            build(secret_key="local-dev-only-secret-key-not-for-production-use-abcdef123456")
        assert "SECRET_KEY" in message_of(exc)

    def test_a_long_but_low_entropy_key_is_refused(self):
        # Passes the 32-character minimum while carrying almost no entropy.
        with pytest.raises(ValidationError) as exc:
            build(secret_key="a" * 64)
        assert "SECRET_KEY" in message_of(exc)

    def test_a_plain_http_base_url_is_refused(self):
        """Not cosmetic: it puts reset links on plaintext and breaks every
        Secure cookie the app sets."""
        with pytest.raises(ValidationError) as exc:
            build(base_url="http://weedout.dev")
        assert "https" in message_of(exc)

    def test_a_localhost_base_url_is_refused(self):
        with pytest.raises(ValidationError) as exc:
            build(base_url="https://localhost:8000")
        assert "localhost" in message_of(exc)

    def test_insecure_cookies_are_refused(self):
        with pytest.raises(ValidationError) as exc:
            build(session_cookie_secure=False)
        assert "SESSION_COOKIE_SECURE" in message_of(exc)

    def test_sql_echo_is_refused(self):
        # Echoes every statement and its bound parameters into the logs.
        with pytest.raises(ValidationError) as exc:
            build(db_echo=True)
        assert "DB_ECHO" in message_of(exc)

    def test_every_problem_is_reported_at_once(self):
        """One round trip per mistake would make fixing this miserable."""
        with pytest.raises(ValidationError) as exc:
            build(debug=True, base_url="http://localhost:8000", db_echo=True)

        text = message_of(exc)
        assert "DEBUG" in text
        assert "BASE_URL" in text
        assert "DB_ECHO" in text


class TestOtherEnvironmentsStayConvenient:
    def test_local_allows_everything_production_refuses(self):
        settings = Settings(
            environment="local",
            debug=True,
            base_url="http://localhost:8000",
            secret_key="local-dev-only-secret-key-not-for-production-use-abcdef",
            database_url=DB,
            db_echo=True,
            session_cookie_secure=None,
            _env_file=None,
        )  # type: ignore[arg-type]
        assert settings.debug is True
        assert settings.cookie_secure is False

    def test_staging_is_not_subject_to_the_production_refusals(self):
        settings = Settings(
            environment="staging",
            debug=True,
            base_url="http://staging.internal:8000",
            secret_key="change-me-please-this-is-staging-only-abcdefghijk",
            database_url=DB,
            session_cookie_secure=None,
            _env_file=None,
        )  # type: ignore[arg-type]
        # Still gets secure cookies, because it is not local.
        assert settings.cookie_secure is True


class TestProductionWarnings:
    """Legal but probably unintended. Announced, not fatal — each has a real
    use during a rollout."""

    def test_console_email_is_warned_about(self):
        warnings = build(email_backend="console").production_warnings
        assert any("EMAIL_BACKEND=console" in w for w in warnings)

    def test_an_unset_proxy_header_is_warned_about(self):
        warnings = build(trusted_client_ip_header=None).production_warnings
        assert any("TRUSTED_CLIENT_IP_HEADER" in w for w in warnings)

    def test_debug_logging_is_warned_about(self):
        warnings = build(log_level="DEBUG").production_warnings
        assert any("LOG_LEVEL=DEBUG" in w for w in warnings)

    def test_a_missing_admin_is_warned_about(self):
        warnings = build(admin_email=None).production_warnings
        assert any("ADMIN_EMAIL" in w for w in warnings)

    def test_a_fully_configured_deployment_warns_about_nothing(self):
        settings = build(
            email_backend="smtp",
            smtp_host="mail",
            # "Fully configured" includes a provider for the relay to hand off
            # to. Without one, mail is sent from the host itself and quietly
            # spam-foldered, which is exactly what the warning list is for.
            mail_relayhost="[smtp.resend.com]:587",
            log_level="INFO",
            trusted_client_ip_header="cf-connecting-ip",
            admin_email="founder@weedout.dev",
        )
        assert settings.production_warnings == []

    def test_warnings_are_silent_outside_production(self):
        settings = Settings(
            environment="local",
            secret_key=GOOD_SECRET,
            database_url=DB,
            email_backend="console",
            _env_file=None,
        )  # type: ignore[arg-type]
        assert settings.production_warnings == []


class TestPlaceholderDetection:
    @pytest.mark.parametrize(
        "value",
        [
            "change-me-to-a-long-random-value-at-least-32-chars",
            "local-development-secret-key-change-me-please",
            "local-dev-only-secret-key-not-for-production-use-abcdef123456",
            "your-secret-key-here-please-replace-this-value",
            "insecure-key-for-testing-only-do-not-use-in-prod",
            "example-secret-key-abcdefghijklmnopqrstuvwxyz",
            "x" * 40,
        ],
    )
    def test_placeholders_are_detected(self, value):
        assert _is_placeholder_secret(value) is True

    @pytest.mark.parametrize(
        "value",
        [
            GOOD_SECRET,
            "8fQ2vXpL9wR4nJ7kT1yB6mZ3cH5dG0sA-uE_iOqW",
            "kM3nP7qR2vX9zB4tY6wL1cJ8hF5dS0gA_eU-iOpQrN",
        ],
    )
    def test_real_keys_are_accepted(self, value):
        assert _is_placeholder_secret(value) is False


class TestMailWiring:
    """The stack ships its own SMTP relay; these check it is wired up and that
    the ways it can be silently wrong are announced."""

    def test_a_missing_relay_provider_is_warned_about(self):
        """An unset relayhost means Postfix tries to deliver from the host
        itself, which is spam-foldered or rejected without a bounce anyone
        notices. Legal, so it warns rather than refusing."""
        warnings = build(email_backend="smtp", smtp_host="mail", mail_relayhost=None)
        assert any("MAIL_RELAYHOST" in w for w in warnings.production_warnings)

    def test_a_configured_relay_warns_about_nothing(self):
        warnings = build(
            email_backend="smtp",
            smtp_host="mail",
            mail_relayhost="[smtp.resend.com]:587",
            admin_email="founder@weedout.dev",
            trusted_client_ip_header="cf-connecting-ip",
            log_level="INFO",
        ).production_warnings
        assert warnings == []

    def test_the_resend_backend_does_not_warn_about_a_relay_it_does_not_use(self):
        """`EMAIL_BACKEND=resend` bypasses the relay entirely, so a warning
        about the relay's configuration would be noise."""
        warnings = build(
            email_backend="resend", resend_api_key="re_x", mail_relayhost=None
        ).production_warnings
        assert not any("MAIL_RELAYHOST" in w for w in warnings)


class TestComposeMailService:
    """Assertions against the compose files themselves.

    The relay is infrastructure rather than code, so the things that make it
    safe — no published port, a persisted queue, a pinned image — are only
    checkable here.
    """

    def _prod(self) -> str:
        path = Path(__file__).resolve().parents[1] / "docker-compose.prod.yml"
        if not path.is_file():
            pytest.skip("repo root not present (running inside the app image)")
        return path.read_text(encoding="utf-8")

    def _parsed(self) -> dict:
        import yaml

        return yaml.safe_load(self._prod())

    def test_the_relay_is_part_of_the_stack(self):
        assert "mail" in self._parsed()["services"]

    def test_the_app_points_at_the_relay_by_default(self):
        prod = self._prod()
        assert "SMTP_HOST: ${SMTP_HOST:-mail}" in prod
        assert "EMAIL_BACKEND: ${EMAIL_BACKEND:-smtp}" in prod

    def test_the_relay_publishes_no_port(self):
        """Anything reachable from outside the Compose network is a relay
        somebody else can use."""
        assert "ports" not in self._parsed()["services"]["mail"]

    def test_the_relay_refuses_unknown_sender_domains(self):
        """Without this the relay would forward for any sender, which is the
        definition of an open relay."""
        env = self._parsed()["services"]["mail"]["environment"]
        assert "ALLOWED_SENDER_DOMAINS" in env

    def test_the_queue_is_persisted(self):
        """The queue is the reason for running this at all. Losing it on a
        container replacement discards mail Postfix promised to retry."""
        volumes = self._parsed()["services"]["mail"]["volumes"]
        assert any("/var/spool/postfix" in v for v in volumes)
        assert "mailqueue" in self._parsed()["volumes"]

    def test_the_image_is_pinned(self):
        """It handles credentials and queued mail; it should change when you
        decide to, not when a tag moves."""
        image = self._parsed()["services"]["mail"]["image"]
        assert ":" in image
        assert not image.endswith(":latest")

    def test_credentials_are_not_sent_in_the_clear(self):
        env = self._parsed()["services"]["mail"]["environment"]
        assert "encrypt" in env["RELAYHOST_TLS_LEVEL"]

    def test_the_app_waits_for_the_relay(self):
        services = self._parsed()["services"]
        assert "mail" in services["web"]["depends_on"]
        assert "mail" in services["worker"]["depends_on"]


class TestLocalMailCatcher:
    def _dev(self) -> dict:
        import yaml

        path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
        if not path.is_file():
            pytest.skip("repo root not present (running inside the app image)")
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    def test_a_mail_catcher_is_available_locally(self):
        """Needed to exercise the admin bootstrap at all: it refuses the console
        backend, because that one delivers by writing the body to the log."""
        assert "mailpit" in self._dev()["services"]

    def test_it_does_not_start_with_a_plain_compose_up(self):
        """`docker compose up` should be unchanged for anyone who does not want
        it — hence the profile."""
        assert self._dev()["services"]["mailpit"]["profiles"] == ["mail"]

    def test_development_still_defaults_to_the_console_backend(self):
        """So no test message can escape to a real address by accident."""
        dev = self._dev()["services"]
        assert dev["web"]["environment"]["EMAIL_BACKEND"] == "console"
        assert dev["worker"]["environment"]["EMAIL_BACKEND"] == "console"
