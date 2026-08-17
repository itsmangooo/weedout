"""Application configuration.

Everything is environment-driven. Local development reads `.env`; production reads
real environment variables. Nothing here has a hardcoded secret default — the
settings that must never be guessable have no default at all, so the process
refuses to boot rather than silently running with a known key.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Explicit algorithm allow-list for every JWT/JWS verification path in the app.
# Never leave this to a library default and never allow "none".
ALLOWED_JWT_ALGORITHMS: list[str] = ["RS256", "ES256"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- Core -------------------------------------------------------------
    environment: Literal["local", "test", "staging", "production"] = "local"
    debug: bool = False
    base_url: str = "http://localhost:8000"
    log_level: str = "INFO"
    log_format: Literal["console", "json"] = "console"

    # Signs the OAuth-state cookie used by Authlib. Session auth does NOT rely
    # on this (sessions are DB-backed opaque tokens), but it still must be secret.
    secret_key: str = Field(min_length=32)

    # ---- Database ---------------------------------------------------------
    database_url: PostgresDsn
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_echo: bool = False

    # ---- Session cookie ---------------------------------------------------
    session_cookie_name: str = "weedout_session"
    session_ttl_hours: int = 24 * 14
    session_cookie_secure: bool | None = None  # defaults to (environment != local)
    session_cookie_samesite: Literal["lax", "strict", "none"] = "lax"

    # ---- Password reset ---------------------------------------------------
    #: Short by design. A reset link is a bearer credential sitting in an
    #: inbox; the window in which a leaked mailbox yields an account takeover
    #: should be measured in minutes, not days.
    password_reset_ttl_minutes: int = 60
    #: Cap on reset emails per account per hour. Without one, the endpoint is a
    #: free mailbox-flooding tool aimed at any address an attacker knows.
    password_reset_max_per_hour: int = 5

    # ---- Outbound feeds ---------------------------------------------------
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    osv_api_url: str = "https://api.osv.dev"
    feed_timeout_seconds: float = 30.0
    feed_user_agent: str = "weedout/0.1 (+https://github.com/weedout-dev)"

    # ---- Local advisory mirror --------------------------------------------
    #: How often the worker re-pulls OSV's ecosystem exports.
    mirror_refresh_hours: int = 12
    #: A scan whose mirror is older than this is served with a warning rather
    #: than silently presented as current.
    mirror_stale_after_hours: int = 48
    mirror_timeout_seconds: float = 300.0
    #: Guards against a malformed or hostile export exhausting memory. npm's
    #: is the largest by a wide margin; this leaves generous headroom.
    mirror_max_bytes: int = 512 * 1024 * 1024

    # ---- Scan API ----------------------------------------------------------
    api_scan_max_bytes: int = 5 * 1024 * 1024
    #: Scans per API key per hour. CI runs on every push, so this is generous
    #: enough not to bite, and low enough to bound a runaway loop.
    api_scan_rate_limit_per_hour: int = 60

    # ---- Background jobs --------------------------------------------------
    # Set false in the web process when running a dedicated worker container.
    run_scheduler_in_web: bool = True
    kev_refresh_hours: int = 6
    scan_tick_minutes: int = 15
    job_max_targets_per_tick: int = 200

    # ---- Email ------------------------------------------------------------
    email_backend: Literal["console", "smtp", "resend"] = "console"
    email_from: str = "Weedout <alerts@weedout.dev>"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True  # STARTTLS on a submission port
    smtp_use_ssl: bool = False  # implicit TLS, usually port 465
    resend_api_key: str | None = None
    resend_api_url: str = "https://api.resend.com/emails"

    # ---- Dodo Payments -----------------------------------------------------
    dodo_enabled: bool = False
    dodo_environment: Literal["test", "live"] = "test"
    #: Server-side only. Never rendered into a page.
    dodo_api_key: str | None = None
    #: Standard Webhooks signing secret, usually prefixed `whsec_`.
    dodo_webhook_secret: str | None = None
    #: The product customers buy for the Pro plan.
    dodo_product_id_pro_monthly: str | None = None

    # ---- GitHub OAuth (wired but optional; enables "Sign in with GitHub") --
    github_client_id: str | None = None
    github_client_secret: str | None = None

    # ---- Administration -----------------------------------------------------
    #: The one account that may reach /admin. Promoted automatically the first
    #: time this address signs in, so there is no "become admin" flow to abuse
    #: and no credential in the codebase. Unset means nobody is auto-promoted;
    #: `python -m app.manage promote-admin <email>` still works.
    admin_email: str | None = None

    #: Link target for actions the panel deliberately does not reimplement
    #: (refunds, disputes, invoice edits).
    dodo_dashboard_url: str = "https://app.dodopayments.com"

    # ---- Limits -----------------------------------------------------------
    max_manifest_bytes: int = 2 * 1024 * 1024

    @field_validator("log_level")
    @classmethod
    def _upper_log_level(cls, v: str) -> str:
        level = v.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"invalid log_level: {v}")
        return level

    @field_validator("base_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @field_validator("admin_email")
    @classmethod
    def _normalize_admin_email(cls, v: str | None) -> str | None:
        """Match the normalisation applied to stored addresses, or the
        comparison at login silently never matches."""
        if v is None:
            return None
        normalized = v.strip().lower()
        return normalized or None

    @model_validator(mode="after")
    def _check_backend_credentials(self) -> Settings:
        if self.email_backend == "smtp" and not self.smtp_host:
            raise ValueError("EMAIL_BACKEND=smtp requires SMTP_HOST")
        if self.email_backend == "resend" and not self.resend_api_key:
            raise ValueError("EMAIL_BACKEND=resend requires RESEND_API_KEY")
        if self.dodo_enabled:
            missing = [
                name
                for name, value in (
                    ("DODO_API_KEY", self.dodo_api_key),
                    ("DODO_WEBHOOK_SECRET", self.dodo_webhook_secret),
                    ("DODO_PRODUCT_ID_PRO_MONTHLY", self.dodo_product_id_pro_monthly),
                )
                if not value
            ]
            if missing:
                # Fail at boot rather than at the first checkout: a billing
                # integration that is half-configured looks fine until money is
                # involved, which is the worst moment to discover it.
                raise ValueError(f"DODO_ENABLED=true requires: {', '.join(missing)}")
        return self

    @property
    def cookie_secure(self) -> bool:
        if self.session_cookie_secure is not None:
            return self.session_cookie_secure
        return self.environment != "local"

    @property
    def github_oauth_configured(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret)

    @property
    def dodo_checkout_base(self) -> str:
        """Dodo's hosted checkout host for the configured environment.

        Test and live are separate hostnames rather than a mode flag, so
        pointing at the wrong one silently charges nobody (or charges someone
        for real). Deriving it from `dodo_environment` keeps that decision in
        one place instead of in a URL somebody pasted into a template.
        """
        if self.dodo_environment == "live":
            return "https://checkout.dodopayments.com"
        return "https://test.checkout.dodopayments.com"

    @property
    def sync_database_url(self) -> str:
        """DSN for synchronous consumers (Alembic).

        The `psycopg` (v3) driver backs both SQLAlchemy's sync and async engines,
        so the same URL works for `create_engine` and `create_async_engine`.
        """
        return str(self.database_url)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
