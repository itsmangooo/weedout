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

    #: Reserved signing key. Nothing signs with it today — application sessions
    #: are database-backed opaque tokens, not signed cookies — and its previous
    #: consumer (Authlib's OAuth state cookie) went away with GitHub sign-in.
    #:
    #: Kept required rather than deleted because it is referenced by every
    #: deployment template and the production validator, and because the first
    #: signed artefact this app grows should not also require a config change on
    #: every environment. Treat it as a real secret: it is validated as one.
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

    # ---- Client identity behind a proxy -----------------------------------
    #: Header carrying the real client IP, or None to trust only the socket.
    #:
    #: This is load-bearing for rate limiting, so it is worth being precise
    #: about. Behind a Cloudflare Tunnel every request arrives from the tunnel
    #: process, so the socket address is the *same for every visitor*: an
    #: IP-keyed limit computed from it would be one global bucket, and the first
    #: brute-force attempt would lock out the whole site.
    #:
    #: `cf-connecting-ip` is the right source there because Cloudflare sets it
    #: at the edge and overwrites any value the client supplied. The danger is
    #: the mirror image: if the app is *not* actually behind the proxy named
    #: here, anyone can spoof this header and rate limiting stops working
    #: entirely. Set it to match the deployment, and to None for a direct bind.
    trusted_client_ip_header: str | None = "cf-connecting-ip"

    # ---- Rate limiting ----------------------------------------------------
    #: Failed sign-ins tolerated per client IP, then per account, in the window.
    #:
    #: Two buckets rather than one because they stop different attacks: the IP
    #: bucket stops one host working through a list of accounts, the account
    #: bucket stops a distributed attack converging on one account. Only
    #: *failures* count, so a legitimate user is never throttled by their own
    #: successful sign-ins, and an office behind one NAT address is not
    #: collectively punished for one person's typo.
    login_rate_limit_per_ip: int = 15
    login_rate_limit_per_account: int = 8
    login_rate_limit_window_minutes: int = 15
    #: Accounts creatable from one IP per hour. Every attempt counts here,
    #: because a successful signup is the thing being abused.
    signup_rate_limit_per_ip: int = 5
    #: Reset requests per IP per hour. `password_reset_max_per_hour` already
    #: caps mail sent to any one address; this caps the endpoint itself, which
    #: is what an address-enumeration sweep hits.
    password_reset_rate_limit_per_ip: int = 10

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

    # ---- Backups ----------------------------------------------------------
    #: Off by default so a development machine does not quietly accumulate
    #: dumps; the production compose file turns it on.
    backup_enabled: bool = False
    backup_interval_hours: int = 24
    #: Where dumps land inside the container. Bind-mount it to survive a
    #: `docker compose down`.
    backup_dir: str = "/var/backups/weedout"
    #: How many local dumps to keep. Old ones are pruned after each run, so the
    #: directory cannot grow without bound and fill the disk the database is on.
    backup_keep: int = 7
    #: Generous: a dump of a large mirror plus gzip takes a while, and a backup
    #: killed halfway is worse than a slow one.
    backup_timeout_seconds: int = 3600

    #: Off-box copy. Optional but strongly recommended — a dump sitting on the
    #: same disk as the database it came from protects against a bad migration
    #: and nothing else. Any S3-compatible endpoint; Cloudflare R2 has no
    #: egress fees. Leaving the bucket unset keeps backups local-only.
    backup_s3_bucket: str | None = None
    backup_s3_endpoint: str | None = None
    backup_s3_access_key_id: str | None = None
    backup_s3_secret_access_key: str | None = None
    backup_s3_prefix: str = "weedout"
    #: R2 ignores the region but SigV4 still has to sign one; "auto" is what
    #: Cloudflare documents.
    backup_s3_region: str = "auto"

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

    #: The provider the in-stack Postfix relay hands mail to.
    #:
    #: The app never uses this — it belongs to the `mail` service — and it is
    #: read here only so that startup can warn when it is empty. Without a
    #: relayhost Postfix delivers straight from the host, and mail from a VPS
    #: address is spam-foldered or rejected without a bounce anyone notices.
    #: The web process is the only thing that prints a configuration summary at
    #: boot, so this is where the warning has to live.
    mail_relayhost: str | None = None

    # ---- Dodo Payments -----------------------------------------------------
    dodo_enabled: bool = False
    dodo_environment: Literal["test", "live"] = "test"
    #: Server-side only. Never rendered into a page.
    dodo_api_key: str | None = None
    #: Standard Webhooks signing secret, usually prefixed `whsec_`.
    dodo_webhook_secret: str | None = None
    #: The product customers buy for the Pro plan.
    dodo_product_id_pro_monthly: str | None = None

    # ---- Administration -----------------------------------------------------
    #: The one account that may reach /admin. Promoted automatically the first
    #: time this address signs in, so there is no "become admin" flow to abuse
    #: and no credential in the codebase. Unset means nobody is auto-promoted;
    #: `python -m app.manage promote-admin <email>` still works.
    admin_email: str | None = None

    #: Where the one-time bootstrap password is sent, if the first admin has to
    #: be created from scratch on deploy.
    #:
    #: Deliberately *not* the admin account's own address: at the moment the
    #: account is created, nobody can sign in to read mail sent to it, and if
    #: `ADMIN_EMAIL` were mistyped the credential would be delivered to whoever
    #: owns the typo. This is the operator's own mailbox.
    #:
    #: No default. Bootstrap is off until this is set, because a default here
    #: would mean a generated password is mailed somewhere nobody chose.
    admin_bootstrap_notify_email: str | None = None

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

    @model_validator(mode="after")
    def _check_production_hardening(self) -> Settings:
        """Refuse to start a production process with development settings.

        Every check here is for something that is *silently* wrong: the app
        boots, serves pages, and looks healthy while a cookie goes out without
        `Secure`, or the whole deployment runs on a secret key published in a
        public example file. None of these announce themselves, so the only
        place to catch them is before the process accepts its first request.

        Deliberately scoped to `production`. Staging and local get to be
        convenient; the environment name is the switch.
        """
        if self.environment != "production":
            return self

        problems: list[str] = []

        if self.debug:
            # Beyond the interactive API docs this exposes, `DEBUG` is the flag
            # people reach for to make errors verbose. It has no business on.
            problems.append("DEBUG must be false in production")

        if _is_placeholder_secret(self.secret_key):
            problems.append(
                "SECRET_KEY looks like a placeholder or is too low-entropy. "
                'Generate one with: python -c "import secrets; '
                'print(secrets.token_urlsafe(48))"'
            )

        if not self.base_url.startswith("https://"):
            # Not cosmetic: an http:// base URL puts password-reset links on
            # plaintext and breaks every Secure cookie the app sets.
            problems.append(f"BASE_URL must be https:// in production (got {self.base_url!r})")

        if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
            problems.append(f"BASE_URL still points at localhost (got {self.base_url!r})")

        if self.session_cookie_secure is False:
            problems.append("SESSION_COOKIE_SECURE=false would send session cookies in the clear")

        if self.db_echo:
            # Echoes every statement, parameters included, into the logs.
            problems.append("DB_ECHO must be false in production")

        if problems:
            raise ValueError(
                "Refusing to start in production with unsafe configuration:\n  - "
                + "\n  - ".join(problems)
            )

        return self

    @property
    def production_warnings(self) -> list[str]:
        """Configuration that is legal but probably not what you want.

        Separate from the hard failures above because each of these has a real
        use during a rollout — deploying before mail is wired up, for
        instance. They are logged loudly at startup instead of blocking it.
        """
        warnings: list[str] = []
        if self.environment != "production":
            return warnings

        if self.email_backend == "console":
            warnings.append(
                "EMAIL_BACKEND=console: no mail is actually sent, so password-reset "
                "links and alert digests silently go nowhere."
            )
        if self.log_level == "DEBUG":
            warnings.append("LOG_LEVEL=DEBUG is very verbose and may log request internals.")
        if self.trusted_client_ip_header is None:
            warnings.append(
                "TRUSTED_CLIENT_IP_HEADER is unset. Behind a proxy every request appears "
                "to come from one address, so IP rate limits become a single shared "
                "bucket. Set it to the header your proxy sets (Cloudflare: cf-connecting-ip)."
            )
        if self.admin_email is None:
            warnings.append(
                "ADMIN_EMAIL is unset; nobody will be auto-promoted to admin. "
                "Use `python -m app.manage promote-admin <email>`."
            )
        if self.email_backend == "smtp" and not self.mail_relayhost:
            warnings.append(
                "MAIL_RELAYHOST is unset, so the mail relay will try to deliver directly "
                "from this host. A VPS address has no sending reputation and most are "
                "blocklisted by default, so password-reset mail will be spam-foldered or "
                "rejected. Point it at a provider — see DEPLOY.md."
            )
        return warnings

    @property
    def cookie_secure(self) -> bool:
        if self.session_cookie_secure is not None:
            return self.session_cookie_secure
        return self.environment != "local"

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


#: Substrings that mark a secret as one somebody never replaced. Matched
#: case-insensitively against the whole value.
_PLACEHOLDER_MARKERS = (
    "change-me",
    "changeme",
    "change_me",
    "placeholder",
    "your-secret",
    "yoursecret",
    "example",
    "local-dev",
    "local-development",
    "not-for-production",
    "insecure",
    "test-key",
    "secret-key-here",
)


def _is_placeholder_secret(value: str) -> bool:
    """Is this secret one that was copied rather than generated?

    Two independent checks, because they catch different mistakes. The marker
    list catches the exact strings shipped in `.env.example` and in this
    repository's compose files — the ones most likely to reach production by
    being copied verbatim. The distinct-character floor catches the other
    common shortcut, a long run of one character or a mashed keyboard row,
    which passes a length check while carrying almost no entropy.

    Not a substitute for generating the key properly. It only has to be good
    enough to catch the values a human would plausibly leave in place.
    """
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    # 48 random urlsafe bytes yield ~40 distinct characters; 16 is a floor low
    # enough never to reject a genuinely random key.
    return len(set(value)) < 16


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
