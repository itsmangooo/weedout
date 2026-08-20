"""ORM models.

Shape of the domain:

    User ──< TrackedTarget ──< Dependency
                  │
                  ├──< ScanRun
                  └──< CVEMatch ──> VulnerabilityRecord
                            │
                            └──< Alert

`CVEMatch` is *state* — the standing fact that a target is affected, with a
status the user controls. `Alert` is *delivery history* — a record that we told
someone. Keeping them apart is what lets a match be re-opened, or dismissed
without erasing the evidence that a notification went out.

`VulnerabilityRecord` and `KevRecord` are local caches of upstream feeds, so a
scan does not depend on OSV and CISA both being reachable at the same moment.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    case,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.supply_chain import SignalKind, SignalLevel
from app.core.types import (
    ActionableReason,
    AlertStatus,
    AudienceKind,
    ContactCategory,
    Ecosystem,
    EmailStatus,
    EmailTrigger,
    ManifestKind,
    MessageStatus,
    Reachability,
    Severity,
    SuppressionReason,
    Tier,
    Verdict,
)
from app.db import Base, enum_column


def utcnow() -> datetime:
    return datetime.now(UTC)


TZDateTime = DateTime(timezone=True)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, server_default=func.now(), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        TZDateTime,
        nullable=False,
        server_default=func.now(),
        default=utcnow,
        onupdate=utcnow,
    )


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: Stored lower-cased; the unique index is therefore case-insensitive in
    #: practice, which is what users expect from an email address.
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)

    #: Nullable, though nothing currently creates an account without a
    #: password. `verify_password` treats a null hash as a failed attempt and
    #: still burns a dummy verification, so the column staying nullable costs
    #: nothing and does not become a way in.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    tier: Mapped[Tier] = mapped_column(
        enum_column(Tier, "tier"), nullable=False, default=Tier.FREE, server_default=Tier.FREE.value
    )

    #: System-level flag: the account exists and is usable. Reserved for
    #: programmatic deactivation (soft delete, bounced-email lockout).
    #: Administrators do NOT toggle this — see `is_suspended`.
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    #: Administrator moderation action, deliberately separate from `is_active`
    #: so the two never have to be disambiguated after the fact: this one always
    #: means "a human suspended this account", and it carries when and why.
    #: Reversible by design — suspending never deletes anything.
    is_suspended: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false", index=True
    )
    suspended_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    suspension_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    #: The single super-admin flag. Deliberately a boolean rather than a role
    #: table: there is exactly one admin, and a permission system for one
    #: principal is machinery with nothing to manage.
    is_admin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false", index=True
    )

    email_alerts_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    # --- Dodo Payments billing ---
    dodo_customer_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    dodo_subscription_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    subscription_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subscription_ends_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    #: Recurring amount in the currency's minor unit, captured from the webhook.
    #: Stored so the admin revenue snapshot is a sum over this column rather
    #: than a fan-out of live API calls every time the page is opened.
    subscription_amount_cents: Mapped[int | None] = mapped_column(Integer, nullable=True)
    subscription_currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    dodo_product_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: Billing cadence as the provider reports it ("month" / "year"), needed to
    #: normalise annual plans when computing MRR.
    subscription_interval: Mapped[str | None] = mapped_column(String(16), nullable=True)

    last_login_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    #: Base32 TOTP shared secret. Present as soon as setup begins, which is not
    #: the same as 2FA being on — `totp_confirmed_at` is what gates the login
    #: flow. Keeping them separate means an abandoned setup cannot lock anyone
    #: out of their own account.
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_confirmed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    #: The last TOTP counter accepted for this user. A code stays valid for its
    #: whole 30-second step, so without this the same six digits can be
    #: replayed until the step rolls over.
    totp_last_counter: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    @property
    def two_factor_enabled(self) -> bool:
        return self.totp_confirmed_at is not None

    targets: Mapped[list[TrackedTarget]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    backup_codes: Mapped[list[BackupCode]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    sessions: Mapped[list[Session]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def can_sign_in(self) -> bool:
        """The single authority on whether this account may authenticate.

        Both gates live here so no caller has to remember that there are two.
        Every auth path — password login, session resolution, API key —
        must consult this rather than testing the flags individually.
        """
        return self.is_active and not self.is_suspended

    @property
    def status_label(self) -> str:
        if self.is_suspended:
            return "Suspended"
        if not self.is_active:
            return "Inactive"
        return "Active"

    @property
    def monthly_value_cents(self) -> int:
        """This subscription's contribution to MRR, normalised to a month.

        Annual plans are divided by twelve so a yearly subscriber does not
        appear as twelve months of revenue in a single month.
        """
        if not self.subscription_amount_cents:
            return 0
        if self.subscription_interval == "year":
            return round(self.subscription_amount_cents / 12)
        return self.subscription_amount_cents

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r} tier={self.tier}>"


class PasswordResetToken(Base):
    """A single-use, time-limited token for resetting a forgotten password.

    Modelled on `Session`, and for the same reason: the emailed token is a
    bearer credential, so only its SHA-256 hash is stored. A database leak
    yields hashes, not working reset links.

    Three independent conditions must all hold for a token to be usable —
    unexpired, unused, and belonging to an account that may sign in. They are
    checked together in `is_usable` so no caller can test two of the three and
    believe it has validated the token.
    """

    __tablename__ = "password_reset_tokens"
    __table_args__ = (Index("ix_password_reset_tokens_user_created", "user_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, server_default=func.now(), default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, index=True)
    #: Set the moment the token is spent. Non-null means never usable again.
    used_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    requested_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user: Mapped[User] = relationship()

    @property
    def is_expired(self) -> bool:
        return self.expires_at <= utcnow()

    @property
    def is_usable(self) -> bool:
        return self.used_at is None and not self.is_expired

    def __repr__(self) -> str:
        return f"<PasswordResetToken user_id={self.user_id} used={self.used_at is not None}>"


class ApiKey(Base):
    """A machine credential for the scan API.

    Scoped to one `TrackedTarget`, not to the account: a key leaked from a CI
    runner should be able to push results for the one project that runner
    builds, not for everything the owner tracks. It also means the upload has
    an unambiguous destination without the client naming a project.

    Stored as a SHA-256 hash of a high-entropy token, like sessions and reset
    links. The plaintext exists once, in the response that creates it.
    `prefix` is the first few characters, kept in clear so the UI can show
    *which* key a row refers to without being able to reconstruct it.
    """

    __tablename__ = "api_keys"
    __table_args__ = (Index("ix_api_keys_target_active", "target_id", "revoked_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("tracked_targets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    #: Display-only fragment, e.g. "wo_live_9f3a". Never enough to authenticate.
    prefix: Mapped[str] = mapped_column(String(24), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False, default="", server_default="")

    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, server_default=func.now(), default=utcnow
    )
    #: Throttled to one write per minute; an exact timestamp is not worth a
    #: database write on every CI run.
    last_used_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    #: Total authenticated calls. Incremented on the same statement that stamps
    #: `last_used_at`, so the two can never disagree about whether a key has
    #: ever been used.
    call_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    revoked_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    user: Mapped[User] = relationship()
    target: Mapped[TrackedTarget] = relationship(back_populates="api_keys")

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    def __repr__(self) -> str:
        return f"<ApiKey {self.prefix} target={self.target_id} active={self.is_active}>"


class Session(Base):
    """A server-side login session.

    The cookie carries a random opaque token; only its SHA-256 hash is stored,
    so a database leak does not hand out live sessions. Validation is a row
    lookup on every request, which is precisely what makes logout and remote
    revocation take effect immediately — the property a self-contained JWT
    cannot offer.
    """

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, server_default=func.now(), default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, server_default=func.now(), default=utcnow
    )
    revoked_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")

    @property
    def is_valid(self) -> bool:
        return self.revoked_at is None and self.expires_at > utcnow()


class BackupCode(Base):
    """One single-use recovery code for an account with 2FA on.

    Only the hash is stored, and a used code is marked rather than deleted so
    the Settings page can honestly show how many are left without implying the
    used ones might still work.
    """

    __tablename__ = "backup_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, server_default=func.now(), default=utcnow
    )
    used_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="backup_codes")

    @property
    def is_used(self) -> bool:
        return self.used_at is not None


# ---------------------------------------------------------------------------
# Tracked targets and their dependencies
# ---------------------------------------------------------------------------


class TrackedTarget(TimestampMixin, Base):
    """A manifest a user wants watched.

    The raw manifest text is retained so a re-scan does not require the user to
    re-upload, and so a parser improvement can be applied retroactively.
    """

    __tablename__ = "tracked_targets"
    __table_args__ = (Index("ix_tracked_targets_scan_queue", "is_active", "next_scan_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)

    #: Null until a manifest arrives. A project can be created with a name and
    #: an ecosystem alone, so that an API key can be issued for it and CI can
    #: push the first scan — the file does not have to come first.
    manifest_kind: Mapped[ManifestKind | None] = mapped_column(
        enum_column(ManifestKind, "manifest_kind"), nullable=True
    )
    #: Chosen at creation and never inferred away. An uploaded file whose
    #: ecosystem disagrees is refused rather than silently reinterpreting every
    #: finding already recorded against this project.
    ecosystem: Mapped[Ecosystem] = mapped_column(
        enum_column(Ecosystem, "ecosystem"), nullable=False
    )

    #: Reserved for repository auto-sync, which is not built. Unrelated to
    #: sign-in; uploads and CLI scans both leave it null.
    repo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    manifest_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: SHA-256 of the manifest, so a re-upload of identical content is a no-op.
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    dependency_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    parse_warnings: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    last_scanned_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    next_scan_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True, index=True)
    last_scan_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Severity floor for a direct dependency, overriding the default. Null
    #: means "use the default", which is what every project starts with and
    #: what a Free project always has.
    direct_threshold: Mapped[Severity | None] = mapped_column(
        enum_column(Severity, "severity"), nullable=True
    )
    #: The same for a dependency further down the tree.
    transitive_threshold: Mapped[Severity | None] = mapped_column(
        enum_column(Severity, "severity"), nullable=True
    )

    #: Alert when EPSS is at or above this, or null to never gate on it.
    #:
    #: Null by default and for everybody until asked. EPSS is re-scored daily,
    #: and a finding drifting over a threshold overnight would interrupt
    #: somebody because a model moved rather than because a vulnerability did.
    epss_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)

    #: The `.weedout.yml` most recently pushed with a scan.
    #:
    #: Stored rather than read from disk because the server never sees the
    #: repository -- only the manifest that was uploaded. The CLI sends this
    #: alongside it, which is also what makes CI the source of truth: the file
    #: that ran in the pipeline is the file that applied.
    policy_file: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_file_updated_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    #: Anything wrong with it, from the last parse. Shown on the project rather
    #: than swallowed: a policy file that failed to parse silently reverts every
    #: rule in it, and the author needs to know that happened.
    policy_file_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: How many packages the last scan did not reach, because the owner's plan
    #: stops at a given depth.
    #:
    #: Shown rather than kept quiet. A project whose deepest dependencies were
    #: never examined must not read as "nothing found" -- that is the same
    #: distinction the CLI draws between exit 1 and exit 2, and the number is
    #: also the only honest way to show what a deeper plan would buy.
    unreached_by_depth: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    #: Which shape the destination expects: a Discord embed, or plain JSON to
    #: somebody's own endpoint. Stored rather than sniffed from the URL, because
    #: guessing from a hostname is how a custom endpoint that happens to be
    #: proxied through Discord's domain gets the wrong body.
    webhook_kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default="discord", server_default="discord"
    )

    #: The destination, per project rather than per account.
    #:
    #: A webhook URL addresses one channel, and somebody tracking six projects
    #: wants six channels rather than one firehose. It is also a credential --
    #: anyone holding it can post to that channel -- so it is written once and
    #: never rendered back in full; `app.core.discord.mask_webhook_url` is what
    #: the settings page shows.
    discord_webhook_url: Mapped[str | None] = mapped_column(String(300), nullable=True)

    #: Set on the last successful post, so the settings page can say when this
    #: channel last actually heard from us rather than only that a URL is saved.
    discord_last_sent_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    #: Why the last attempt failed, or null. Kept so a webhook Discord has since
    #: deleted shows as broken on the page instead of silently never arriving.
    discord_last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped[User] = relationship(back_populates="targets")
    dependencies: Mapped[list[DependencyRecord]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )
    matches: Mapped[list[CVEMatch]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )
    scan_runs: Mapped[list[ScanRun]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )
    api_keys: Mapped[list[ApiKey]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )
    ignore_rules: Mapped[list[IgnoreRule]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )
    supply_chain_findings: Mapped[list[SupplyChainFinding]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def has_manifest(self) -> bool:
        """Has anything been uploaded or pushed for this project yet?"""
        return bool(self.manifest_content)

    @property
    def has_webhook(self) -> bool:
        return bool(self.discord_webhook_url)

    @property
    def has_been_scanned(self) -> bool:
        """Distinct from `has_manifest`.

        A manifest can be present and unscanned — the first scan runs inline and
        can fail, for instance against an empty advisory mirror. Conflating the
        two would report "no findings" for a project that was never checked,
        which is the reassuring-but-false answer this product exists to avoid.
        """
        return self.last_scanned_at is not None

    @property
    def status_label(self) -> str:
        """One phrase for where this project is in its lifecycle."""
        if not self.has_manifest:
            return "No manifest yet"
        if not self.has_been_scanned:
            return "Not scanned yet"
        if self.last_scan_error:
            return "Last check failed"
        return "Watching"

    def __repr__(self) -> str:
        return f"<TrackedTarget id={self.id} name={self.name!r}>"


class DependencyRecord(Base):
    """One resolved dependency of a target, as of the last parse."""

    __tablename__ = "dependencies"
    __table_args__ = (
        UniqueConstraint("target_id", "name", "version", name="uq_dependency_target_name_version"),
        Index("ix_dependencies_lookup", "ecosystem", "name", "version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("tracked_targets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    ecosystem: Mapped[Ecosystem] = mapped_column(
        enum_column(Ecosystem, "ecosystem"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    version: Mapped[str] = mapped_column(String(120), nullable=False)
    version_spec: Mapped[str] = mapped_column(String(200), nullable=False)
    reachability: Mapped[Reachability] = mapped_column(
        enum_column(Reachability, "reachability"), nullable=False
    )
    #: False when `version` was inferred from a range rather than observed.
    version_exact: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    #: Distance from the project. 0 is declared in the manifest.
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")

    #: The path from the project to this package, excluding it. Stored so a
    #: finding can say how the package got in, which is the difference between
    #: "upgrade this" and "upgrade the thing that asked for it".
    via: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list, server_default="[]")

    target: Mapped[TrackedTarget] = relationship(back_populates="dependencies")

    def __repr__(self) -> str:
        return f"<Dependency {self.name}@{self.version}>"


# ---------------------------------------------------------------------------
# Cached upstream feed data
# ---------------------------------------------------------------------------


class VulnerabilityRecord(TimestampMixin, Base):
    """A cached OSV advisory, normalised at write time.

    Advisory details are fetched once and reused across every user and every
    scan. Without this cache a nightly sweep would re-download the same few
    thousand records repeatedly.
    """

    __tablename__ = "vulnerabilities"

    #: The OSV identifier, e.g. "GHSA-jf85-cpcp-j695" or "GO-2022-0322".
    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    aliases: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    #: Denormalised from `aliases` for indexed KEV cross-referencing.
    cve_ids: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    summary: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    details: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")

    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity, "severity"),
        nullable=False,
        default=Severity.UNKNOWN,
        server_default=Severity.UNKNOWN.value,
    )
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)

    #: The OSV `affected` array, kept whole so version matching can be re-run
    #: locally without another network round trip.
    affected: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    references: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    #: CWE identifiers ("CWE-79"), where the publisher classifies the weakness.
    #: Useful for grouping "what kind of bug is this" across advisories.
    cwe_ids: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    withdrawn: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    published: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    modified: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now()
    )

    affected_packages: Mapped[list[VulnerabilityAffected]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan", passive_deletes=True
    )

    def __repr__(self) -> str:
        return f"<VulnerabilityRecord {self.id} severity={self.severity}>"


class VulnerabilityAffected(Base):
    """Which packages an advisory affects — one row per (advisory, package).

    This is the index that makes the local mirror usable. `VulnerabilityRecord`
    already stores the whole OSV `affected` array as JSONB, but "find every
    advisory touching lodash on npm" cannot be answered from that without
    scanning the table. A scan of a 400-dependency manifest asks that question
    400 times, so it needs to be a plain indexed lookup.

    Version ranges deliberately stay in the JSONB blob rather than being
    normalised here: range semantics differ per ecosystem and are already
    implemented in `app.core.versions`. Splitting them across SQL and Python
    would mean two places that must agree about what "affected" means.
    """

    __tablename__ = "vulnerability_affected"
    __table_args__ = (
        UniqueConstraint(
            "vulnerability_id", "ecosystem", "package_name", name="uq_vuln_affected_identity"
        ),
        # The lookup the scan pipeline performs, once per dependency.
        Index("ix_vuln_affected_lookup", "ecosystem", "package_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ecosystem: Mapped[Ecosystem] = mapped_column(
        enum_column(Ecosystem, "ecosystem"), nullable=False
    )
    #: Stored lower-cased so the lookup is a plain equality match rather than a
    #: case-insensitive scan; npm and PyPI both treat names case-insensitively.
    package_name: Mapped[str] = mapped_column(String(300), nullable=False)

    vulnerability: Mapped[VulnerabilityRecord] = relationship(back_populates="affected_packages")

    def __repr__(self) -> str:
        return (
            f"<VulnerabilityAffected {self.ecosystem}:{self.package_name} {self.vulnerability_id}>"
        )


class KevRecord(TimestampMixin, Base):
    """One row of the CISA Known Exploited Vulnerabilities catalog."""

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(
        String(200), nullable=False, default="", server_default=""
    )
    product: Mapped[str] = mapped_column(String(200), nullable=False, default="", server_default="")
    vulnerability_name: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=""
    )
    short_description: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=""
    )
    required_action: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=""
    )
    date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    known_ransomware_use: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    def __repr__(self) -> str:
        return f"<KevRecord {self.cve_id}>"


class EpssScore(Base):
    """FIRST's modelled probability that a CVE will be exploited.

    Its own table rather than a column on `vulnerabilities`, for two reasons.
    EPSS is keyed on CVE and an advisory can carry several; and the whole set is
    re-scored daily, which as an upsert against a 260,000-row advisory table
    would rewrite far more than it changes.
    """

    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)

    #: Probability of exploitation in the next 30 days, 0.0 to 1.0.
    score: Mapped[float] = mapped_column(Float, nullable=False)
    #: Where it sits against every other scored CVE.
    percentile: Mapped[float] = mapped_column(Float, nullable=False)

    #: The day FIRST scored it, which is not the day we fetched it. Worth
    #: keeping both: a stale mirror and a stale model are different problems.
    scored_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<EpssScore {self.cve_id} {self.score:.5f}>"


class FeedSync(Base):
    """When each upstream feed was last pulled, and whether it worked.

    Lets the UI say "KEV data is 4 hours old" rather than implying freshness it
    cannot vouch for, and stops the scheduler from re-pulling on every tick.
    """

    __tablename__ = "feed_syncs"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_success_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    record_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    catalog_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def is_stale(self, max_age: timedelta) -> bool:
        if self.last_success_at is None:
            return True
        return utcnow() - self.last_success_at > max_age


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class CVEMatch(TimestampMixin, Base):
    """A vulnerability affecting a tracked target.

    Rows are keyed on (target, package, version, advisory) so a finding keeps a
    stable identity across scans: `first_seen_at` survives, a dismissal sticks,
    and re-alerting on something the user already handled cannot happen.

    Suppressed matches are stored alongside actionable ones. That is deliberate
    — the count of advisories deliberately not shown is the product's core
    claim, and a claim the user cannot inspect is a claim they have to take on
    trust.
    """

    __tablename__ = "cve_matches"
    __table_args__ = (
        UniqueConstraint(
            "target_id",
            "package_name",
            "package_version",
            "vulnerability_id",
            name="uq_cve_match_identity",
        ),
        Index("ix_cve_matches_open", "target_id", "verdict", "status"),
        CheckConstraint(
            "(verdict = 'actionable' AND actionable_reason IS NOT NULL) "
            "OR (verdict = 'suppressed' AND suppression_reason IS NOT NULL)",
            name="verdict_has_a_reason",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("tracked_targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # The affected dependency is denormalised rather than referenced, so a
    # finding survives the dependency row being replaced by a re-parse.
    ecosystem: Mapped[Ecosystem] = mapped_column(
        enum_column(Ecosystem, "ecosystem"), nullable=False
    )
    package_name: Mapped[str] = mapped_column(String(300), nullable=False)
    package_version: Mapped[str] = mapped_column(String(120), nullable=False)
    version_spec: Mapped[str] = mapped_column(
        String(200), nullable=False, default="", server_default=""
    )
    version_exact: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    reachability: Mapped[Reachability] = mapped_column(
        enum_column(Reachability, "reachability"), nullable=False
    )

    #: EPSS at the time of the scan, for the CVE this advisory carries.
    #:
    #: A snapshot, not a live value: it is what the finding was scored at when
    #: it was last seen, so a row that has not been re-scanned does not silently
    #: change its story. Null when the CVE is unscored, which is most of them.
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)

    #: True when an ignore rule covered this and it was raised anyway, because
    #: the advisory is now on CISA's known-exploited list. Stored rather than
    #: derived: the rule can be deleted afterwards, and the finding still has to
    #: be able to explain itself.
    ignore_overridden: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    #: Denormalised alongside the package name and for the same reason: a
    #: finding has to keep saying how the package got into the tree even after
    #: the dependency rows are replaced by the next parse.
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    via: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list, server_default="[]")

    verdict: Mapped[Verdict] = mapped_column(
        enum_column(Verdict, "verdict"), nullable=False, index=True
    )
    severity: Mapped[Severity] = mapped_column(enum_column(Severity, "severity"), nullable=False)
    is_kev: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false", index=True
    )
    fixed_version: Mapped[str | None] = mapped_column(String(120), nullable=True)

    actionable_reason: Mapped[ActionableReason | None] = mapped_column(
        enum_column(ActionableReason, "actionable_reason"), nullable=True
    )
    suppression_reason: Mapped[SuppressionReason | None] = mapped_column(
        enum_column(SuppressionReason, "suppression_reason"), nullable=True
    )

    status: Mapped[AlertStatus] = mapped_column(
        enum_column(AlertStatus, "alert_status"),
        nullable=False,
        default=AlertStatus.OPEN,
        server_default=AlertStatus.OPEN.value,
        index=True,
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    dismissed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    dismiss_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    #: Set once an email has gone out, so re-scans do not re-notify.
    notified_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    target: Mapped[TrackedTarget] = relationship(back_populates="matches")
    vulnerability: Mapped[VulnerabilityRecord] = relationship(lazy="joined")
    alerts: Mapped[list[Alert]] = relationship(
        back_populates="match", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def chain_label(self) -> str:
        """`express -> body-parser -> qs`, or the package alone if direct."""
        return " → ".join([*(self.via or []), self.package_name])

    @property
    def is_direct(self) -> bool:
        return not self.via

    def __repr__(self) -> str:
        return f"<CVEMatch {self.package_name}@{self.package_version} {self.vulnerability_id}>"


class SupplyChainFinding(Base):
    """An observation about a package that is not a vulnerability in it.

    Its own table rather than a `CVEMatch` with a special verdict, because it
    is a different kind of statement. A match says "this version is affected by
    that advisory" and is keyed on the pair; this says "depending on this
    package is worth a second look" and is keyed on the package alone. Folding
    them together would mean every query about vulnerabilities had to remember
    to exclude the things that are not vulnerabilities.

    The level scale is separate too, and deliberately does not share words with
    `Severity`. A single-maintainer package is not a "medium vulnerability".
    """

    __tablename__ = "supply_chain_findings"
    __table_args__ = (
        UniqueConstraint("target_id", "package_name", "kind", name="uq_supply_chain_identity"),
        Index("ix_supply_chain_open", "target_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("tracked_targets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    ecosystem: Mapped[Ecosystem] = mapped_column(
        enum_column(Ecosystem, "ecosystem"), nullable=False
    )
    package_name: Mapped[str] = mapped_column(String(300), nullable=False)
    package_version: Mapped[str] = mapped_column(String(120), nullable=False, default="")

    kind: Mapped[SignalKind] = mapped_column(enum_column(SignalKind, "signal_kind"), nullable=False)
    level: Mapped[SignalLevel] = mapped_column(
        enum_column(SignalLevel, "signal_level"), nullable=False
    )

    #: A whole sentence, written when the signal was raised. Stored rather than
    #: rebuilt at render time so it cannot drift from the data that produced it.
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: The specifics, for the interface: which package it resembles, how old the
    #: last release is, and so on.
    data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    #: Reuses AlertStatus so "dismiss" means the same thing here as on a
    #: finding. A dismissal survives re-scans, which is the whole point: being
    #: told twice that you chose this package on purpose is how a signal gets
    #: switched off entirely.
    status: Mapped[AlertStatus] = mapped_column(
        enum_column(AlertStatus, "alert_status"),
        nullable=False,
        default=AlertStatus.OPEN,
        server_default=AlertStatus.OPEN.value,
    )
    dismiss_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now()
    )

    target: Mapped[TrackedTarget] = relationship(back_populates="supply_chain_findings")

    def __repr__(self) -> str:
        return f"<SupplyChainFinding {self.kind} {self.package_name}>"


class ScanRun(Base):
    """One execution of the scan pipeline against one target."""

    __tablename__ = "scan_runs"
    __table_args__ = (Index("ix_scan_runs_target_started", "target_id", "started_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("tracked_targets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    started_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    #: "running" | "success" | "failed"
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")

    dependencies_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actionable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suppressed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_actionable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resolved_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    target: Mapped[TrackedTarget] = relationship(back_populates="scan_runs")

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()


class Alert(Base):
    """A notification that was (or failed to be) delivered for a match."""

    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_user_created", "user_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    match_id: Mapped[int] = mapped_column(
        ForeignKey("cve_matches.id", ondelete="CASCADE"), nullable=False, index=True
    )

    #: "email" today; "slack"/"discord" once webhooks land.
    channel: Mapped[str] = mapped_column(String(32), nullable=False, default="email")
    destination: Mapped[str] = mapped_column(String(320), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False, default="")

    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    sent_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    #: "pending" | "sent" | "failed"
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    match: Mapped[CVEMatch] = relationship(back_populates="alerts")

    def __repr__(self) -> str:
        return f"<Alert id={self.id} channel={self.channel} status={self.status}>"


class DocPage(TimestampMixin, Base):
    """A documentation page, authored by the administrator in Markdown.

    A deliberately small CMS: a slug, a title, a body and a published flag.
    Anything more — revisions, drafts with previews, per-page permissions — is
    machinery for a team, and there is one author.

    Markdown is stored as written and rendered on read. Storing rendered HTML
    instead would mean a change to the renderer silently applied only to pages
    edited afterwards, leaving old pages frozen in an older output format.
    """

    __tablename__ = "doc_pages"
    __table_args__ = (Index("ix_doc_pages_published_position", "published", "position"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: URL segment. Lower-case, hyphenated, unique.
    slug: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    #: One-line description for the index page and meta tags.
    summary: Mapped[str] = mapped_column(String(300), nullable=False, default="", server_default="")
    content: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")

    #: Unpublished pages are invisible to everyone except an administrator,
    #: who reaches them through the admin panel rather than the public URL.
    published: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false", index=True
    )
    #: Manual ordering on the index. Docs have a reading order that neither
    #: alphabetical nor chronological sorting captures.
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")

    def __repr__(self) -> str:
        return f"<DocPage {self.slug!r} published={self.published}>"


class AdminAuditLog(Base):
    """An append-only record of every administrative action.

    Worth having even with exactly one administrator. This is a security
    product, so "who changed this account and when" is a question that will be
    asked — by a customer disputing a tier change, or by the maintainer six
    months later wondering why an account is suspended. Reconstructing it from
    application logs after the fact is not the same as having it in the
    database next to the thing it describes.

    Rows are never updated or deleted by application code. `actor_user_id` is
    nulled rather than cascaded if the admin account is ever removed, so the
    trail outlives the actor.
    """

    __tablename__ = "admin_audit_log"
    __table_args__ = (Index("ix_admin_audit_log_target_created", "target_user_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    #: Denormalised so the entry stays readable after the actor row is gone.
    actor_email: Mapped[str] = mapped_column(String(320), nullable=False)

    #: e.g. "user.tier_changed", "user.suspended", "user.unsuspended".
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    target_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    target_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    #: Before/after values and any note, as structured data rather than prose,
    #: so the trail stays queryable.
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now(), index=True
    )

    def __repr__(self) -> str:
        return f"<AdminAuditLog {self.action} by={self.actor_email} target={self.target_email}>"


class IgnoreRule(Base):
    """One advisory a project has chosen not to hear about.

    Distinct from dismissing a finding, and the difference is worth keeping.
    Dismissing says "I have looked at this one and I am not acting on it" about
    a finding that exists. A rule says "do not raise this again on this
    project", including for findings that do not exist yet -- a package
    upgraded into range next month is covered by the rule without anybody
    revisiting it.

    A rule never deletes anything. Matching findings stay on the Filtered tab
    with the rule named as the reason, because "what am I not being told about?"
    has to have an answer.

    The reason is required by the schema rather than by convention. Six months
    on it is the only thing that makes the entry reviewable, and the person who
    wrote it is the only one who can supply it.
    """

    __tablename__ = "ignore_rules"
    __table_args__ = (UniqueConstraint("target_id", "identifier", name="uq_ignore_rule_identity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("tracked_targets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    #: A CVE or advisory id, upper-cased on the way in. Matched against every
    #: alias an advisory carries, so ignoring the CVE also silences the GHSA
    #: that aliases it.
    identifier: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    #: Who and when, so the rule carries its own audit trail alongside the one
    #: in admin_audit_log. Denormalised for the same reason that log is: the
    #: entry has to stay readable after the account is gone.
    created_by_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now()
    )

    #: Set when a KEV listing overrode this rule, so the settings page can show
    #: that it stopped applying rather than leaving somebody to assume it held.
    overridden_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    target: Mapped[TrackedTarget] = relationship(back_populates="ignore_rules")

    def __repr__(self) -> str:
        return f"<IgnoreRule {self.identifier} target={self.target_id}>"


class EmailLog(Base):
    """One attempt to send one message to one address.

    Written whatever the outcome, including for messages a preference held
    back. A log that only records successes cannot answer either of the two
    questions it exists for: "did they get it?" and "why did they get four?"

    `recipient` is stored rather than only `user_id` because plenty of what
    goes out has no account behind it -- the admin notification for a
    logged-out bug report, a password reset for an address that turned out not
    to exist.
    """

    __tablename__ = "email_log"
    __table_args__ = (
        Index("ix_email_log_recipient_created", "recipient", "created_at"),
        Index("ix_email_log_trigger_created", "trigger", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    #: The template name, or "custom" for something an admin composed.
    template: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)

    trigger: Mapped[EmailTrigger] = mapped_column(
        enum_column(EmailTrigger, "email_trigger"), nullable=False
    )
    status: Mapped[EmailStatus] = mapped_column(
        enum_column(EmailStatus, "email_status"), nullable=False, index=True
    )

    #: Set for a manual send, so "who mailed everybody" is answerable.
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    #: The delivery backend's complaint, or the reason it was skipped.
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Groups the rows produced by one audience send, so a batch can be read as
    #: one event instead of six hundred.
    batch_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now(), index=True
    )

    def __repr__(self) -> str:
        return f"<EmailLog {self.template} to={self.recipient} {self.status}>"


class EmailCampaign(Base):
    """A message an administrator composed and sent to an audience.

    Separate from `EmailLog` because the two answer different questions. This
    row is "what did we decide to send, to whom, and how many did that turn out
    to be" -- one row per send. The log holds one row per address.
    """

    __tablename__ = "email_campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)

    audience: Mapped[AudienceKind] = mapped_column(
        enum_column(AudienceKind, "audience_kind"), nullable=False
    )
    #: Set when `audience` is ONE.
    audience_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    actor_email: Mapped[str] = mapped_column(String(320), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)

    recipient_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sent_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now(), index=True
    )

    def __repr__(self) -> str:
        return f"<EmailCampaign {self.subject!r} to={self.audience} n={self.recipient_count}>"


class ContactMessage(Base):
    """Something a person wanted to tell us.

    Deliberately not tied to an account. Two of the situations most worth
    hearing about -- "I cannot sign up" and "I cannot log in" -- are exactly the
    ones where requiring an account would swallow the report. `user_id` is set
    when we know who it was and left null otherwise; `email` is always
    populated, because a message we cannot reply to is barely a message.

    There is no reply feature here on purpose. Replies go out from a normal
    mailbox, so this table is a capture point and a queue, not half a support
    desk that would need its own threading, notifications and spam handling.
    """

    __tablename__ = "contact_messages"
    __table_args__ = (Index("ix_contact_messages_status_created", "status", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: Null for a logged-out visitor, and nulled rather than cascaded if the
    #: account is deleted -- the report stays useful without its author.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    #: Captured from the session when authenticated, typed by hand otherwise.
    email: Mapped[str] = mapped_column(String(320), nullable=False)

    category: Mapped[ContactCategory] = mapped_column(
        enum_column(ContactCategory, "contact_category"),
        nullable=False,
        default=ContactCategory.OTHER,
        server_default=ContactCategory.OTHER.value,
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[MessageStatus] = mapped_column(
        enum_column(MessageStatus, "message_status"),
        nullable=False,
        default=MessageStatus.NEW,
        server_default=MessageStatus.NEW.value,
        index=True,
    )

    #: What the sender was looking at. Answers "which page is broken" without
    #: asking them to describe it.
    page_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(300), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: Whether the admin notification email left the building. A message that
    #: arrived while mail was down is still here; this says nobody was told.
    notified_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    handled_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    handled_by_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    admin_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now(), index=True
    )

    user: Mapped[User | None] = relationship()

    @property
    def preview(self) -> str:
        """First line, trimmed -- what the inbox list shows."""
        first = self.message.strip().splitlines()[0] if self.message.strip() else ""
        return first[:110] + ("\u2026" if len(first) > 110 else "")

    def __repr__(self) -> str:
        return f"<ContactMessage {self.id} from={self.email} status={self.status}>"


class RateLimitHit(Base):
    """One recorded attempt against a rate-limited action.

    Stored in Postgres rather than in process memory, for the same reason
    sessions are: the app can run as more than one replica, and an in-process
    counter would multiply every limit by however many happen to be up while
    also resetting on every deploy. This is the table the login, signup and
    password-reset limits are counted from.

    `bucket` is an opaque key built by `rate_limit_service` — never a raw email
    address. Addresses are hashed into it so that a table an attacker might
    read does not double as a list of who has accounts here.

    Rows are pruned by the daily sweep; nothing here is worth keeping once its
    window has passed.
    """

    __tablename__ = "rate_limit_hits"
    __table_args__ = (Index("ix_rate_limit_hits_bucket_created", "bucket", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bucket: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, nullable=False, default=utcnow, server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<RateLimitHit {self.bucket} at={self.created_at}>"


#: Order findings by real severity, not by the alphabetical order of the stored
#: strings — which would rank "critical" next to "high" but put "low" above
#: "medium". Use as ``.order_by(desc(SEVERITY_RANK))``.
SEVERITY_RANK = case(
    {
        Severity.CRITICAL.value: 4,
        Severity.HIGH.value: 3,
        Severity.MEDIUM.value: 2,
        Severity.LOW.value: 1,
        Severity.UNKNOWN.value: 0,
    },
    value=CVEMatch.severity,
    else_=0,
)
