"""Pydantic models for request validation.

Every endpoint that accepts input validates it here, including the
form-encoded HTML posts. Doing it in a model rather than inline in the handler
means the rules are declared once, testable, and applied identically whether a
field arrives from a form, from fetch(), or from a future JSON API.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from app.core.policy import MATCHES_EVERYTHING, MAX_PATTERN_LENGTH
from app.core.types import (
    AlertStatus,
    AudienceKind,
    ContactCategory,
    Ecosystem,
    IgnoreKind,
    KeyScope,
    MessageStatus,
    Reachability,
    Severity,
    Tier,
)

MAX_NAME_LENGTH = 200


class CurrentUserView(BaseModel):
    """The deliberately small user shape exposed to the React application.

    ``from_attributes`` is intentionally not enabled. Callers must select and
    copy each field rather than passing a ``User`` ORM instance through a
    serializer that could grow when the model grows.
    """

    model_config = ConfigDict(frozen=True)

    id: int
    email: str
    is_admin: bool
    tier: Tier
    account_state: Literal["active"] = "active"


class CurrentAuthState(BaseModel):
    model_config = ConfigDict(frozen=True)

    authenticated: bool
    session_state: Literal["anonymous", "authenticated"]
    user: CurrentUserView | None


class CurrentAuthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    data: CurrentAuthState


class DashboardSummaryView(BaseModel):
    model_config = ConfigDict(frozen=True)

    projects: int
    dependencies: int
    open_findings: int
    exploited_findings: int
    critical_findings: int
    filtered_findings: int
    dismissed_findings: int
    resolved_findings: int
    filter_rate_percent: int


class DashboardProjectFindingsView(BaseModel):
    model_config = ConfigDict(frozen=True)

    open: int
    exploited: int
    filtered: int


class DashboardProjectView(BaseModel):
    """The project fields the read-only React dashboard actually renders."""

    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    ecosystem: Ecosystem
    manifest_kind: str | None
    dependency_count: int
    is_active: bool
    has_manifest: bool
    last_scanned_at: datetime | None
    last_scan_failed: bool
    findings: DashboardProjectFindingsView


class DashboardDataView(BaseModel):
    model_config = ConfigDict(frozen=True)

    summary: DashboardSummaryView
    projects: list[DashboardProjectView]


class DashboardResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    data: DashboardDataView


class FindingProjectView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    name: str


class FindingAttentionView(BaseModel):
    """The compact, explicit finding shape rendered by the React dashboard."""

    model_config = ConfigDict(frozen=True)

    id: int
    project: FindingProjectView
    identifier: str
    package_name: str
    installed_version: str
    severity: Severity
    is_exploited: bool
    reachability: Reachability
    status: AlertStatus
    detected_at: datetime


class FindingListMeta(BaseModel):
    model_config = ConfigDict(frozen=True)

    show: Literal["open", "filtered", "dismissed", "resolved"]
    limit: int
    count: int
    #: How many days back an archive tab reaches on this plan. None on the
    #: tabs that describe the present, which are never trimmed by plan.
    history_days: int | None = None


class FindingListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    data: list[FindingAttentionView]
    meta: FindingListMeta


def first_error(exc: ValidationError) -> str:
    """The first validation failure, phrased for a person rather than a library.

    Pydantic prefixes messages raised by a field validator with "Value error, ",
    which is noise on a page. Model-level errors have no field location, and
    prefixing those with a made-up field name produces "Input: Those passwords
    don't match" — worse than the sentence on its own.
    """
    error = exc.errors()[0]
    message = error["msg"].removeprefix("Value error, ")
    if not error["loc"]:
        return message
    field = str(error["loc"][0])
    return f"{field.replace('_', ' ').capitalize()}: {message}"


class SignupForm(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    password: Annotated[str, Field(min_length=10, max_length=1024)]
    #: Honeypot. Real users never see this field; bots fill everything in.
    website: str = ""

    @field_validator("email")
    @classmethod
    def normalize(cls, value: str) -> str:
        return value.strip().lower()


class LoginForm(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    # No length floor on login: the rule applies to new passwords, and enforcing
    # it here would only tell an attacker which accounts predate the policy.
    password: Annotated[str, Field(min_length=1, max_length=1024)]
    next: str = "/dashboard"

    @field_validator("email")
    @classmethod
    def normalize(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("next")
    @classmethod
    def only_local_redirects(cls, value: str) -> str:
        """Block open redirects.

        Anything not a single-slash-prefixed local path is discarded, which
        rules out `//evil.com` and `https://evil.com` alike.
        """
        candidate = (value or "").strip()
        if not candidate.startswith("/") or candidate.startswith("//"):
            return "/dashboard"
        return candidate


class ChangePasswordForm(BaseModel):
    current_password: Annotated[str, Field(min_length=1, max_length=1024)]
    new_password: Annotated[str, Field(min_length=10, max_length=1024)]


class ForgotPasswordForm(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize(cls, value: str) -> str:
        return value.strip().lower()


class ResetPasswordForm(BaseModel):
    """New password chosen from an emailed link.

    The confirmation field is validated here rather than in JavaScript: this is
    the one screen where a typo locks someone out of the account they are
    trying to recover, and there is no old password left to fall back on.
    """

    token: Annotated[str, Field(min_length=1, max_length=512)]
    password: Annotated[str, Field(min_length=10, max_length=1024)]
    password_confirm: Annotated[str, Field(min_length=1, max_length=1024)]

    @model_validator(mode="after")
    def passwords_match(self) -> ResetPasswordForm:
        if self.password != self.password_confirm:
            raise ValueError("Those passwords don't match.")
        return self


class NewProjectForm(BaseModel):
    """Creating a project with no manifest — a name and an ecosystem.

    The ecosystem is required and never guessed. It decides which advisories a
    later upload is matched against, and a project that silently changed
    ecosystem would reinterpret every finding recorded against it.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    # No min_length: it would fire before _require_a_real_name and surface
    # "String should have at least 1 character" instead of the sentence below.
    name: Annotated[str, Field(max_length=MAX_NAME_LENGTH)]
    ecosystem: Ecosystem

    @field_validator("name")
    @classmethod
    def _require_a_real_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Give the project a name.")
        return value.strip()

    @field_validator("ecosystem", mode="before")
    @classmethod
    def _require_an_ecosystem(cls, value: object) -> object:
        if value in ("", None):
            raise ValueError("Choose which ecosystem this project uses.")
        return value


class RenameProjectForm(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: Annotated[str, Field(max_length=MAX_NAME_LENGTH)]

    @field_validator("name")
    @classmethod
    def _require_a_real_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Give the project a name.")
        return value.strip()


class TargetCreateForm(BaseModel):
    """Validated metadata for a manifest upload.

    The file content itself is read and size-checked in the handler, since
    streaming an UploadFile does not fit a Pydantic field.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    name: Annotated[str, Field(default="", max_length=MAX_NAME_LENGTH)]

    @field_validator("name")
    @classmethod
    def strip_control_characters(cls, value: str) -> str:
        return "".join(ch for ch in value if ch.isprintable()).strip()


class PasteManifestForm(TargetCreateForm):
    """Pasting manifest text instead of uploading a file."""

    filename: Annotated[str, Field(default="", max_length=255)]
    content: Annotated[str, Field(min_length=2, max_length=2 * 1024 * 1024)]


class MatchActionForm(BaseModel):
    """Dismissing or reopening a finding."""

    status: AlertStatus
    note: Annotated[str, Field(default="", max_length=500)] = ""

    @field_validator("status")
    @classmethod
    def only_user_settable(cls, value: AlertStatus) -> AlertStatus:
        """`resolved` is derived from a scan, never chosen by hand.

        Allowing it here would let a user mark something resolved that is still
        present, and the next scan would silently contradict them.
        """
        if value is AlertStatus.RESOLVED:
            raise ValueError("A finding is marked resolved by a scan, not manually.")
        return value


class AlertPreferencesForm(BaseModel):
    email_alerts_enabled: bool = False


class ApiKeyForm(BaseModel):
    """Creating an API key for one project.

    `target_id` arrives as a form string. Coercing and bounding it here means
    the handler never sees `"1 OR 1=1"` or a 400-digit integer, and an empty
    select renders the same friendly error as any other invalid field.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    target_id: Annotated[int, Field(ge=1)]
    #: Purely a label so a person can tell two keys apart later.
    name: Annotated[str, Field(default="", max_length=120)]
    #: Defaults to the narrowest scope, so a form posted without the field --
    #: an old bookmark, a script, a template that lost the select -- issues a
    #: key that can only push scans rather than one that can change rules.
    scope: KeyScope = KeyScope.SCAN

    @field_validator("scope", mode="before")
    @classmethod
    def _unknown_scope_is_the_narrow_one(cls, value: object) -> object:
        if value in ("", None):
            return KeyScope.SCAN
        return value

    @field_validator("target_id", mode="before")
    @classmethod
    def _require_a_project(cls, value: object) -> object:
        if value in ("", None):
            raise ValueError("Choose a project for this key.")
        return value


# ---------------------------------------------------------------------------
# Admin
#
# Query parameters get the same treatment as request bodies. `?page=-1` and
# `?per_page=100000` arrive from the same untrusted place as a form field, and
# an unbounded per_page is a one-request denial of service against a table that
# grows without limit.
# ---------------------------------------------------------------------------


class ComposeEmailForm(BaseModel):
    """An email an administrator is about to send to other people.

    The length caps are generous rather than tight: this is a person writing
    prose, and a validator that truncates somebody's carefully worded outage
    notice is worse than a long email.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    subject: Annotated[str, Field(max_length=300)]
    body: Annotated[str, Field(max_length=50_000)]
    audience: AudienceKind
    audience_email: Annotated[str, Field(max_length=320)] = ""

    @field_validator("subject")
    @classmethod
    def _require_a_subject(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Give the email a subject.")
        return value.strip()

    @field_validator("body")
    @classmethod
    def _require_a_body(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("The email has no body.")
        return value.strip()

    @field_validator("audience", mode="before")
    @classmethod
    def _require_an_audience(cls, value: object) -> object:
        if value in ("", None):
            raise ValueError("Choose who this goes to.")
        return value

    @model_validator(mode="after")
    def _one_needs_an_address(self) -> ComposeEmailForm:
        if self.audience is AudienceKind.ONE and "@" not in self.audience_email:
            raise ValueError("Give the address to send to.")
        return self


class IgnoreRuleForm(BaseModel):
    """Silencing one advisory, or one family of packages, on one project.

    The reason is required, and the refusal when it is missing is the feature.
    An ignore with no reason is unreviewable six months later, and the person
    adding it is the only one who can supply it.

    `identifier` is validated differently depending on `kind`, which is why the
    check is a model validator rather than two field validators: an advisory id
    has a shape, and a package glob has a different one.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: Annotated[str, Field(max_length=MAX_PATTERN_LENGTH)]
    reason: Annotated[str, Field(max_length=1000)]
    kind: IgnoreKind = IgnoreKind.ADVISORY

    @model_validator(mode="after")
    def _check_the_identifier_against_its_kind(self) -> IgnoreRuleForm:
        cleaned = (
            _clean_package_pattern(self.identifier)
            if self.kind is IgnoreKind.PACKAGE
            else _clean_advisory_id(self.identifier)
        )
        object.__setattr__(self, "identifier", cleaned)
        return self

    @field_validator("reason")
    @classmethod
    def _require_a_real_reason(cls, value: str) -> str:
        if len(value.strip()) < 10:
            raise ValueError(
                "Say why in a sentence. Whoever reads this in six months will "
                "need it, and that might be you."
            )
        return value.strip()


#: What a package glob may be made of. Deliberately narrow: every character
#: here appears in a real package name on some registry, and nothing else does.
#: `[`, `]` and `!` are glob syntax rather than name characters.
_PACKAGE_PATTERN = re.compile(rf"[a-z0-9@/*?\[\]!._+-]{{1,{MAX_PATTERN_LENGTH}}}")


def _clean_advisory_id(value: str) -> str:
    cleaned = value.strip().upper()
    if not cleaned:
        raise ValueError("Which advisory? Paste a CVE or GHSA id.")
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{2,63}", cleaned):
        raise ValueError(
            "That does not look like an advisory id. Use something like "
            "CVE-2021-23337 or GHSA-jf85-cpcp-j695."
        )
    return cleaned


def _clean_package_pattern(value: str) -> str:
    """A glob over dependency names: `@acme/*`, `karma-*`, `spring-core`.

    Lower-cased rather than upper-cased: matching is case-insensitive anyway,
    and the stored form is what gets listed back on the settings page.
    """
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("Which packages? Use a name or a pattern like @acme/*.")
    if cleaned in MATCHES_EVERYTHING:
        raise ValueError(
            "That ignores every package, which switches the scan off rather than "
            "filtering it. Deactivate the project instead."
        )
    if not re.fullmatch(_PACKAGE_PATTERN, cleaned):
        raise ValueError(
            "Use a package name or a glob over one -- letters, digits, and "
            "@ / . _ - + with * or ? as wildcards."
        )
    return cleaned


class ThresholdForm(BaseModel):
    """A project's own alerting floors. Blank means "use the default"."""

    model_config = ConfigDict(str_strip_whitespace=True)

    direct: str = ""
    transitive: str = ""
    #: EPSS probability, 0 to 1. Blank means never gate on it.
    epss_threshold: str = ""

    @field_validator("epss_threshold")
    @classmethod
    def _a_probability(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            return ""
        try:
            number = float(cleaned)
        except ValueError:
            raise ValueError("The EPSS threshold should be a number between 0 and 1.") from None
        if not (0.0 < number <= 1.0):
            raise ValueError("The EPSS threshold should be between 0 and 1.")
        return cleaned

    @field_validator("direct", "transitive")
    @classmethod
    def _known_level(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned in ("", "default"):
            return ""
        if cleaned not in ("low", "medium", "high", "critical"):
            raise ValueError("Choose low, medium, high or critical.")
        return cleaned


class ContactForm(BaseModel):
    """A message from anybody -- signed in or not.

    `email` is optional here because the route supplies the session's address
    when there is one. Requiring it in the model would mean an authenticated
    sender could type a different address into a hidden field and have the
    reply go there.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    message: Annotated[str, Field(max_length=8000)]
    category: ContactCategory = ContactCategory.OTHER
    email: Annotated[str, Field(max_length=320)] = ""

    @field_validator("message")
    @classmethod
    def _require_something_to_read(cls, value: str) -> str:
        text = value.strip()
        if len(text) < 10:
            raise ValueError("Tell us a bit more -- at least a sentence.")
        return text

    @field_validator("category", mode="before")
    @classmethod
    def _default_the_category(cls, value: object) -> object:
        # A blank select is "Something else", not a validation error. Nobody
        # reporting a bug should be stopped to classify it first.
        return ContactCategory.OTHER if value in ("", None) else value


class ContactStatusForm(BaseModel):
    """An admin moving a message through the queue."""

    model_config = ConfigDict(str_strip_whitespace=True)

    status: MessageStatus
    note: Annotated[str, Field(max_length=2000)] = ""


class UserListQuery(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    page: Annotated[int, Field(default=1, ge=1, le=100_000)]
    per_page: Annotated[int, Field(default=25, ge=5, le=100)]
    search: Annotated[str, Field(default="", max_length=320)]
    #: Empty string means "any" — these arrive from a <select> whose first
    #: option has no value, so blank has to be a legal input, not an error.
    tier: Annotated[str, Field(default="")]
    status: Annotated[str, Field(default="")]

    @field_validator("search")
    @classmethod
    def clean_search(cls, value: str) -> str:
        return "".join(ch for ch in value if ch.isprintable()).strip()

    @field_validator("tier")
    @classmethod
    def known_tier(cls, value: str) -> str:
        if value and value not in {t.value for t in Tier}:
            raise ValueError("Unknown tier filter.")
        return value

    @field_validator("status")
    @classmethod
    def known_status(cls, value: str) -> str:
        if value and value not in {"active", "suspended", "admin"}:
            raise ValueError("Unknown status filter.")
        return value

    @property
    def tier_filter(self) -> Tier | None:
        return Tier(self.tier) if self.tier else None

    @property
    def status_filter(self) -> str | None:
        return self.status or None

    @property
    def search_filter(self) -> str | None:
        return self.search or None


class TierChangeForm(BaseModel):
    """Manual tier override, for comps and support."""

    model_config = ConfigDict(str_strip_whitespace=True)

    tier: Tier
    note: Annotated[str, Field(default="", max_length=500)]

    @field_validator("note")
    @classmethod
    def printable(cls, value: str) -> str:
        return "".join(ch for ch in value if ch.isprintable() or ch == "\n").strip()


class SuspendForm(BaseModel):
    """Suspension is reversible, so a reason is requested but not required."""

    model_config = ConfigDict(str_strip_whitespace=True)

    reason: Annotated[str, Field(default="", max_length=500)]

    @field_validator("reason")
    @classmethod
    def printable(cls, value: str) -> str:
        return "".join(ch for ch in value if ch.isprintable() or ch == "\n").strip()


class DeleteUserForm(BaseModel):
    """Irreversible account deletion, gated on typing the address.

    A plain "are you sure?" is answered reflexively; retyping the address is
    the cheapest way to make the admin look at *which* account they are about
    to destroy. Enforced server-side because the modal is only a courtesy.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    confirm_email: Annotated[str, Field(min_length=3, max_length=320)]

    @field_validator("confirm_email")
    @classmethod
    def normalize(cls, value: str) -> str:
        return value.strip().lower()


class DocPageForm(BaseModel):
    """Create or edit a documentation page."""

    model_config = ConfigDict(str_strip_whitespace=True)

    title: Annotated[str, Field(min_length=1, max_length=200)]
    #: Blank is legal — the service derives it from the title.
    slug: Annotated[str, Field(default="", max_length=120)]
    summary: Annotated[str, Field(default="", max_length=300)]
    #: Generous, but bounded: an unbounded text field is an easy way to fill a
    #: disk from a single request.
    content: Annotated[str, Field(default="", max_length=200_000)]
    published: bool = False
    position: Annotated[int, Field(default=0, ge=0, le=10_000)]

    @field_validator("title", "summary")
    @classmethod
    def printable(cls, value: str) -> str:
        return "".join(ch for ch in value if ch.isprintable()).strip()


class SignupChartQuery(BaseModel):
    #: Bounded so the chart query can never be asked to scan an unbounded range.
    days: Annotated[int, Field(default=30, ge=7, le=365)]


# ---------------------------------------------------------------------------
# One project, for the React project page
#
# Explicit views rather than serialising the ORM, matching the dashboard and
# findings responses above. The rule is the same: nothing reaches a browser
# because it happened to be an attribute.
# ---------------------------------------------------------------------------


class ProjectDependencyView(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    depth: int
    is_direct: bool


class ProjectRunView(BaseModel):
    model_config = ConfigDict(frozen=True)

    started_at: datetime | None
    status: str
    dependencies_scanned: int
    actionable_count: int
    suppressed_count: int
    new_actionable_count: int
    resolved_count: int
    duration_seconds: float | None
    error: str | None


class ProjectSignalView(BaseModel):
    model_config = ConfigDict(frozen=True)

    package_name: str
    package_version: str | None
    kind: str
    label: str
    level: str
    detail: str


class ProjectIgnoreRuleView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    identifier: str
    #: Whether `identifier` is an advisory id or a glob over package names.
    kind: IgnoreKind
    reason: str
    created_by_email: str
    created_at: datetime | None
    #: Set when a KEV listing set the rule aside. Reported so the interface can
    #: say the rule stopped applying rather than showing it as active.
    overridden_at: datetime | None


class ProjectApiKeyView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    prefix: str
    name: str
    scope: KeyScope
    created_at: datetime | None
    last_used_at: datetime | None
    call_count: int
    is_active: bool
    revoked_at: datetime | None


class ProjectWebhookView(BaseModel):
    model_config = ConfigDict(frozen=True)

    configured: bool
    kind: str | None
    #: The host only, never the URL. A webhook URL is a credential — anyone
    #: holding it can post into the channel — so it is write-only from the
    #: browser's point of view, exactly as it is in the rendered page.
    host: str | None


class ProjectThresholdsView(BaseModel):
    model_config = ConfigDict(frozen=True)

    direct: Severity | None
    transitive: Severity | None
    epss: float | None


class ProjectPolicyFileView(BaseModel):
    model_config = ConfigDict(frozen=True)

    present: bool
    updated_at: datetime | None
    error: str | None
    ignored_ids: list[str]


class ProjectDetailView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    ecosystem: Ecosystem
    manifest_kind: str | None
    has_manifest: bool
    dependency_count: int
    is_active: bool
    last_scanned_at: datetime | None
    next_scan_at: datetime | None
    last_scan_error: str | None
    unreached_by_depth: int
    counts: dict[str, int]
    tab_counts: dict[str, int]


class ProjectResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    data: ProjectDetailView


class ProjectPageResponse(BaseModel):
    """Everything the project page needs, in one request.

    One response rather than six, because the page shows them together and six
    round trips would render it in pieces — each arriving at a different
    moment, each shifting the layout under whoever is reading it.
    """

    model_config = ConfigDict(frozen=True)

    data: ProjectDetailView
    findings: list[FindingAttentionView]
    dependencies: list[ProjectDependencyView]
    recent_runs: list[ProjectRunView]
    supply_chain: list[ProjectSignalView]
    rules: list[ProjectIgnoreRuleView]
    thresholds: ProjectThresholdsView
    policy_file: ProjectPolicyFileView
    api_keys: list[ProjectApiKeyView]
    webhook: ProjectWebhookView
    can_use_rules: bool
    can_use_webhooks: bool
