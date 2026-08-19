"""Pydantic models for request validation.

Every endpoint that accepts input validates it here, including the
form-encoded HTML posts. Doing it in a model rather than inline in the handler
means the rules are declared once, testable, and applied identically whether a
field arrives from a form, from fetch(), or from a future JSON API.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from app.core.types import AlertStatus, Ecosystem, Tier

MAX_NAME_LENGTH = 200


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
