"""Account-level operations for a signed-in machine.

Everything here authenticates with a `CliToken` — the credential `weedout auth`
puts on a laptop — and nothing here accepts a project API key. That split is
the point of having two credential types:

- A **project key** can push a scan and read findings for one project. It is
  what sits in CI, where anyone who can read a build log can take it.
- A **CLI token** can create projects and mint keys for them, and cannot read a
  single finding. It belongs to a person at a keyboard and is obtained by
  confirming in a browser.

Neither can do the other's job. A key stolen from a runner cannot enumerate the
account; a token stolen from a laptop cannot quietly read what the account is
vulnerable to. Both are bad, and they are bad in different, smaller ways than
one credential that does everything.

`weedout key regenerate` lives here for the reason the whole section exists: it
mints a project key and hands it to the process that asked, so nobody ever
copies one out of a browser.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.types import KeyScope
from app.deps import DbSession
from app.logging_config import get_logger
from app.models import CliToken, TrackedTarget, User
from app.schemas import NewProjectForm, TargetCreateForm, first_error
from app.services.api_key_service import ApiKeyError, issue_api_key, revoke_api_key
from app.services.cli_auth_service import authenticate_cli_token
from app.services.target_service import (
    TargetLimitReached,
    UnsupportedManifest,
    create_empty_target,
    create_target,
)

#: Starlette renamed its 422 constant and deprecated the old spelling. Named
#: here rather than imported from the other route module, so neither file has
#: to import the other for a number.
HTTP_UNPROCESSABLE_CONTENT = 422

router = APIRouter(prefix="/api/account", tags=["account"])

log = get_logger(__name__)


def _fail(status_code: int, code: str, message: str, **extra) -> HTTPException:
    return HTTPException(
        status_code=status_code, detail={"error": code, "message": message, **extra}
    )


async def require_cli_token(request: Request, db: DbSession) -> CliToken:
    """Resolve the bearer token to a signed-in machine, or refuse.

    Refuses a project key explicitly rather than by failing to find it. Somebody
    who pastes a `wo_` key here has made a comprehensible mistake, and telling
    them which credential this needs is the difference between a fix and a
    support message.
    """
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "unauthenticated",
                "message": "Run `weedout auth` to sign this machine in.",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    resolved = await authenticate_cli_token(db, token)
    if resolved is None:
        if token.strip().startswith("wo_"):
            raise _fail(
                status.HTTP_403_FORBIDDEN,
                "wrong_credential",
                "That is a project key. This needs the machine credential from "
                "`weedout auth` — a project key cannot create projects.",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "unauthenticated",
                "message": "That machine credential is not valid. Run `weedout auth` again.",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    return resolved


CliKey = Annotated[CliToken, Depends(require_cli_token)]


class CreateProjectBody(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(default="", max_length=200)
    #: The lockfile, if the caller has one to hand. Optional: a project can be
    #: created empty and receive its first manifest from the next scan, which
    #: is what `weedout create` in a directory with no lockfile does.
    filename: str = Field(default="", max_length=200)
    content: str = Field(default="", max_length=5_000_000)
    #: Required only when there is no manifest, because that is the only case
    #: where nothing else can say which advisories this project is matched
    #: against. Never guessed: a project that silently changed ecosystem would
    #: reinterpret every finding recorded against it.
    ecosystem: str = Field(default="", max_length=32)
    #: What the resulting key may do. Narrowest by default, like everywhere
    #: else keys are minted.
    scope: str = Field(default="scan", max_length=16)


async def _make_target(db, owner: User, body: CreateProjectBody) -> TrackedTarget:
    """With a manifest, or without one.

    Two paths because they need different things: a manifest names its own
    ecosystem, and a project created empty has to be told. Kept here rather
    than inline so the endpoint reads as one decision.
    """
    if body.content.strip():
        meta = TargetCreateForm(name=body.name)
        return await create_target(
            db,
            owner,
            body.filename or "manifest",
            body.content,
            meta.name,
        )

    form = NewProjectForm(name=body.name, ecosystem=body.ecosystem)
    return await create_empty_target(db, owner, form.name, form.ecosystem)


class KeyBody(BaseModel):
    project_id: int
    scope: str = Field(default="scan", max_length=16)
    name: str = Field(default="", max_length=120)


def _scope(raw: str) -> KeyScope:
    try:
        return KeyScope(raw.strip().lower() or "scan")
    except ValueError:
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "bad_scope",
            "Scope is one of scan, read or manage.",
        ) from None


async def _owner(db: DbSession, key: CliToken) -> User:
    user = await db.get(User, key.user_id)
    if user is None:
        raise _fail(status.HTTP_401_UNAUTHORIZED, "unauthenticated", "That account is gone.")
    return user


@router.get("/projects")
async def list_projects(response: Response, db: DbSession, key: CliKey) -> dict:
    """Every project on the account, so `weedout link` can offer a choice.

    No findings, no counts of what is wrong — this credential is not for
    reading results. Names and identifiers only, which is what linking a
    directory needs.
    """
    response.headers["Cache-Control"] = "no-store"

    from sqlalchemy import select

    rows = await db.scalars(
        select(TrackedTarget)
        .where(TrackedTarget.user_id == key.user_id)
        .order_by(TrackedTarget.name)
    )

    return {
        "projects": [
            {
                "id": target.id,
                "name": target.name,
                "ecosystem": str(target.ecosystem),
                "has_manifest": bool(target.manifest_content),
            }
            for target in rows.all()
        ]
    }


@router.post("/projects")
async def create_project(response: Response, db: DbSession, key: CliKey, body: CreateProjectBody):
    """Create a project and hand back a key for it, in one call.

    One call rather than two because the alternative is a project that exists
    with no way to reach it, sitting there if the second call fails. And the
    key goes to the process that asked rather than being shown in a browser,
    which is the whole reason this endpoint exists.
    """
    response.headers["Cache-Control"] = "no-store"

    owner = await _owner(db, key)
    scope = _scope(body.scope)

    try:
        target = await _make_target(db, owner, body)
    except TargetLimitReached as exc:
        raise _fail(status.HTTP_402_PAYMENT_REQUIRED, "plan_limit", str(exc)) from None
    except UnsupportedManifest as exc:
        raise _fail(HTTP_UNPROCESSABLE_CONTENT, "unsupported_manifest", str(exc)) from exc
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "invalid_request", first_error(exc)) from None

    try:
        issued = await issue_api_key(db, owner, target, name="cli", scope=scope)
    except ApiKeyError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "key_refused", str(exc)) from None

    await db.commit()

    log.info("account.project_created", user_id=owner.id, target_id=target.id, scope=str(scope))
    return {
        "project": {"id": target.id, "name": target.name, "ecosystem": str(target.ecosystem)},
        # Once. Only the hash is stored, and it goes to the process that asked
        # rather than through a clipboard.
        "key": issued.token,
        "scope": str(scope),
    }


@router.post("/keys")
async def mint_key(response: Response, db: DbSession, key: CliKey, body: KeyBody) -> dict:
    """A key for a project that already exists — `weedout link`."""
    response.headers["Cache-Control"] = "no-store"

    owner = await _owner(db, key)
    target = await db.get(TrackedTarget, body.project_id)
    # A 404 rather than a 403 for somebody else's project: whether an id exists
    # on another account is not this account's business.
    if target is None or target.user_id != key.user_id:
        raise _fail(status.HTTP_404_NOT_FOUND, "no_such_project", "No such project.")

    scope = _scope(body.scope)
    try:
        issued = await issue_api_key(db, owner, target, name=body.name or "cli", scope=scope)
    except ApiKeyError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "key_refused", str(exc)) from None

    await db.commit()

    log.info("account.key_issued", user_id=owner.id, target_id=target.id, scope=str(scope))
    return {
        "project": {"id": target.id, "name": target.name},
        "key": issued.token,
        "scope": str(scope),
    }


class RegenerateBody(BaseModel):
    project_id: int
    scope: str = Field(default="scan", max_length=16)
    #: The key being replaced, if the caller knows which one it holds. Revoked
    #: after the new one is minted, so a failure part-way leaves the caller
    #: with a working credential rather than none.
    replace_key_id: int | None = None


@router.post("/keys/regenerate")
async def regenerate_key(
    response: Response, db: DbSession, key: CliKey, body: RegenerateBody
) -> dict:
    """Replace a project key without anybody copying one out of a browser.

    Mint first, revoke second, and never the other way round. A rotation that
    revokes first has a window where the caller holds nothing, and if the mint
    then fails they are locked out of their own project until they open the
    dashboard — which is the situation this command exists to avoid.
    """
    response.headers["Cache-Control"] = "no-store"

    owner = await _owner(db, key)
    target = await db.get(TrackedTarget, body.project_id)
    if target is None or target.user_id != key.user_id:
        raise _fail(status.HTTP_404_NOT_FOUND, "no_such_project", "No such project.")

    scope = _scope(body.scope)
    try:
        issued = await issue_api_key(db, owner, target, name="cli", scope=scope)
    except ApiKeyError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "key_refused", str(exc)) from None

    revoked = False
    if body.replace_key_id is not None:
        revoked = await revoke_api_key(db, owner, body.replace_key_id)

    await db.commit()

    log.info(
        "account.key_regenerated",
        user_id=owner.id,
        target_id=target.id,
        replaced=revoked,
    )
    return {
        "project": {"id": target.id, "name": target.name},
        "key": issued.token,
        "scope": str(scope),
        "replaced": revoked,
    }


@router.get("/whoami")
async def whoami(response: Response, db: DbSession, key: CliKey) -> dict:
    """Which account this machine is signed in as.

    Exists so `weedout whoami` can say something true rather than reading a
    local file and hoping. A revoked token answers 401 here, which is how the
    CLI finds out it was signed out from the dashboard.
    """
    response.headers["Cache-Control"] = "no-store"

    owner = await _owner(db, key)
    return {
        "email": owner.email,
        "tier": str(owner.tier),
        "device_label": key.device_label,
        "expires_at": key.expires_at.isoformat(),
    }


__all__ = ["router"]
