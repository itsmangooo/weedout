"""Rule profiles for the cookie-authenticated React application.

Account-scoped rather than project-scoped, which is why these live here rather
than under `internal_projects`. Assigning a profile *to* a project is the one
operation that belongs on the project, and it is there.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from app.deps import CsrfProtected, CurrentInternalUser, DbSession
from app.logging_config import get_logger
from app.models import RuleProfile
from app.schemas import RuleProfileView
from app.services.profile_service import (
    MAX_PROFILES,
    ProfileError,
    create_profile,
    delete_profile,
    list_profiles,
    set_default,
    update_profile,
)
from app.tiers import can_use_custom_rules

router = APIRouter(prefix="/api/internal", tags=["internal-profiles"])

log = get_logger(__name__)


def _fail(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _require_pro(user) -> None:
    if not can_use_custom_rules(user.tier):
        raise _fail(
            status.HTTP_402_PAYMENT_REQUIRED,
            "PRO_REQUIRED",
            "Rule profiles are part of the Pro plan.",
        )


async def _owned(db, user, profile_id: int) -> RuleProfile:
    profile = await db.get(RuleProfile, profile_id)
    # A 404 rather than a 403 for somebody else's profile: whether an id exists
    # on another account is not this account's business.
    if profile is None or profile.user_id != user.id:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That profile doesn't exist.")
    return profile


def _view(profile: RuleProfile, *, used_by: int = 0) -> RuleProfileView:
    return RuleProfileView(
        id=profile.id,
        name=profile.name,
        slug=profile.slug,
        description=profile.description,
        document=profile.document,
        is_default=profile.is_default,
        used_by=used_by,
        updated_at=profile.updated_at,
    )


class ProfileBody(BaseModel):
    """What a create or an edit may set.

    Every field is optional and defaults to None rather than to the empty
    string, so an edit that omits one leaves it alone. The difference matters
    for `document`: a client sending only a new name should not silently blank
    out the rules, and "" is a legitimate value somebody may mean on purpose.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str | None = Field(default=None, max_length=80)
    description: str | None = Field(default=None, max_length=300)
    #: A `.weedout.yml` document. The cap matches the one the parser enforces,
    #: so the refusal arrives from the same place either way.
    document: str | None = Field(default=None, max_length=64 * 1024)


@router.get("/profiles")
async def profiles(response: Response, db: DbSession, user: CurrentInternalUser) -> dict:
    """Every profile on this account, with how many projects use each."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"

    from sqlalchemy import func, select

    from app.models import TrackedTarget

    counts = dict(
        (
            await db.execute(
                select(TrackedTarget.profile_id, func.count(TrackedTarget.id))
                .where(TrackedTarget.user_id == user.id, TrackedTarget.profile_id.is_not(None))
                .group_by(TrackedTarget.profile_id)
            )
        ).all()
    )

    rows = await list_profiles(db, user.id)
    return {
        "data": [_view(profile, used_by=counts.get(profile.id, 0)) for profile in rows],
        "meta": {
            "limit": MAX_PROFILES,
            "can_use_profiles": can_use_custom_rules(user.tier),
        },
    }


@router.post("/profiles", dependencies=[CsrfProtected])
async def add_profile(db: DbSession, user: CurrentInternalUser, body: ProfileBody) -> dict:
    _require_pro(user)

    try:
        profile = await create_profile(
            db,
            user,
            name=body.name or "",
            document=body.document or "",
            description=body.description or "",
        )
    except ProfileError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_PROFILE", str(exc)) from None

    await db.commit()
    return {"data": _view(profile)}


@router.post("/profiles/{profile_id}", dependencies=[CsrfProtected])
async def edit_profile(
    db: DbSession, user: CurrentInternalUser, profile_id: int, body: ProfileBody
) -> dict:
    _require_pro(user)
    profile = await _owned(db, user, profile_id)

    try:
        await update_profile(
            db,
            profile,
            name=body.name or None,
            document=body.document,
            description=body.description,
        )

    except ProfileError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_PROFILE", str(exc)) from None

    await db.commit()
    return {"data": _view(profile)}


@router.post("/profiles/{profile_id}/default", dependencies=[CsrfProtected])
async def make_default(db: DbSession, user: CurrentInternalUser, profile_id: int) -> dict:
    """Apply this profile to every project that has not chosen its own."""
    _require_pro(user)
    profile = await _owned(db, user, profile_id)

    await set_default(db, user.id, profile)
    await db.commit()
    return {"data": _view(profile)}


@router.post("/profiles/{profile_id}/delete", dependencies=[CsrfProtected])
async def remove_profile(db: DbSession, user: CurrentInternalUser, profile_id: int) -> dict:
    _require_pro(user)
    profile = await _owned(db, user, profile_id)

    await delete_profile(db, profile)
    await db.commit()
    # Said back rather than left implicit: projects using it have quietly moved
    # to the account default, and somebody should know which rules they are on
    # now.
    return {"data": {"deleted": True}}


__all__ = ["router"]
