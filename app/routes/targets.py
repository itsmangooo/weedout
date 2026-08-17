"""Adding, viewing and removing tracked projects."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import desc, func, select

from app.config import get_settings
from app.core.types import AlertStatus, Verdict
from app.deps import CsrfProtected, CurrentUser, DbSession, redirect
from app.logging_config import get_logger
from app.models import SEVERITY_RANK, CVEMatch, DependencyRecord, ScanRun
from app.schemas import PasteManifestForm, TargetCreateForm
from app.services.alert_service import mark_delivered_in_app
from app.services.scan_service import scan_target
from app.services.target_service import (
    TargetLimitReached,
    UnsupportedManifest,
    count_targets,
    create_target,
    delete_target,
    get_target_for_user,
)
from app.templating import render
from app.tiers import can_add_target, limits_for

log = get_logger(__name__)

router = APIRouter(tags=["targets"])


@router.get("/targets/new")
async def new_target_page(request: Request, db: DbSession, user: CurrentUser):
    current = await count_targets(db, user.id)
    limits = limits_for(user.tier)
    return render(
        request,
        "targets/new.html",
        {
            "page_title": "Add a project",
            "at_limit": not can_add_target(user.tier, current),
            "limits": limits,
            "current_count": current,
        },
    )


@router.post("/targets", dependencies=[CsrfProtected])
async def create_target_route(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    name: Annotated[str, Form()] = "",
    manifest: Annotated[UploadFile | None, File()] = None,
    content: Annotated[str, Form()] = "",
    filename: Annotated[str, Form()] = "",
):
    """Accept a manifest by file upload or pasted text.

    Both paths converge on the same validation, so a paste and an upload of the
    same bytes behave identically.
    """
    settings = get_settings()

    if manifest is not None and manifest.filename:
        raw = await manifest.read()
        if len(raw) > settings.max_manifest_bytes:
            return await _error_page(
                request,
                db,
                user,
                f"That file is larger than {settings.max_manifest_bytes // (1024 * 1024)} MB.",
            )
        try:
            text_content = raw.decode("utf-8")
        except UnicodeDecodeError:
            return await _error_page(
                request, db, user, "That file isn't valid UTF-8 text — is it a binary file?"
            )
        upload_name = manifest.filename
    elif content.strip():
        try:
            form = PasteManifestForm(name=name, filename=filename, content=content)
        except ValidationError as exc:
            return await _error_page(request, db, user, exc.errors()[0]["msg"])
        text_content = form.content
        upload_name = form.filename or "pasted-manifest"
    else:
        return await _error_page(request, db, user, "Choose a file or paste a manifest first.")

    try:
        meta = TargetCreateForm(name=name)
    except ValidationError as exc:
        return await _error_page(request, db, user, exc.errors()[0]["msg"])

    try:
        target = await create_target(db, user, upload_name, text_content, meta.name)
    except TargetLimitReached as exc:
        return await _error_page(request, db, user, str(exc), status_code=402)
    except UnsupportedManifest as exc:
        return await _error_page(request, db, user, str(exc))

    await db.commit()

    # Scan immediately rather than making the user wait for the next tick —
    # an empty dashboard right after signup is how a trial ends early.
    try:
        outcome = await scan_target(db, target)
        # No email for this one: the user is about to read these findings on
        # screen. Marking them delivered also stops the next scheduled scan
        # from mailing a list the user has already seen.
        mark_delivered_in_app(outcome.new_matches)
        await db.commit()
    except Exception as exc:
        log.warning("target.initial_scan_failed", target_id=target.id, error=str(exc))
        await db.rollback()

    return redirect(f"/targets/{target.id}")


@router.get("/targets/{target_id}")
async def target_detail(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    target_id: int,
    show: str = "open",
):
    """One project: its open findings, and the noise that was filtered out."""
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    filters = {
        "open": (CVEMatch.verdict == Verdict.ACTIONABLE, CVEMatch.status == AlertStatus.OPEN),
        "filtered": (CVEMatch.verdict == Verdict.SUPPRESSED,),
        "dismissed": (CVEMatch.status == AlertStatus.DISMISSED,),
        "resolved": (CVEMatch.status == AlertStatus.RESOLVED,),
    }
    selected = show if show in filters else "open"

    matches = list(
        (
            await db.scalars(
                select(CVEMatch)
                .where(CVEMatch.target_id == target.id, *filters[selected])
                .order_by(desc(CVEMatch.is_kev), desc(SEVERITY_RANK), desc(CVEMatch.first_seen_at))
                .limit(200)
            )
        ).all()
    )

    # All four tab counts in one round trip, using filtered aggregates.
    count_row = (
        await db.execute(
            select(
                func.count(CVEMatch.id).filter(
                    CVEMatch.verdict == Verdict.ACTIONABLE,
                    CVEMatch.status == AlertStatus.OPEN,
                ),
                func.count(CVEMatch.id).filter(CVEMatch.verdict == Verdict.SUPPRESSED),
                func.count(CVEMatch.id).filter(CVEMatch.status == AlertStatus.DISMISSED),
                func.count(CVEMatch.id).filter(CVEMatch.status == AlertStatus.RESOLVED),
            ).where(CVEMatch.target_id == target.id)
        )
    ).one()
    counts = dict(zip(filters.keys(), count_row, strict=True))

    dependencies = list(
        (
            await db.scalars(
                select(DependencyRecord)
                .where(DependencyRecord.target_id == target.id)
                .order_by(DependencyRecord.name)
                .limit(500)
            )
        ).all()
    )

    recent_runs = list(
        (
            await db.scalars(
                select(ScanRun)
                .where(ScanRun.target_id == target.id)
                .order_by(desc(ScanRun.started_at))
                .limit(10)
            )
        ).all()
    )

    return render(
        request,
        "targets/detail.html",
        {
            "page_title": target.name,
            "target": target,
            "matches": matches,
            "counts": counts,
            "selected": selected,
            "dependencies": dependencies,
            "recent_runs": recent_runs,
        },
    )


@router.post("/targets/{target_id}/scan", dependencies=[CsrfProtected])
async def rescan_target(request: Request, db: DbSession, user: CurrentUser, target_id: int):
    """Scan on demand, from the project page."""
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    try:
        outcome = await scan_target(db, target)
        # Same reasoning as the initial scan: the user asked for this and is
        # about to read the result, so it does not also arrive by email.
        mark_delivered_in_app(outcome.new_matches)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        log.error("target.manual_scan_failed", target_id=target_id, error=str(exc))
        raise HTTPException(
            status_code=503, detail="Advisory data is unavailable right now."
        ) from exc

    return redirect(f"/targets/{target_id}")


@router.post("/targets/{target_id}/delete", dependencies=[CsrfProtected])
async def delete_target_route(request: Request, db: DbSession, user: CurrentUser, target_id: int):
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    await delete_target(db, target)
    await db.commit()

    if request.headers.get("accept", "").startswith("application/json"):
        return JSONResponse({"ok": True})
    return redirect("/dashboard")


async def _error_page(
    request: Request, db: DbSession, user: CurrentUser, message: str, status_code: int = 400
):
    current = await count_targets(db, user.id)
    return render(
        request,
        "targets/new.html",
        {
            "page_title": "Add a project",
            "error": message,
            "at_limit": not can_add_target(user.tier, current),
            "limits": limits_for(user.tier),
            "current_count": current,
        },
        status_code=status_code,
    )
