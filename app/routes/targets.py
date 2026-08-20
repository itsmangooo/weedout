"""Adding, viewing and removing tracked projects."""

from __future__ import annotations

import csv
import io
import json
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from sqlalchemy import desc, func, select

from app.config import get_settings
from app.core.discord import InvalidWebhookURL, build_test_payload, parse_webhook_url
from app.core.types import AlertStatus, Verdict
from app.deps import CsrfProtected, CurrentUser, DbSession, redirect
from app.logging_config import get_logger
from app.models import SEVERITY_RANK, CVEMatch, DependencyRecord, ScanRun, utcnow
from app.schemas import (
    NewProjectForm,
    PasteManifestForm,
    RenameProjectForm,
    TargetCreateForm,
    first_error,
)
from app.services.alert_service import mark_delivered_in_app
from app.services.api_key_service import (
    ApiKeyError,
    issue_api_key,
    keys_for_target,
    revoke_api_key,
)
from app.services.discord_service import post_webhook
from app.services.scan_service import scan_target
from app.services.target_service import (
    TargetLimitReached,
    UnsupportedManifest,
    count_targets,
    create_empty_target,
    create_target,
    delete_target,
    get_target_for_user,
    replace_manifest,
)
from app.templating import render
from app.tiers import can_add_target, can_use_webhooks, limits_for

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
    ecosystem: Annotated[str, Form()] = "",
    manifest: Annotated[UploadFile | None, File()] = None,
    content: Annotated[str, Form()] = "",
    filename: Annotated[str, Form()] = "",
):
    """Create a project, with or without a manifest.

    Three entry points converge here: an uploaded file, pasted text, and neither
    — a name and an ecosystem. The first two share their validation, so a paste
    and an upload of the same bytes behave identically.
    """
    settings = get_settings()

    # No file at all: create the project from a name and an ecosystem so an API
    # key can be scoped to it. The manifest arrives later, from the project page
    # or from CI. This is the common path for anyone using the CLI.
    if not (manifest is not None and manifest.filename) and not content.strip():
        try:
            form = NewProjectForm(name=name, ecosystem=ecosystem)
        except ValidationError as exc:
            return await _error_page(request, db, user, first_error(exc))

        try:
            target = await create_empty_target(db, user, form.name, form.ecosystem)
        except TargetLimitReached as exc:
            return await _error_page(request, db, user, str(exc), status_code=402)
        except UnsupportedManifest as exc:
            return await _error_page(request, db, user, str(exc))

        await db.commit()
        return redirect(f"/targets/{target.id}")

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
            return await _error_page(request, db, user, first_error(exc))
        text_content = form.content
        upload_name = form.filename or "pasted-manifest"
    else:
        return await _error_page(request, db, user, "Choose a file or paste a manifest first.")

    try:
        meta = TargetCreateForm(name=name)
    except ValidationError as exc:
        return await _error_page(request, db, user, first_error(exc))

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
    view: str | None = None,
    new_api_key: str | None = None,
):
    """One project, in three views.

    Findings is the default because it is what somebody clicking through from
    the dashboard came for — the dashboard already showed them the counts. The
    exception is a project with no manifest, which opens on Overview instead.
    Overview and Settings are siblings rather than a second page, so the tab
    pattern already used for the finding filters carries over unchanged.
    """
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

    counts = await _tab_counts(db, target.id)

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

    views = ("overview", "findings", "settings")
    if view in views:
        active = view
    elif target.has_manifest:
        active = "findings"
    else:
        # A project with nothing uploaded has no findings to show, so landing on
        # findings would be an empty table it can only tell you to leave. Overview
        # is where its "no manifest yet" state and the upload form live.
        active = "overview"

    api_keys = await keys_for_target(db, target.id) if active == "settings" else []

    return render(
        request,
        "targets/detail.html",
        {
            "page_title": target.name,
            "target": target,
            "matches": matches,
            "counts": counts,
            "selected": selected,
            "active_view": active,
            "dependencies": dependencies,
            "recent_runs": recent_runs,
            "api_keys": api_keys,
            "limits": limits_for(user.tier),
            # A newly created key is passed straight into the template by the
            # POST handler below. It is never a query parameter: that would put
            # a live credential into browser history, the Referer header, and
            # any proxy log between here and the user.
            "new_api_key": new_api_key,
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


# ---------------------------------------------------------------------------
# Settings
#
# Every handler re-fetches the project through `get_target_for_user`, which puts
# ownership in the query rather than in an assertion afterwards. A project that
# is not yours is a 404, not a 403: confirming that an id exists is itself a
# small leak.
# ---------------------------------------------------------------------------


@router.post("/targets/{target_id}/rename", dependencies=[CsrfProtected])
async def rename_target(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    target_id: int,
    name: Annotated[str, Form()] = "",
):
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    try:
        form = RenameProjectForm(name=name)
    except ValidationError as exc:
        return await _settings_error(request, db, user, target, first_error(exc))

    target.name = form.name
    target.updated_at = utcnow()
    await db.commit()

    log.info("target.renamed", target_id=target.id, user_id=user.id)
    return redirect(f"/targets/{target.id}?view=settings")


@router.post("/targets/{target_id}/manifest", dependencies=[CsrfProtected])
async def attach_manifest(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    target_id: int,
    manifest: Annotated[UploadFile | None, File()] = None,
    content: Annotated[str, Form()] = "",
    filename: Annotated[str, Form()] = "",
):
    """Attach or replace this project's manifest, then scan it.

    The other half of creating a project without a file. Also how somebody
    updates a project that has drifted, without the CLI.
    """
    settings = get_settings()
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    if manifest is not None and manifest.filename:
        raw = await manifest.read()
        if len(raw) > settings.max_manifest_bytes:
            megabytes = settings.max_manifest_bytes // (1024 * 1024)
            return await _settings_error(
                request, db, user, target, f"That file is larger than {megabytes} MB."
            )
        try:
            text_content = raw.decode("utf-8")
        except UnicodeDecodeError:
            return await _settings_error(
                request, db, user, target, "That file isn't valid UTF-8 text."
            )
        upload_name = manifest.filename
    elif content.strip():
        text_content = content
        upload_name = filename.strip() or None
    else:
        return await _settings_error(
            request, db, user, target, "Choose a file or paste a manifest first."
        )

    try:
        changed = await replace_manifest(db, target, text_content, filename=upload_name)
    except UnsupportedManifest as exc:
        return await _settings_error(request, db, user, target, str(exc))

    if not changed:
        await db.commit()
        return redirect(f"/targets/{target.id}")

    await db.commit()

    # Scan straight away rather than waiting for the next tick — the user just
    # supplied the file and is about to look for the result.
    try:
        outcome = await scan_target(db, target)
        mark_delivered_in_app(outcome.new_matches)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        log.warning("target.attach_scan_failed", target_id=target.id, error=str(exc))

    return redirect(f"/targets/{target.id}")


@router.post("/targets/{target_id}/keys", dependencies=[CsrfProtected])
async def create_project_key(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    target_id: int,
    name: Annotated[str, Form()] = "",
):
    """Issue an API key for this project.

    Keys are scoped to a project, not to an account — see `ApiKey` — so this
    belongs on the project page. The plaintext is rendered once, straight into
    the response, and never stored or redirected with.
    """
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    try:
        issued = await issue_api_key(db, user, target, name)
    except ApiKeyError as exc:
        return await _settings_error(request, db, user, target, str(exc))

    await db.commit()
    return await _render_settings(
        request,
        db,
        user,
        target,
        new_api_key=issued.token,
        success="Key created. Copy it now — it will not be shown again.",
    )


@router.post("/targets/{target_id}/keys/{key_id}/revoke", dependencies=[CsrfProtected])
async def revoke_project_key(
    request: Request, db: DbSession, user: CurrentUser, target_id: int, key_id: int
):
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    if not await revoke_api_key(db, user, key_id):
        return await _settings_error(request, db, user, target, "That key could not be found.")

    await db.commit()
    return redirect(f"/targets/{target.id}?view=settings")


@router.get("/targets/{target_id}/export.{fmt}")
async def export_findings(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    target_id: int,
    fmt: str,
    show: str = "open",
):
    """Download this project's findings as CSV or JSON.

    Exports what the tab you are on shows, not "everything ever": a compliance
    export of the open findings is a different document from a dump of every
    row including the ones that were filtered, and quietly giving someone the
    second when they asked for the first is how a report ends up wrong.

    GET rather than POST because it is a read with no side effects, and a
    download you can bookmark or curl is more useful than one you cannot.
    """
    if fmt not in ("csv", "json"):
        raise HTTPException(status_code=404, detail="Export format must be csv or json.")

    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    filters = {
        "open": (CVEMatch.verdict == Verdict.ACTIONABLE, CVEMatch.status == AlertStatus.OPEN),
        "filtered": (CVEMatch.verdict == Verdict.SUPPRESSED,),
        "dismissed": (CVEMatch.status == AlertStatus.DISMISSED,),
        "resolved": (CVEMatch.status == AlertStatus.RESOLVED,),
        "all": (),
    }
    selected = show if show in filters else "open"

    matches = list(
        (
            await db.scalars(
                select(CVEMatch)
                .where(CVEMatch.target_id == target.id, *filters[selected])
                .order_by(desc(CVEMatch.is_kev), desc(SEVERITY_RANK), CVEMatch.package_name)
            )
        ).all()
    )

    rows = [_export_row(target, match) for match in matches]
    stamp = utcnow().strftime("%Y%m%d")
    slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in target.name).strip("-")
    filename = f"weedout-{slug or 'project'}-{selected}-{stamp}.{fmt}"

    if fmt == "json":
        body = json.dumps(
            {
                "project": target.name,
                "ecosystem": target.ecosystem.value,
                "view": selected,
                "exported_at": utcnow().isoformat(),
                "count": len(rows),
                "findings": rows,
            },
            indent=2,
        )
        media_type = "application/json"
    else:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(_EXPORT_FIELDS), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        body = buffer.getvalue()
        media_type = "text/csv"

    log.info("target.exported", target_id=target.id, fmt=fmt, view=selected, rows=len(rows))
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


#: Column order for the CSV. Declared once so the header and the rows cannot
#: drift apart, and ordered so the columns somebody actually reads come first.
_EXPORT_FIELDS = (
    "package",
    "version",
    "severity",
    "exploited_in_wild",
    "advisory",
    "cve",
    "summary",
    "verdict",
    "status",
    "reason",
    "fixed_version",
    "ships_to_production",
    "first_seen",
    "project",
    "ecosystem",
)


def _export_row(target, match) -> dict:
    record = match.vulnerability
    cve = (record.cve_ids[0] if record and record.cve_ids else None) or match.vulnerability_id
    reason = match.actionable_reason or match.suppression_reason
    return {
        "package": match.package_name,
        "version": match.package_version,
        "severity": match.severity.value,
        # Spelled out rather than true/false: a spreadsheet column of bare
        # booleans is one autocorrect away from meaning nothing.
        "exploited_in_wild": "yes" if match.is_kev else "no",
        "advisory": match.vulnerability_id,
        "cve": cve,
        "summary": (record.summary if record else "") or "",
        "verdict": match.verdict.value,
        "status": match.status.value,
        "reason": reason.label if reason else "",
        "fixed_version": match.fixed_version or "",
        "ships_to_production": "yes" if match.reachability.ships_to_production else "no",
        "first_seen": match.first_seen_at.isoformat() if match.first_seen_at else "",
        "project": target.name,
        "ecosystem": target.ecosystem.value,
    }


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


async def _tab_counts(db: DbSession, target_id: int) -> dict[str, int]:
    """All four tab counts in one round trip, using filtered aggregates.

    Every render of the project page needs these, Settings included: the number
    on the Findings tab is a fact about the project, not about the current view,
    and rendering a zero there because we happened to be on another tab would be
    the same lie this product exists to stop telling.
    """
    row = (
        await db.execute(
            select(
                func.count(CVEMatch.id).filter(
                    CVEMatch.verdict == Verdict.ACTIONABLE,
                    CVEMatch.status == AlertStatus.OPEN,
                ),
                func.count(CVEMatch.id).filter(CVEMatch.verdict == Verdict.SUPPRESSED),
                func.count(CVEMatch.id).filter(CVEMatch.status == AlertStatus.DISMISSED),
                func.count(CVEMatch.id).filter(CVEMatch.status == AlertStatus.RESOLVED),
            ).where(CVEMatch.target_id == target_id)
        )
    ).one()
    return dict(zip(("open", "filtered", "dismissed", "resolved"), row, strict=True))


# ---------------------------------------------------------------------------
# Discord webhook
#
# The URL is a credential and a request destination, so it gets treated as
# both: validated against an allowlist of Discord's own hosts before it is
# stored (see app.core.discord for why an allowlist rather than a blocklist),
# and never rendered back in full afterwards.
# ---------------------------------------------------------------------------


@router.post("/targets/{target_id}/discord", dependencies=[CsrfProtected])
async def save_discord_webhook(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    target_id: int,
    webhook_url: Annotated[str, Form()] = "",
):
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    if not can_use_webhooks(user.tier):
        return await _settings_error(
            request, db, user, target, "Discord alerts are part of the Pro plan."
        )

    try:
        webhook = parse_webhook_url(webhook_url)
    except InvalidWebhookURL as exc:
        return await _settings_error(request, db, user, target, str(exc))

    target.discord_webhook_url = webhook.url
    # A new URL has not failed yet, and carrying the old error forward would
    # show a freshly pasted webhook as broken.
    target.discord_last_error = None
    target.discord_last_sent_at = None
    target.updated_at = utcnow()
    await db.commit()

    # Never the URL itself: this line goes to a log aggregator.
    log.info("target.discord_saved", target_id=target.id, user_id=user.id)
    return await _render_settings(
        request,
        db,
        user,
        target,
        success="Discord webhook saved. Send a test to check it reaches the right channel.",
    )


@router.post("/targets/{target_id}/discord/test", dependencies=[CsrfProtected])
async def test_discord_webhook(request: Request, db: DbSession, user: CurrentUser, target_id: int):
    """Post a message that says it is a test.

    Worth its own button. The failure this catches -- a webhook pointing at the
    wrong channel, or one somebody deleted in Discord last week -- is otherwise
    discovered on the day a critical finding lands and nobody hears about it.
    """
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    if not target.discord_webhook_url:
        return await _settings_error(request, db, user, target, "Add a webhook URL first.")
    if not can_use_webhooks(user.tier):
        return await _settings_error(
            request, db, user, target, "Discord alerts are part of the Pro plan."
        )

    result = await post_webhook(target.discord_webhook_url, build_test_payload(project=target.name))

    if result.ok:
        target.discord_last_sent_at = utcnow()
        target.discord_last_error = None
        await db.commit()
        return await _render_settings(
            request, db, user, target, success="Test message sent. Check the channel."
        )

    target.discord_last_error = (result.error or "Delivery failed")[:500]
    await db.commit()
    return await _settings_error(
        request, db, user, target, result.error or "The test message did not go through."
    )


@router.post("/targets/{target_id}/discord/remove", dependencies=[CsrfProtected])
async def remove_discord_webhook(
    request: Request, db: DbSession, user: CurrentUser, target_id: int
):
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="That project doesn't exist.")

    target.discord_webhook_url = None
    target.discord_last_error = None
    target.discord_last_sent_at = None
    target.updated_at = utcnow()
    await db.commit()

    log.info("target.discord_removed", target_id=target.id, user_id=user.id)
    return await _render_settings(request, db, user, target, success="Discord webhook removed.")


async def _render_settings(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    target,
    *,
    new_api_key: str | None = None,
    error: str | None = None,
    success: str | None = None,
    status_code: int = 200,
):
    """Re-render the project page on its Settings tab.

    Used instead of a redirect wherever there is something to say — an error, or
    a freshly minted key that exists in this response and nowhere else.
    """
    return render(
        request,
        "targets/detail.html",
        {
            "page_title": target.name,
            "target": target,
            "matches": [],
            "counts": await _tab_counts(db, target.id),
            "selected": "open",
            "active_view": "settings",
            "dependencies": [],
            "recent_runs": [],
            "api_keys": await keys_for_target(db, target.id),
            "limits": limits_for(user.tier),
            "new_api_key": new_api_key,
            "error": error,
            "success": success,
        },
        status_code=status_code,
    )


async def _settings_error(request, db, user, target, message: str):
    return await _render_settings(request, db, user, target, error=message, status_code=400)


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
