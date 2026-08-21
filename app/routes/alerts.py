"""Alert detail and triage actions."""

from __future__ import annotations

from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import desc, select

from app.core.explain import explain_decision
from app.core.matching import DEFAULT_POLICY
from app.core.types import (
    AlertStatus,
    Dependency,
    MatchDecision,
)
from app.deps import CsrfProtected, CurrentUser, DbSession, redirect
from app.logging_config import get_logger
from app.models import Alert, CVEMatch, KevRecord, TrackedTarget, utcnow
from app.schemas import MatchActionForm
from app.services.feed_service import record_to_vulnerability
from app.services.finding_service import FindingShow, list_findings
from app.templating import render

log = get_logger(__name__)

router = APIRouter(tags=["alerts"])


async def _load_match(db, user_id: int, match_id: int) -> CVEMatch:
    """Fetch a finding, scoped to its owner via the join."""
    match = await db.scalar(
        select(CVEMatch)
        .join(TrackedTarget, TrackedTarget.id == CVEMatch.target_id)
        .where(CVEMatch.id == match_id, TrackedTarget.user_id == user_id)
    )
    if match is None:
        raise HTTPException(status_code=404, detail="That alert doesn't exist.")
    return match


@router.get("/alerts")
async def alerts_index(request: Request, db: DbSession, user: CurrentUser, show: str = "open"):
    """Every finding across every project, with the filtered ones one tab away."""
    selected: FindingShow = (
        show if show in {"open", "filtered", "dismissed", "resolved"} else "open"
    )
    matches = await list_findings(db, user.id, show=selected, limit=200)
    targets = {match.target.id: match.target.name for match in matches}

    return render(
        request,
        "alerts/index.html",
        {
            "page_title": "Alerts",
            "matches": matches,
            "selected": selected,
            "target_names": targets,
        },
    )


@router.get("/alerts/{match_id}")
async def alert_detail(request: Request, db: DbSession, user: CurrentUser, match_id: int):
    """One finding, explained in plain language rather than as a score dump."""
    match = await _load_match(db, user.id, match_id)
    target = await db.get(TrackedTarget, match.target_id)

    kev_entry = None
    record = match.vulnerability
    if match.is_kev and record:
        for cve_id in record.cve_ids or []:
            kev_row = await db.get(KevRecord, cve_id)
            if kev_row is not None:
                kev_entry = kev_row
                break

    # Rebuild the core decision so the same explanation functions the scanner
    # and the emails use also drive this page — one wording, one place.
    decision = MatchDecision(
        dependency=Dependency(
            ecosystem=match.ecosystem,
            name=match.package_name,
            version=match.package_version,
            version_spec=match.version_spec,
            reachability=match.reachability,
            version_exact=match.version_exact,
        ),
        vulnerability=record_to_vulnerability(record) if record else None,  # type: ignore[arg-type]
        verdict=match.verdict,
        severity=match.severity,
        kev=match.is_kev,
        fixed_version=match.fixed_version,
        actionable_reason=match.actionable_reason,
        suppression_reason=match.suppression_reason,
    )

    core_kev = None
    if kev_entry is not None:
        from app.core.types import KevEntry

        core_kev = KevEntry(
            cve_id=kev_entry.cve_id,
            vendor_project=kev_entry.vendor_project,
            product=kev_entry.product,
            vulnerability_name=kev_entry.vulnerability_name,
            short_description=kev_entry.short_description,
            required_action=kev_entry.required_action,
            date_added=kev_entry.date_added,
            due_date=kev_entry.due_date,
            known_ransomware_use=kev_entry.known_ransomware_use,
        )

    explanation = explain_decision(decision, core_kev)

    delivery = list(
        (
            await db.scalars(
                select(Alert)
                .where(Alert.match_id == match.id)
                .order_by(desc(Alert.created_at))
                .limit(10)
            )
        ).all()
    )

    return render(
        request,
        "alerts/detail.html",
        {
            "page_title": match.package_name,
            "match": match,
            "target": target,
            "explanation": explanation,
            "kev_entry": kev_entry,
            "policy": DEFAULT_POLICY,
            "delivery": delivery,
        },
    )


@router.post("/alerts/{match_id}/status", dependencies=[CsrfProtected])
async def update_status(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    match_id: int,
    status: Annotated[str, Form()] = "",
    note: Annotated[str, Form()] = "",
):
    """Dismiss a finding, or reopen one that was dismissed."""
    match = await _load_match(db, user.id, match_id)

    try:
        form = MatchActionForm(status=status, note=note)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.errors()[0]["msg"]) from exc

    if form.status is AlertStatus.DISMISSED:
        match.status = AlertStatus.DISMISSED
        match.dismissed_at = utcnow()
        match.dismiss_note = form.note or None
    else:
        match.status = AlertStatus.OPEN
        match.dismissed_at = None
        match.dismiss_note = None

    await db.commit()
    log.info("alert.status_changed", match_id=match.id, user_id=user.id, status=str(match.status))

    if request.headers.get("accept", "").startswith("application/json"):
        return JSONResponse({"ok": True, "status": str(match.status)})
    return redirect(_safe_return_path(request, fallback=f"/alerts/{match.id}"))


def _safe_return_path(request: Request, fallback: str) -> str:
    """Extract a same-origin path from the Referer header, or use the fallback.

    The header is attacker-influenceable, so only its path component is ever
    used, and only after confirming the origin is ours. Passing it through
    unchecked would be an open redirect.
    """
    referer = request.headers.get("referer")
    if not referer:
        return fallback
    try:
        parsed = urlparse(referer)
    except ValueError:
        return fallback

    if parsed.netloc and parsed.netloc != request.url.netloc:
        return fallback
    path = parsed.path or fallback
    if not path.startswith("/") or path.startswith("//"):
        return fallback
    return f"{path}?{parsed.query}" if parsed.query else path
