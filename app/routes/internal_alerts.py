"""Findings, for the React application.

The list and one finding in full, plus dismissing and reopening.

The explanation on the detail response is not composed here. It comes from
`app.core.explain`, the same functions the scanner and the alert emails use,
rebuilt from the stored decision — so a finding is described in identical words
wherever somebody meets it. Writing a second explanation for the browser is how
an email and a page end up disagreeing about why something was reported.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, ValidationError
from sqlalchemy import desc, select

from app.core.explain import explain_decision
from app.core.matching import DEFAULT_POLICY
from app.core.types import AlertStatus, Dependency, KevEntry, MatchDecision
from app.deps import CsrfProtected, CurrentInternalUser, DbSession
from app.logging_config import get_logger
from app.models import Alert, CVEMatch, KevRecord, TrackedTarget, utcnow
from app.schemas import MatchActionForm, first_error
from app.services.feed_service import record_to_vulnerability

log = get_logger(__name__)

router = APIRouter(prefix="/api/internal", tags=["internal-alerts"])


def _fail(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code, detail={"error": {"code": code, "message": message}}
    )


async def _owned_match(db, user, match_id: int) -> CVEMatch:
    """One finding belonging to this account, or a 404.

    Joined through the project rather than trusting the match row, because the
    finding id is the only thing the caller supplies and it is the project that
    carries ownership.
    """
    match = await db.scalar(
        select(CVEMatch)
        .join(TrackedTarget, TrackedTarget.id == CVEMatch.target_id)
        .where(CVEMatch.id == match_id, TrackedTarget.user_id == user.id)
    )
    if match is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That finding doesn't exist.")
    return match


@router.get("/alerts/{match_id}")
async def alert_detail(
    response: Response, db: DbSession, user: CurrentInternalUser, match_id: int
) -> dict:
    """One finding, explained in plain language rather than as a score dump."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"

    match = await _owned_match(db, user, match_id)
    target = await db.get(TrackedTarget, match.target_id)
    record = match.vulnerability

    kev_row = None
    if match.is_kev and record:
        for cve_id in record.cve_ids or []:
            found = await db.get(KevRecord, cve_id)
            if found is not None:
                kev_row = found
                break

    # The stored decision, rebuilt so the shared explanation functions can
    # describe it. This is what keeps the page, the email and the CLI saying
    # the same thing about the same finding.
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

    core_kev = (
        KevEntry(
            cve_id=kev_row.cve_id,
            vendor_project=kev_row.vendor_project,
            product=kev_row.product,
            vulnerability_name=kev_row.vulnerability_name,
            short_description=kev_row.short_description,
            required_action=kev_row.required_action,
            date_added=kev_row.date_added,
            due_date=kev_row.due_date,
            known_ransomware_use=kev_row.known_ransomware_use,
        )
        if kev_row is not None
        else None
    )

    deliveries = list(
        (
            await db.scalars(
                select(Alert)
                .where(Alert.match_id == match.id)
                .order_by(desc(Alert.created_at))
                .limit(10)
            )
        ).all()
    )

    return {
        "data": {
            "id": match.id,
            "identifier": match.vulnerability_id,
            "cve_ids": list(record.cve_ids or []) if record else [],
            "summary": record.summary if record else "",
            "package_name": match.package_name,
            "installed_version": match.package_version,
            "version_spec": match.version_spec,
            "fixed_version": match.fixed_version,
            "severity": str(match.severity),
            "is_exploited": bool(match.is_kev),
            "epss_score": match.epss_score,
            "reachability": str(match.reachability),
            "verdict": str(match.verdict),
            "status": str(match.status),
            "depth": match.depth,
            "via": list(match.via or []),
            "first_seen_at": match.first_seen_at,
            "dismissed_at": match.dismissed_at,
            "dismiss_note": match.dismiss_note,
            "project": {"id": target.id, "name": target.name} if target else None,
        },
        # Plain text from app.core.explain, not composed here.
        "explanation": explain_decision(decision, core_kev),
        "kev": (
            {
                "cve_id": kev_row.cve_id,
                "vulnerability_name": kev_row.vulnerability_name,
                "required_action": kev_row.required_action,
                "date_added": kev_row.date_added,
                "due_date": kev_row.due_date,
                "known_ransomware_use": kev_row.known_ransomware_use,
            }
            if kev_row is not None
            else None
        ),
        "deliveries": [
            {
                "channel": str(delivery.channel),
                "status": str(delivery.status),
                "created_at": delivery.created_at,
                "error": delivery.error,
            }
            for delivery in deliveries
        ],
        "thresholds": {
            "direct": str(DEFAULT_POLICY.direct_threshold),
            "transitive": str(DEFAULT_POLICY.transitive_threshold),
        },
    }


class StatusBody(BaseModel):
    status: str = ""
    note: str = ""


@router.post("/alerts/{match_id}/status", dependencies=[CsrfProtected])
async def update_status(
    db: DbSession, user: CurrentInternalUser, match_id: int, body: StatusBody
) -> dict:
    """Dismiss a finding, or reopen one that was dismissed.

    `resolved` cannot be set here. It is derived from a scan finding the
    vulnerability gone, and letting somebody choose it by hand would let a
    still-present finding be marked fixed — which is the one claim this
    product exists not to make falsely. MatchActionForm enforces it.
    """
    match = await _owned_match(db, user, match_id)

    try:
        form = MatchActionForm(status=body.status, note=body.note)
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None

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

    return {
        "data": {
            "id": match.id,
            "status": str(match.status),
            "dismissed_at": match.dismissed_at,
            "dismiss_note": match.dismiss_note,
        }
    }
