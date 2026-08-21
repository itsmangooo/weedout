"""Adding, viewing and removing tracked projects."""

from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import desc, func, select

from app.core.types import AlertStatus, Verdict
from app.deps import CurrentUser, DbSession
from app.logging_config import get_logger
from app.models import SEVERITY_RANK, CVEMatch, utcnow
from app.services.target_service import (
    get_target_for_user,
)

log = get_logger(__name__)

router = APIRouter(tags=["targets"])


# ---------------------------------------------------------------------------
# Settings
#
# Every handler re-fetches the project through `get_target_for_user`, which puts
# ownership in the query rather than in an assertion afterwards. A project that
# is not yours is a 404, not a 403: confirming that an id exists is itself a
# small leak.
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Scan rules
#
# Pro only, and checked here as well as at scan time. Two checks rather than
# one because they answer different questions: this one stops a Free account
# creating a rule, and the one in rules_service stops a rule created while the
# subscription was live from continuing to apply after it lapses.
# ---------------------------------------------------------------------------
