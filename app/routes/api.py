"""The machine-facing scan API.

One endpoint, and a deliberately narrow one. `POST /api/v1/scan` takes a
lockfile, runs the existing pipeline against the local mirror, and answers with
counts. It is synchronous because the caller is a CI job that is blocking on
the answer: handing it a job id to poll would mean the pipeline has to wait
anyway, only with more moving parts and a worse failure mode.

Synchronous is affordable precisely because of the mirror — the request does no
outbound HTTP, so the work is a parse plus a handful of indexed queries.

Three things separate these routes from the HTML ones:

* Authentication is a bearer key, never a cookie, so no browser can be tricked
  into making an authenticated call and no CSRF token is needed.
* Every error is JSON with a stable `error` code. A CI script should be able to
  branch on the failure without parsing prose.
* The destination project comes from the key, never from the request body. A
  client cannot name the wrong project because it never names one.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status
from sqlalchemy import func, select

from app.config import get_settings
from app.core.types import AlertStatus, Severity, Verdict
from app.deps import CurrentApiKey, DbSession
from app.logging_config import get_logger
from app.models import CVEMatch, ScanRun, utcnow
from app.services.alert_service import mark_delivered_in_app
from app.services.scan_service import scan_target
from app.services.target_service import UnsupportedManifest, replace_manifest

log = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["api"])

# Starlette renamed its constants for these two (`HTTP_413_CONTENT_TOO_LARGE`,
# `HTTP_422_UNPROCESSABLE_CONTENT`) and deprecated the old spellings. The
# numbers are the stable thing — they are what goes on the wire and what a
# client branches on — so they are written literally rather than pinning this
# module to whichever spelling the installed Starlette happens to prefer.
HTTP_CONTENT_TOO_LARGE = 413
HTTP_UNPROCESSABLE_CONTENT = 422


def _fail(status_code: int, code: str, message: str, **extra) -> HTTPException:
    """A JSON error with a stable machine-readable code.

    The code is the part a script branches on; the message is for the human
    reading the build log. Both are always present so neither audience has to
    make do with the other's half.
    """
    return HTTPException(
        status_code=status_code, detail={"error": code, "message": message, **extra}
    )


async def _check_rate_limit(db, target_id: int, limit: int) -> None:
    """Refuse if this project has already had `limit` scans in the past hour.

    Counted from `scan_runs` rather than from an in-process counter, because
    the app runs as more than one replica and a per-process limit would
    multiply by however many happen to be up. The index on
    `(target_id, started_at)` makes it a cheap lookup.

    Scoped per project rather than per account: a busy monorepo should not be
    able to lock out the other projects on the same plan.
    """
    if limit <= 0:
        return

    window_start = utcnow() - timedelta(hours=1)
    recent = (
        await db.scalar(
            select(func.count(ScanRun.id)).where(
                ScanRun.target_id == target_id, ScanRun.started_at >= window_start
            )
        )
    ) or 0

    if recent >= limit:
        raise _fail(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "rate_limited",
            f"This project has run {recent} scans in the last hour "
            f"(limit {limit}). Try again shortly.",
            retry_after_seconds=300,
        )


@router.post("/scan")
async def scan(
    request: Request,
    db: DbSession,
    key: CurrentApiKey,
    manifest: Annotated[UploadFile | None, File()] = None,
):
    """Scan a lockfile against the project this key belongs to.

    Returns the tier counts and a dashboard link — small on purpose. The full
    findings live behind the link, and a CI log is the wrong place to print
    them; what a pipeline needs is a number to gate on.
    """
    settings = get_settings()
    target = key.target

    if manifest is None or not manifest.filename:
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "missing_file",
            "Attach the lockfile as a multipart field named 'manifest'.",
        )

    raw = await manifest.read()

    # Size first: a file that is too large is too large regardless of what is
    # in it, and checking its contents first would report a five-megabyte file
    # of whitespace as "empty" — true, but not the thing to fix.
    if len(raw) > settings.api_scan_max_bytes:
        raise _fail(
            HTTP_CONTENT_TOO_LARGE,
            "file_too_large",
            f"That file is larger than {settings.api_scan_max_bytes // (1024 * 1024)} MB.",
        )

    if not raw.strip():
        raise _fail(status.HTTP_400_BAD_REQUEST, "empty_file", "That file is empty.")

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "not_utf8",
            "That file isn't valid UTF-8 text — is it a binary file?",
        ) from None

    await _check_rate_limit(db, target.id, settings.api_scan_rate_limit_per_hour)

    try:
        changed = await replace_manifest(db, target, content, filename=manifest.filename)
    except UnsupportedManifest as exc:
        raise _fail(HTTP_UNPROCESSABLE_CONTENT, "unsupported_manifest", str(exc)) from exc

    outcome = await scan_target(db, target)

    # The results are being returned in this response, so they are not new to
    # the caller. Emailing them again after a CI run the developer just watched
    # is exactly the noise this product exists to remove.
    mark_delivered_in_app(outcome.new_matches)
    await db.commit()

    if outcome.failed:
        # A failed scan is a 503, not a 200 with zero findings. "No findings"
        # and "could not check" must never look the same to a pipeline.
        log.warning("api.scan_failed", target_id=target.id, errors=outcome.errors)
        raise _fail(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "scan_failed",
            outcome.errors[0] if outcome.errors else "The scan could not be completed.",
        )

    counts = await _severity_counts(db, target.id)
    base_url = settings.base_url.rstrip("/")

    log.info(
        "api.scan_completed",
        target_id=target.id,
        key_id=key.id,
        actionable=outcome.actionable_count,
        suppressed=outcome.suppressed_count,
    )

    return {
        "project": target.name,
        "manifest_changed": changed,
        "dependencies_scanned": outcome.dependencies_scanned,
        "actionable": outcome.actionable_count,
        "suppressed": outcome.suppressed_count,
        "new": len(outcome.new_matches),
        "resolved": outcome.resolved_count,
        "counts": counts,
        "findings": await _critical_findings(db, target.id),
        "warnings": outcome.errors,
        "dashboard_url": f"{base_url}/targets/{target.id}",
    }


async def _severity_counts(db, target_id: int) -> dict[str, int]:
    """Open, actionable findings for this project by severity.

    Always carries every severity, including zeroes: a client that has to guess
    whether a missing key means "none" or "not reported" ends up with `.get()`
    calls and silent bugs.
    """
    rows = (
        await db.execute(
            select(CVEMatch.severity, func.count(CVEMatch.id))
            .where(
                CVEMatch.target_id == target_id,
                CVEMatch.verdict == Verdict.ACTIONABLE,
                CVEMatch.status == AlertStatus.OPEN,
            )
            .group_by(CVEMatch.severity)
        )
    ).all()

    counts = {str(severity).lower(): 0 for severity in Severity}
    for severity, count in rows:
        counts[str(severity).lower()] = count

    counts["exploited"] = (
        await db.scalar(
            select(func.count(CVEMatch.id)).where(
                CVEMatch.target_id == target_id,
                CVEMatch.verdict == Verdict.ACTIONABLE,
                CVEMatch.status == AlertStatus.OPEN,
                CVEMatch.is_kev.is_(True),
            )
        )
    ) or 0
    return counts


#: How many critical findings the response spells out. The rest are behind the
#: dashboard link — a build log that scrolls for two hundred lines is one
#: nobody reads.
MAX_INLINE_FINDINGS = 10


async def _critical_findings(db, target_id: int) -> list[dict]:
    """The findings a pipeline would actually stop for, with their fixes."""
    from app.models import SEVERITY_RANK, VulnerabilityRecord

    rows = (
        await db.execute(
            select(
                VulnerabilityRecord.cve_ids,
                CVEMatch.package_name,
                CVEMatch.package_version,
                CVEMatch.fixed_version,
                CVEMatch.severity,
                CVEMatch.is_kev,
            )
            .join(VulnerabilityRecord, VulnerabilityRecord.id == CVEMatch.vulnerability_id)
            .where(
                CVEMatch.target_id == target_id,
                CVEMatch.verdict == Verdict.ACTIONABLE,
                CVEMatch.status == AlertStatus.OPEN,
                (CVEMatch.severity == Severity.CRITICAL) | (CVEMatch.is_kev.is_(True)),
            )
            .order_by(CVEMatch.is_kev.desc(), SEVERITY_RANK.desc(), CVEMatch.package_name)
            .limit(MAX_INLINE_FINDINGS)
        )
    ).all()

    return [
        {
            "cve": (cve_ids or ["—"])[0],
            "package": package,
            "version": version,
            "fixed_in": fixed,
            "severity": str(severity).lower(),
            "exploited": bool(is_kev),
        }
        for cve_ids, package, version, fixed, severity, is_kev in rows
    ]
