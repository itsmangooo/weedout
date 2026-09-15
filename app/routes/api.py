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

import json
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from pydantic import ValidationError
from sqlalchemy import func, select

from app.config import get_settings
from app.core.policy import MAX_POLICY_BYTES, parse_policy
from app.core.reachability import (
    MAX_SOURCE_BYTES,
    MAX_SOURCE_FILE_BYTES,
    MAX_SOURCE_FILES,
    SourceBundle,
    SourceFile,
    safe_source_path,
    supported_source_path,
)
from app.core.types import ActionableReason, AlertStatus, Severity, Verdict
from app.deps import DbSession, ManageKey, ReadKey, ScanKey
from app.logging_config import get_logger
from app.models import SEVERITY_RANK, CVEMatch, ScanRun, User, VulnerabilityRecord, utcnow
from app.schemas import first_error as _first_error
from app.services.alert_service import mark_delivered_in_app
from app.services.profile_service import NoSuchProfile
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


async def _plan_for(db, key) -> dict:
    """The plan this key's owner is on, right now.

    Read fresh and normalised so legacy database tier values never leak into
    the machine-facing contract.
    """
    from app.services.plan_service import plan_summary

    owner = await db.get(User, key.user_id)
    return plan_summary(owner.tier if owner else "free")


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
    key: ScanKey,
    manifest: Annotated[UploadFile | None, File()] = None,
    policy: Annotated[UploadFile | None, File()] = None,
    profile: Annotated[str | None, Form()] = None,
    sources: Annotated[list[UploadFile] | None, File()] = None,
    source_context: Annotated[str | None, Form()] = None,
):
    """Scan a lockfile against the project this key belongs to.

    Returns finding counts and a dashboard link — small on purpose. The full
    findings live behind the link, and a CI log is the wrong place to print
    them; what a pipeline needs is a number to gate on.

    `profile` names one of the account's rule profiles. It is resolved
    server-side against that account's own profiles: a name that does not exist
    is a refusal, never a quiet fall back to the defaults. A pipeline that
    believes it is running under stricter rules than it is would be the worse
    failure by a wide margin.
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

    # `.weedout.yml`, if the pipeline sent one. The server never sees the
    # repository -- only the file that was uploaded -- so the policy has to
    # travel with the scan. That is also what makes CI the source of truth: the
    # file that ran in the pipeline is the file that applied.
    if policy is not None and policy.filename:
        policy_raw = await policy.read()
        if len(policy_raw) > MAX_POLICY_BYTES:
            raise _fail(
                HTTP_CONTENT_TOO_LARGE,
                "policy_too_large",
                "That .weedout.yml is too large to read.",
            )
        parsed = parse_policy(policy_raw)
        target.policy_file = policy_raw.decode("utf-8", "replace")
        target.policy_file_updated_at = utcnow()
        # Recorded rather than raised. A policy file that will not parse means
        # every rule in it stops applying, which can only produce more alerts
        # than intended -- so the scan proceeds and says what happened.
        target.policy_file_error = parsed.error

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

    source_bundle = await _source_bundle(sources or [], source_context)

    try:
        outcome = await scan_target(
            db,
            target,
            requested_profile=profile,
            source_bundle=source_bundle,
        )
    except NoSuchProfile as exc:
        # 400 rather than 404: the project and the key are both fine, and what
        # is wrong is the request. Raised before anything was scanned, so
        # nothing has been recorded under the wrong rules.
        raise _fail(status.HTTP_400_BAD_REQUEST, "no_such_profile", str(exc)) from None

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
        # What this scan actually ran under. A client comparing it to what it
        # saw last time is how a plan change becomes visible in a terminal.
        "plan": await _plan_for(db, key),
        "manifest_changed": changed,
        "dependencies_scanned": outcome.dependencies_scanned,
        "actionable": outcome.actionable_count,
        "suppressed": outcome.suppressed_count,
        "new": len(outcome.new_matches),
        "resolved": outcome.resolved_count,
        "counts": counts,
        "reachability": {
            "analysis_complete": outcome.reachability_analysis_complete,
            "source_files": outcome.reachability_source_count,
            "counts": outcome.reachability_counts,
            "notes": outcome.reachability_notes,
        },
        "findings": await _blocking_findings(db, target.id),
        "warnings": outcome.errors,
        "dashboard_url": f"{base_url}/targets/{target.id}",
    }


async def _source_bundle(uploads: list[UploadFile], source_context: str | None) -> SourceBundle:
    """Validate and read the bounded source inventory attached by the CLI.

    Source is analysed in memory and discarded after the request. The context
    carries repository-relative labels because multipart clients and proxies
    commonly reduce an uploaded filename to its basename.
    """
    if len(uploads) > MAX_SOURCE_FILES:
        raise _fail(
            HTTP_CONTENT_TOO_LARGE,
            "too_many_source_files",
            f"Source analysis accepts at most {MAX_SOURCE_FILES} files per scan.",
        )

    context: dict = {}
    if source_context:
        if len(source_context) > 100_000:
            raise _fail(
                HTTP_CONTENT_TOO_LARGE,
                "source_context_too_large",
                "The source inventory metadata is too large.",
            )
        try:
            decoded = json.loads(source_context)
        except json.JSONDecodeError as exc:
            raise _fail(
                status.HTTP_400_BAD_REQUEST,
                "invalid_source_context",
                "The source inventory metadata is not valid JSON.",
            ) from exc
        if not isinstance(decoded, dict):
            raise _fail(
                status.HTTP_400_BAD_REQUEST,
                "invalid_source_context",
                "The source inventory metadata must be an object.",
            )
        context = decoded

    raw_paths = context.get("files")
    if raw_paths is None:
        raw_paths = [upload.filename or "" for upload in uploads]
    if not isinstance(raw_paths, list) or len(raw_paths) != len(uploads):
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "invalid_source_context",
            "The source inventory must name every attached source file exactly once.",
        )

    notes = context.get("notes") or []
    if not isinstance(notes, list):
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "invalid_source_context",
            "Source analysis notes must be a list.",
        )
    bounded_notes = tuple(str(note)[:300] for note in notes[:20] if str(note).strip())
    complete = context.get("complete") is True

    files: list[SourceFile] = []
    seen_paths: set[str] = set()
    total = 0
    for upload, raw_path in zip(uploads, raw_paths, strict=True):
        if not isinstance(raw_path, str):
            raise _fail(
                status.HTTP_400_BAD_REQUEST,
                "invalid_source_context",
                "Every source inventory path must be a string.",
            )
        path = safe_source_path(raw_path)
        if path is None or not supported_source_path(path):
            raise _fail(
                status.HTTP_400_BAD_REQUEST,
                "invalid_source_path",
                f"Unsupported or unsafe source path: {str(raw_path)[:120]!r}.",
            )
        if path in seen_paths:
            raise _fail(
                status.HTTP_400_BAD_REQUEST,
                "invalid_source_context",
                f"The source inventory names {path!r} more than once.",
            )
        seen_paths.add(path)

        raw = await upload.read(MAX_SOURCE_FILE_BYTES + 1)
        if len(raw) > MAX_SOURCE_FILE_BYTES:
            raise _fail(
                HTTP_CONTENT_TOO_LARGE,
                "source_file_too_large",
                f"{path} is larger than {MAX_SOURCE_FILE_BYTES // 1024} KiB.",
            )
        total += len(raw)
        if total > MAX_SOURCE_BYTES:
            raise _fail(
                HTTP_CONTENT_TOO_LARGE,
                "source_bundle_too_large",
                f"Source analysis accepts at most {MAX_SOURCE_BYTES // (1024 * 1024)} MiB.",
            )
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            complete = False
            bounded_notes = (*bounded_notes, f"{path} was not UTF-8 and could not be analysed.")
            continue
        files.append(SourceFile(path=path, content=content))

    if not source_context:
        complete = False
        bounded_notes = (
            *bounded_notes,
            "No complete source inventory was supplied; unobserved dependencies remain unknown.",
        )
    return SourceBundle(files=tuple(files), complete=complete, notes=bounded_notes)


# ---------------------------------------------------------------------------
# Reading a project
#
# Everything below is scoped to the project the key belongs to, and needs a
# `read` key rather than the `scan` key a pipeline holds. The split is the
# point: a key that can push results is not automatically a key that can read
# the findings list or edit the rules, so one leaked from a build log stays as
# narrow as it was before any of this existed.
#
# These exist so the CLI can do what the dashboard does. Somebody who never
# opens the web interface should still be able to see what their project looks
# like.
# ---------------------------------------------------------------------------


@router.get("/project")
async def project_status(db: DbSession, key: ReadKey):
    """This project at a glance: the same numbers the dashboard leads with."""
    target = key.target
    counts = await _severity_counts(db, target.id)
    # Reused from the targets router rather than reimplemented: two
    # implementations of "how many are on each tab" would eventually
    # disagree, and the API would be the copy nobody noticed had drifted.
    from app.routes.targets import _tab_counts

    tabs = await _tab_counts(db, target.id)

    return {
        "project": target.name,
        "plan": await _plan_for(db, key),
        "ecosystem": str(target.ecosystem),
        "dependencies": target.dependency_count,
        "last_scanned_at": _iso(target.last_scanned_at),
        "next_scan_at": _iso(target.next_scan_at),
        "last_error": target.last_scan_error,
        "counts": counts,
        "open": tabs["open"],
        # The number this product is proud of: advisories that matched and were
        # deliberately not reported.
        "filtered": tabs["filtered"],
        "dismissed": tabs["dismissed"],
        "resolved": tabs["resolved"],
        # Said out loud rather than left to be inferred from a smaller number:
        # packages the plan did not reach were never examined.
        "unreached_by_depth": target.unreached_by_depth,
        "dashboard_url": f"{get_settings().base_url.rstrip('/')}/targets/{target.id}",
    }


@router.get("/findings")
async def list_findings(
    db: DbSession,
    key: ReadKey,
    show: str = "open",
    limit: int = 50,
):
    """Findings for this project, worst first.

    `show` mirrors the tabs in the interface -- open, filtered, dismissed,
    resolved -- because somebody moving between the two should not have to
    learn a second vocabulary for the same four things.
    """
    limit = max(1, min(limit, 200))

    where = [CVEMatch.target_id == key.target_id]
    if show == "filtered":
        where.extend(
            [
                CVEMatch.verdict == Verdict.SUPPRESSED,
                CVEMatch.status == AlertStatus.FILTERED,
            ]
        )
    elif show == "dismissed":
        where.append(CVEMatch.status == AlertStatus.DISMISSED)
    elif show == "resolved":
        where.append(CVEMatch.status == AlertStatus.RESOLVED)
    else:
        show = "open"
        where.extend([CVEMatch.verdict == Verdict.ACTIONABLE, CVEMatch.status == AlertStatus.OPEN])

    rows = (
        await db.execute(
            select(CVEMatch, VulnerabilityRecord)
            .join(VulnerabilityRecord, VulnerabilityRecord.id == CVEMatch.vulnerability_id)
            .where(*where)
            .order_by(CVEMatch.is_kev.desc(), SEVERITY_RANK.desc(), CVEMatch.package_name)
            .limit(limit)
        )
    ).all()

    return {
        "show": show,
        "plan": await _plan_for(db, key),
        "count": len(rows),
        "findings": [
            {
                "id": match.id,
                "package": match.package_name,
                "version": match.package_version,
                "cve": (record.cve_ids or [match.vulnerability_id])[0],
                "advisory": match.vulnerability_id,
                "severity": str(match.severity).lower(),
                "exploited": bool(match.is_kev),
                "malicious": match.actionable_reason == ActionableReason.MALICIOUS_PACKAGE,
                "epss": match.epss_score,
                "fixed_in": match.fixed_version,
                "summary": record.summary,
                # How the package got into the tree, which is usually the
                # difference between "upgrade this" and "upgrade what wants it".
                "via": list(match.via or []),
                "depth": match.depth,
                "dependency_relationship": str(match.reachability),
                "reachability": str(match.automated_reachability),
                "reachability_evidence": list(match.reachability_evidence or []),
                "status": str(match.status),
                "reason": (
                    match.actionable_reason.label
                    if match.actionable_reason
                    else (match.suppression_reason.label if match.suppression_reason else "")
                ),
                "first_seen_at": _iso(match.first_seen_at),
            }
            for match, record in rows
        ],
    }


@router.get("/history")
async def scan_history(db: DbSession, key: ReadKey, limit: int = 20):
    """Recent scans, newest first. What the Recent checks panel shows."""
    limit = max(1, min(limit, 100))
    rows = (
        await db.execute(
            select(ScanRun)
            .where(ScanRun.target_id == key.target_id)
            .order_by(ScanRun.started_at.desc())
            .limit(limit)
        )
    ).scalars()

    return {
        "runs": [
            {
                "started_at": _iso(run.started_at),
                "status": run.status,
                "dependencies_scanned": run.dependencies_scanned,
                "actionable": run.actionable_count,
                "suppressed": run.suppressed_count,
                "new": run.new_actionable_count,
                "resolved": run.resolved_count,
                "duration_seconds": run.duration_seconds,
                "error": run.error,
            }
            for run in rows
        ]
    }


@router.get("/supply-chain")
async def supply_chain(db: DbSession, key: ReadKey):
    """Signals about the packages themselves, rather than versions of them."""
    from app.services.supply_chain_service import open_signals

    rows = await open_signals(db, key.target_id)
    return {
        "signals": [
            {
                "package": row.package_name,
                "version": row.package_version,
                "kind": row.kind.value,
                "label": row.kind.label,
                "level": row.level.value,
                "detail": row.detail,
            }
            for row in rows
        ]
    }


# ---------------------------------------------------------------------------
# Changing a project's rules
#
# `manage` scope only. This is the boundary that matters: a key that can add an
# ignore rule can silence an alert, so it must never be the key sitting in a CI
# environment variable where anyone who can read a build log can take it.
# ---------------------------------------------------------------------------


@router.get("/rules")
async def list_scan_rules(db: DbSession, key: ManageKey):
    from app.core.policy import parse_policy
    from app.services.rules_service import list_rules

    target = key.target
    policy = parse_policy(target.policy_file)

    return {
        "thresholds": {
            "direct": str(target.direct_threshold) if target.direct_threshold else None,
            "transitive": (
                str(target.transitive_threshold) if target.transitive_threshold else None
            ),
            "epss": target.epss_threshold,
        },
        "ignores": [
            {
                "identifier": rule.identifier,
                "kind": str(rule.kind),
                "reason": rule.reason,
                "created_by": rule.created_by_email,
                "created_at": _iso(rule.created_at),
                # A rule a KEV listing set aside. Reported so somebody reading
                # this in a terminal sees it stopped applying.
                "overridden_at": _iso(rule.overridden_at),
            }
            for rule in await list_rules(db, target.id)
        ],
        "policy_file": {
            "present": bool(target.policy_file),
            "updated_at": _iso(target.policy_file_updated_at),
            "error": target.policy_file_error,
            "ignores": list(policy.ignored_ids),
            "ignored_packages": list(policy.ignored_packages),
        },
        # Here more than anywhere else. A Free account with rules configured
        # gets a tidy list of things that are not doing anything, and without
        # this there is nothing on the page to say so -- which is the exact
        # shape of failure this product exists to avoid.
        "plan": await _plan_for(db, key),
    }


@router.get("/profiles")
async def list_rule_profiles(db: DbSession, key: ReadKey):
    """The account's rule profiles, and which one this project uses.

    Read scope rather than manage: knowing which rule sets exist is part of
    understanding what a scan reported, and a CI key that can see the name it
    is meant to pass is a CI key that fails with a useful message rather than a
    puzzle.

    The documents are included. They are rules, not credentials, and a pipeline
    that can see them can explain its own results without a second call.
    """
    from app.services.profile_service import list_profiles

    target = key.target
    rows = await list_profiles(db, key.user_id)

    return {
        "profiles": [
            {
                "name": profile.name,
                # What --profile matches. Given explicitly so nobody has to
                # reproduce the normalisation by guesswork.
                "slug": profile.slug,
                "description": profile.description,
                "is_default": profile.is_default,
                "in_use_here": profile.id == target.profile_id,
                "document": profile.document,
            }
            for profile in rows
        ],
        # What this project would use if a scan ran with no --profile. Answers
        # the question the listing is usually opened for.
        "applies_here": next(
            (
                profile.slug
                for profile in rows
                if profile.id == target.profile_id
                or (target.profile_id is None and profile.is_default)
            ),
            None,
        ),
    }


@router.post("/rules")
async def add_scan_rule(request: Request, db: DbSession, key: ManageKey):
    """Ignore an advisory, or a family of packages, on this project.

    The reason is required. `kind` is `advisory` by default, so every client
    written before package rules existed keeps working and keeps meaning what
    it meant.
    """
    from app.core.types import IgnoreKind
    from app.models import IgnoreRule
    from app.schemas import IgnoreRuleForm
    from app.services.rules_service import list_rules

    owner = await db.get(User, key.user_id)
    if owner is None:
        raise _fail(status.HTTP_401_UNAUTHORIZED, "unauthenticated", "That account is gone.")

    try:
        payload = await request.json()
    except Exception:
        raise _fail(status.HTTP_400_BAD_REQUEST, "bad_json", "Send a JSON body.") from None
    if not isinstance(payload, dict):
        raise _fail(status.HTTP_400_BAD_REQUEST, "bad_json", "Send a JSON object.")

    raw_kind = payload.get("kind") or IgnoreKind.ADVISORY.value
    try:
        kind = IgnoreKind(str(raw_kind).strip().lower())
    except ValueError:
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "invalid_rule",
            "An ignore rule names either an advisory or a package.",
        ) from None

    try:
        form = IgnoreRuleForm(
            identifier=str(payload.get("identifier", "")),
            reason=str(payload.get("reason", "")),
            kind=kind,
        )
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "invalid_rule", _first_error(exc)) from None

    existing = await list_rules(db, key.target_id)
    if any(r.kind is form.kind and r.identifier == form.identifier for r in existing):
        raise _fail(
            status.HTTP_409_CONFLICT,
            "already_ignored",
            f"{form.identifier} is already ignored on this project.",
        )

    db.add(
        IgnoreRule(
            target_id=key.target_id,
            identifier=form.identifier,
            kind=form.kind,
            reason=form.reason,
            # Attributed to the key rather than to a person: nobody was at a
            # keyboard, and recording an account that did not do it would make
            # the audit trail a guess.
            created_by_email=f"api key {key.prefix}",
        )
    )
    await db.commit()

    log.info(
        "api.rule_added",
        target_id=key.target_id,
        identifier=form.identifier,
        kind=str(form.kind),
    )
    return {"identifier": form.identifier, "kind": str(form.kind), "reason": form.reason}


@router.delete("/rules/{identifier}")
async def remove_scan_rule(db: DbSession, key: ManageKey, identifier: str):
    """Remove one rule by what it names.

    Case-insensitive on both kinds, so a package rule stored as `@acme/*` comes
    off whether the caller types it that way or not. Advisory ids and package
    globs do not collide in practice -- one is `CVE-...`, the other has a slash
    or a wildcard -- so a single path parameter is enough.
    """
    from app.services.rules_service import list_rules

    wanted = identifier.strip().casefold()
    for rule in await list_rules(db, key.target_id):
        if rule.identifier.casefold() == wanted:
            removed = {"identifier": rule.identifier, "kind": str(rule.kind), "removed": True}
            await db.delete(rule)
            await db.commit()
            log.info("api.rule_removed", target_id=key.target_id, identifier=rule.identifier)
            return removed

    raise _fail(
        status.HTTP_404_NOT_FOUND, "no_such_rule", f"{identifier.strip()} is not ignored here."
    )


def _iso(value) -> str | None:
    return value.isoformat() if value else None


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

    counts["malicious"] = (
        await db.scalar(
            select(func.count(CVEMatch.id)).where(
                CVEMatch.target_id == target_id,
                CVEMatch.verdict == Verdict.ACTIONABLE,
                CVEMatch.status == AlertStatus.OPEN,
                CVEMatch.actionable_reason == ActionableReason.MALICIOUS_PACKAGE,
            )
        )
    ) or 0

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


#: How many findings the response spells out. The rest are behind the dashboard
#: link — a build log that scrolls for two hundred lines is one nobody reads.
MAX_INLINE_FINDINGS = 20


async def _blocking_findings(db, target_id: int) -> list[dict]:
    """The findings a pipeline might stop for, worst first, with their fixes.

    High severity is included as well as critical and exploited, because the
    CLI's `--fail-on high` lets the caller choose where the line sits. The
    server sends what could matter and the client decides what does; deciding
    here would mean a pipeline configured to fail on high had nothing to print
    when it failed.
    """
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
                CVEMatch.actionable_reason,
                CVEMatch.automated_reachability,
                CVEMatch.reachability_evidence,
            )
            .join(VulnerabilityRecord, VulnerabilityRecord.id == CVEMatch.vulnerability_id)
            .where(
                CVEMatch.target_id == target_id,
                CVEMatch.verdict == Verdict.ACTIONABLE,
                CVEMatch.status == AlertStatus.OPEN,
                CVEMatch.severity.in_((Severity.CRITICAL, Severity.HIGH))
                | CVEMatch.is_kev.is_(True)
                # Malware carries no CVSS score, so a severity filter alone
                # drops it -- which would leave the worst finding this scanner
                # can produce out of the list a pipeline gates on.
                | (CVEMatch.actionable_reason == ActionableReason.MALICIOUS_PACKAGE),
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
            # Its own field rather than a severity value. A client that has not
            # been taught about this yet still sees `exploited: false` and a
            # severity it understands, rather than a level it cannot rank.
            "malicious": reason == ActionableReason.MALICIOUS_PACKAGE,
            "reachability": str(reachability),
            "reachability_evidence": list(evidence or []),
        }
        for cve_ids, package, version, fixed, severity, is_kev, reason, reachability, evidence in rows
    ]
