"""Projects, for the React application.

The JSON face of everything the project page does: reading one project,
creating one, renaming it, attaching a manifest, rescanning, deleting, and the
three things that shape what it reports — ignore rules, thresholds and webhooks.

Two conventions, both inherited rather than invented here:

  * Ownership is re-checked on every call through `get_target_for_user`, which
    returns None for somebody else's project. That becomes a 404 rather than a
    403 — a 403 confirms the project exists, and whether an id is real is not
    something a stranger should be able to learn by asking.
  * Nothing is serialised from the ORM. Each response is an explicit view, so a
    column added later cannot reach a browser by accident.

None of the decisions live here. Creating, scanning and deleting go through
target_service and scan_service exactly as the rendered routes do.
"""

from __future__ import annotations

from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError
from sqlalchemy import desc, select

from app.config import get_settings
from app.core.types import IgnoreKind, KeyScope, Severity
from app.deps import CsrfProtected, CurrentInternalUser, DbSession
from app.logging_config import get_logger
from app.models import CVEMatch, DependencyRecord, ScanRun
from app.schemas import (
    FindingAttentionView,
    FindingProjectView,
    IgnoreRuleForm,
    NewProjectForm,
    PasteManifestForm,
    ProjectApiKeyView,
    ProjectDependencyView,
    ProjectDetailView,
    ProjectIgnoreRuleView,
    ProjectPageResponse,
    ProjectPolicyFileView,
    ProjectRunView,
    ProjectSignalView,
    ProjectThresholdsView,
    ProjectWebhookView,
    TargetCreateForm,
    first_error,
)
from app.services.api_key_service import (
    ApiKeyError,
    issue_api_key,
    keys_for_target,
    revoke_api_key,
)
from app.services.rules_service import list_rules
from app.services.scan_service import scan_target
from app.services.supply_chain_service import open_signals
from app.services.target_service import (
    TargetLimitReached,
    UnsupportedManifest,
    create_empty_target,
    create_target,
    delete_target,
    get_target_for_user,
    replace_manifest,
)
from app.tiers import can_use_custom_rules, can_use_webhooks

log = get_logger(__name__)

router = APIRouter(prefix="/api/internal", tags=["internal-projects"])


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"


def _fail(status_code: int, code: str, message: str) -> HTTPException:
    """The error envelope the React client parses."""
    return HTTPException(
        status_code=status_code, detail={"error": {"code": code, "message": message}}
    )


async def _owned(db, user, target_id: int):
    """The project, or a 404.

    404 and not 403 on somebody else's project. A 403 confirms the id exists,
    which turns this endpoint into a way to count how many projects the service
    holds and to probe for particular ones.
    """
    target = await get_target_for_user(db, user.id, target_id)
    if target is None:
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That project doesn't exist.")
    return target


# ---------------------------------------------------------------------------
# Reading one project
# ---------------------------------------------------------------------------


@router.get("/projects/{target_id}", response_model=ProjectPageResponse)
async def project_page(
    response: Response,
    db: DbSession,
    user: CurrentInternalUser,
    target_id: int,
    show: str = "open",
) -> ProjectPageResponse:
    """Everything the project page renders, in one response."""
    _no_store(response)
    target = await _owned(db, user, target_id)

    from app.core.types import AlertStatus, Verdict
    from app.routes.targets import SEVERITY_RANK, _tab_counts

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

    runs = list(
        (
            await db.scalars(
                select(ScanRun)
                .where(ScanRun.target_id == target.id)
                .order_by(desc(ScanRun.started_at))
                .limit(10)
            )
        ).all()
    )

    tab_counts = await _tab_counts(db, target.id)
    project = FindingProjectView(id=target.id, name=target.name)

    return ProjectPageResponse(
        data=_detail_view(target, tab_counts),
        findings=[_finding_view(match, project) for match in matches],
        dependencies=[
            ProjectDependencyView(
                name=row.name,
                version=row.version or "",
                depth=row.depth or 0,
                is_direct=(row.depth or 0) <= 1,
            )
            for row in dependencies
        ],
        recent_runs=[
            ProjectRunView(
                started_at=run.started_at,
                status=run.status,
                dependencies_scanned=run.dependencies_scanned,
                actionable_count=run.actionable_count,
                suppressed_count=run.suppressed_count,
                new_actionable_count=run.new_actionable_count,
                resolved_count=run.resolved_count,
                duration_seconds=run.duration_seconds,
                error=run.error,
            )
            for run in runs
        ],
        supply_chain=[
            ProjectSignalView(
                package_name=signal.package_name,
                package_version=signal.package_version,
                kind=signal.kind.value,
                label=signal.kind.label,
                level=signal.level.value,
                detail=signal.detail,
            )
            for signal in await open_signals(db, target.id)
        ],
        rules=[
            ProjectIgnoreRuleView(
                id=rule.id,
                identifier=rule.identifier,
                kind=rule.kind,
                reason=rule.reason,
                created_by_email=rule.created_by_email,
                created_at=rule.created_at,
                overridden_at=rule.overridden_at,
            )
            for rule in await list_rules(db, target.id)
        ],
        thresholds=ProjectThresholdsView(
            direct=target.direct_threshold,
            transitive=target.transitive_threshold,
            epss=target.epss_threshold,
        ),
        policy_file=_policy_view(target),
        api_keys=[
            ProjectApiKeyView(
                id=key.id,
                prefix=key.prefix,
                name=key.name,
                scope=key.scope,
                created_at=key.created_at,
                last_used_at=key.last_used_at,
                call_count=key.call_count,
                is_active=key.is_active,
                revoked_at=key.revoked_at,
            )
            for key in await keys_for_target(db, target.id)
        ],
        webhook=_webhook_view(target),
        can_use_rules=can_use_custom_rules(user.tier),
        can_use_webhooks=can_use_webhooks(user.tier),
    )


def _detail_view(target, tab_counts: dict[str, int]) -> ProjectDetailView:
    return ProjectDetailView(
        id=target.id,
        name=target.name,
        ecosystem=target.ecosystem,
        manifest_kind=str(target.manifest_kind) if target.manifest_kind else None,
        has_manifest=target.has_manifest,
        dependency_count=target.dependency_count,
        is_active=target.is_active,
        last_scanned_at=target.last_scanned_at,
        next_scan_at=target.next_scan_at,
        last_scan_error=target.last_scan_error,
        unreached_by_depth=target.unreached_by_depth or 0,
        counts={
            "critical": tab_counts.get("critical", 0),
            "high": tab_counts.get("high", 0),
        },
        tab_counts=tab_counts,
    )


def _finding_view(match, project: FindingProjectView) -> FindingAttentionView:
    return FindingAttentionView(
        id=match.id,
        project=project,
        identifier=match.vulnerability_id,
        package_name=match.package_name,
        installed_version=match.package_version,
        severity=match.severity,
        is_exploited=bool(match.is_kev),
        reachability=match.reachability,
        status=match.status,
        detected_at=match.first_seen_at,
    )


def _policy_view(target) -> ProjectPolicyFileView:
    from app.core.policy import parse_policy

    policy = parse_policy(target.policy_file)
    return ProjectPolicyFileView(
        present=bool(target.policy_file),
        updated_at=target.policy_file_updated_at,
        error=target.policy_file_error,
        ignored_ids=sorted(policy.ignored_ids),
    )


def _webhook_view(target) -> ProjectWebhookView:
    """The host, never the URL.

    A webhook URL is a credential: whoever holds it can post into the channel.
    The rendered settings page never shows it back either, and an endpoint that
    did would hand it to any XSS bug on the page.
    """
    raw = target.discord_webhook_url
    if not raw:
        return ProjectWebhookView(configured=False, kind=None, host=None)
    try:
        host = urlparse(raw).hostname
    except ValueError:
        host = None
    return ProjectWebhookView(
        configured=True,
        kind=str(target.webhook_kind) if target.webhook_kind else None,
        host=host,
    )


# ---------------------------------------------------------------------------
# Creating a project
# ---------------------------------------------------------------------------


@router.post("/projects", dependencies=[CsrfProtected], status_code=status.HTTP_201_CREATED)
async def create_project(
    db: DbSession,
    user: CurrentInternalUser,
    name: Annotated[str, Form()] = "",
    ecosystem: Annotated[str, Form()] = "",
    manifest: Annotated[UploadFile | None, File()] = None,
    content: Annotated[str, Form()] = "",
    filename: Annotated[str, Form()] = "",
) -> JSONResponse:
    """Create a project, with or without a manifest.

    Multipart rather than JSON, because one of the three ways in is a file
    upload and base64 in a JSON body would cost a third more bytes for no gain.
    The other two — pasted text, or neither — arrive as ordinary form fields.
    """
    settings = get_settings()

    if not (manifest is not None and manifest.filename) and not content.strip():
        try:
            form = NewProjectForm(name=name, ecosystem=ecosystem)
        except ValidationError as exc:
            raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None

        try:
            target = await create_empty_target(db, user, form.name, form.ecosystem)
        except TargetLimitReached as exc:
            raise _fail(status.HTTP_402_PAYMENT_REQUIRED, "LIMIT_REACHED", str(exc)) from None
        except UnsupportedManifest as exc:
            raise _fail(status.HTTP_400_BAD_REQUEST, "UNSUPPORTED", str(exc)) from None

        await db.commit()
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"data": {"id": target.id, "name": target.name, "scanned": False}},
        )

    text_content, upload_name = await _read_manifest(settings, manifest, content, filename, name)

    try:
        meta = TargetCreateForm(name=name)
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None

    try:
        target = await create_target(db, user, upload_name, text_content, meta.name)
    except TargetLimitReached as exc:
        raise _fail(status.HTTP_402_PAYMENT_REQUIRED, "LIMIT_REACHED", str(exc)) from None
    except UnsupportedManifest as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "UNSUPPORTED", str(exc)) from None

    await db.commit()

    # Scanned immediately rather than at the next tick: an empty project right
    # after signup is how a trial ends early. A failure here is logged and
    # swallowed — the project exists, and the scheduler will try again.
    scanned = True
    try:
        from app.services.alert_service import mark_delivered_in_app

        outcome = await scan_target(db, target)
        mark_delivered_in_app(outcome.new_matches)
        await db.commit()
    except Exception as exc:
        log.warning("target.initial_scan_failed", target_id=target.id, error=str(exc))
        await db.rollback()
        scanned = False

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"data": {"id": target.id, "name": target.name, "scanned": scanned}},
    )


async def _read_manifest(settings, manifest, content: str, filename: str, name: str):
    """The uploaded or pasted manifest, validated the same way for both."""
    if manifest is not None and manifest.filename:
        raw = await manifest.read()
        if len(raw) > settings.max_manifest_bytes:
            raise _fail(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                "TOO_LARGE",
                f"That file is larger than {settings.max_manifest_bytes // (1024 * 1024)} MB.",
            )
        try:
            return raw.decode("utf-8"), manifest.filename
        except UnicodeDecodeError:
            raise _fail(
                status.HTTP_400_BAD_REQUEST,
                "NOT_TEXT",
                "That file isn't valid UTF-8 text — is it a binary file?",
            ) from None

    try:
        form = PasteManifestForm(name=name, filename=filename, content=content)
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None
    return form.content, form.filename or "pasted-manifest"


# ---------------------------------------------------------------------------
# Changing a project
# ---------------------------------------------------------------------------


class RenameBody(BaseModel):
    name: str = ""


@router.post("/projects/{target_id}/rename", dependencies=[CsrfProtected])
async def rename_project(
    db: DbSession, user: CurrentInternalUser, target_id: int, body: RenameBody
) -> dict:
    target = await _owned(db, user, target_id)

    try:
        form = TargetCreateForm(name=body.name)
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None

    target.name = form.name
    await db.commit()
    return {"data": {"id": target.id, "name": target.name}}


@router.post("/projects/{target_id}/manifest", dependencies=[CsrfProtected])
async def attach_project_manifest(
    db: DbSession,
    user: CurrentInternalUser,
    target_id: int,
    manifest: Annotated[UploadFile | None, File()] = None,
    content: Annotated[str, Form()] = "",
    filename: Annotated[str, Form()] = "",
) -> dict:
    """Replace the manifest and rescan."""
    target = await _owned(db, user, target_id)
    settings = get_settings()

    text_content, upload_name = await _read_manifest(
        settings, manifest, content, filename, target.name
    )

    try:
        # Keyword arguments deliberately. create_target takes (filename,
        # content) and replace_manifest takes (content, filename) — passing
        # them positionally here sent the name in as the file and the file in
        # as the name, and the only symptom was "could not recognise that
        # file" about a perfectly ordinary package.json.
        await replace_manifest(db, target, content=text_content, filename=upload_name)
    except UnsupportedManifest as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "UNSUPPORTED", str(exc)) from None

    await db.commit()

    try:
        from app.services.alert_service import mark_delivered_in_app

        outcome = await scan_target(db, target)
        mark_delivered_in_app(outcome.new_matches)
        await db.commit()
    except Exception as exc:
        log.warning("target.rescan_after_manifest_failed", target_id=target.id, error=str(exc))
        await db.rollback()

    return {"data": {"id": target.id, "dependency_count": target.dependency_count}}


@router.post("/projects/{target_id}/scan", dependencies=[CsrfProtected])
async def rescan_project(db: DbSession, user: CurrentInternalUser, target_id: int) -> dict:
    target = await _owned(db, user, target_id)

    if not target.has_manifest:
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "NO_MANIFEST",
            "There is nothing to scan yet. Attach a manifest first.",
        )

    try:
        outcome = await scan_target(db, target)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        log.warning("target.manual_scan_failed", target_id=target.id, error=str(exc))
        raise _fail(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "SCAN_FAILED",
            "The scan could not run just now. Try again shortly.",
        ) from None

    return {
        "data": {
            "actionable": outcome.actionable_count,
            "suppressed": outcome.suppressed_count,
            # ScanOutcome carries the matches themselves, not a count — the
            # alerting step needs the rows. The page only needs how many.
            "new": len(outcome.new_matches),
            "resolved": outcome.resolved_count,
            "unreached_by_depth": outcome.unreached_by_depth,
        }
    }


@router.post("/projects/{target_id}/delete", dependencies=[CsrfProtected])
async def delete_project(db: DbSession, user: CurrentInternalUser, target_id: int) -> dict:
    target = await _owned(db, user, target_id)
    await delete_target(db, target)
    await db.commit()
    log.info("target.deleted", target_id=target_id, user_id=user.id)
    return {"data": {"deleted": True}}


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


class NewKeyBody(BaseModel):
    name: str = ""
    scope: str = KeyScope.SCAN.value


@router.post("/projects/{target_id}/keys", dependencies=[CsrfProtected])
async def create_project_api_key(
    db: DbSession, user: CurrentInternalUser, target_id: int, body: NewKeyBody
) -> dict:
    """Issue a key. The plaintext is in this response and nowhere else.

    Never a redirect parameter, which is what the rendered page was careful to
    avoid too: a live credential in a URL ends up in browser history, the
    Referer header, and every proxy log between here and the user.
    """
    target = await _owned(db, user, target_id)

    try:
        chosen = KeyScope(body.scope)
    except ValueError:
        chosen = KeyScope.SCAN

    try:
        issued = await issue_api_key(db, user, target, body.name, scope=chosen)
    except ApiKeyError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "KEY_REFUSED", str(exc)) from None

    await db.commit()
    return {
        "data": {
            "id": issued.record.id,
            "prefix": issued.record.prefix,
            "scope": issued.record.scope.value,
            "token": issued.token,
        }
    }


@router.post("/projects/{target_id}/keys/{key_id}/revoke", dependencies=[CsrfProtected])
async def revoke_project_api_key(
    db: DbSession, user: CurrentInternalUser, target_id: int, key_id: int
) -> dict:
    await _owned(db, user, target_id)

    if not await revoke_api_key(db, user, key_id):
        raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That key doesn't exist.")

    await db.commit()
    return {"data": {"revoked": True}}


# ---------------------------------------------------------------------------
# Rules and thresholds
# ---------------------------------------------------------------------------


class ThresholdsBody(BaseModel):
    direct: str = ""
    transitive: str = ""
    epss: float | None = None


def _ignore_kind(raw: object) -> IgnoreKind:
    """Default to `advisory` rather than refusing an absent kind.

    Every client that predates package rules sends no kind and means an
    advisory, and that is also the safer default: a value misread as a package
    glob could silence more than the caller asked for, and one misread as an
    advisory id silences nothing that is not named outright.
    """
    if raw is None or raw == "":
        return IgnoreKind.ADVISORY
    try:
        return IgnoreKind(str(raw).strip().lower())
    except ValueError:
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "INVALID_REQUEST",
            "An ignore rule names either an advisory or a package.",
        ) from None


def _require_rules(user) -> None:
    if not can_use_custom_rules(user.tier):
        raise _fail(
            status.HTTP_402_PAYMENT_REQUIRED,
            "PRO_REQUIRED",
            "Custom scan rules are part of the Pro plan.",
        )


@router.post("/projects/{target_id}/rules", dependencies=[CsrfProtected])
async def add_project_rule(
    request: Request, db: DbSession, user: CurrentInternalUser, target_id: int
) -> dict:
    from app.models import IgnoreRule

    target = await _owned(db, user, target_id)
    _require_rules(user)

    payload = await request.json()
    try:
        form = IgnoreRuleForm(
            identifier=str(payload.get("identifier", "")),
            reason=str(payload.get("reason", "")),
            kind=_ignore_kind(payload.get("kind")),
        )
    except ValidationError as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", first_error(exc)) from None

    existing = await list_rules(db, target.id)
    if any(r.kind is form.kind and r.identifier == form.identifier for r in existing):
        raise _fail(
            status.HTTP_409_CONFLICT,
            "ALREADY_IGNORED",
            f"{form.identifier} is already ignored on this project.",
        )

    rule = IgnoreRule(
        target_id=target.id,
        identifier=form.identifier,
        kind=form.kind,
        reason=form.reason,
        created_by_email=user.email,
    )
    db.add(rule)
    await db.commit()
    return {
        "data": {
            "id": rule.id,
            "identifier": rule.identifier,
            "kind": str(rule.kind),
            "reason": rule.reason,
        }
    }


@router.post("/projects/{target_id}/rules/{rule_id}/delete", dependencies=[CsrfProtected])
async def remove_project_rule(
    db: DbSession, user: CurrentInternalUser, target_id: int, rule_id: int
) -> dict:
    target = await _owned(db, user, target_id)
    _require_rules(user)

    for rule in await list_rules(db, target.id):
        if rule.id == rule_id:
            await db.delete(rule)
            await db.commit()
            return {"data": {"deleted": True}}

    raise _fail(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "That rule doesn't exist.")


@router.post("/projects/{target_id}/thresholds", dependencies=[CsrfProtected])
async def set_project_thresholds(
    db: DbSession, user: CurrentInternalUser, target_id: int, body: ThresholdsBody
) -> dict:
    target = await _owned(db, user, target_id)
    _require_rules(user)

    def parse(value: str) -> Severity | None:
        """An empty value means "use the default", which is not the same as a
        threshold of low — so it is stored as NULL rather than a floor."""
        if not value:
            return None
        try:
            return Severity(value)
        except ValueError:
            raise _fail(
                status.HTTP_400_BAD_REQUEST, "INVALID_REQUEST", f"Unknown severity {value!r}."
            ) from None

    target.direct_threshold = parse(body.direct)
    target.transitive_threshold = parse(body.transitive)

    if body.epss is not None and not (0 <= body.epss <= 100):
        raise _fail(
            status.HTTP_400_BAD_REQUEST,
            "INVALID_REQUEST",
            "Exploit likelihood is a percentage between 0 and 100.",
        )
    target.epss_threshold = body.epss

    await db.commit()
    return {
        "data": {
            "direct": str(target.direct_threshold) if target.direct_threshold else None,
            "transitive": str(target.transitive_threshold) if target.transitive_threshold else None,
            "epss": target.epss_threshold,
        }
    }


# ---------------------------------------------------------------------------
# Webhooks
#
# The URL is write-only from the browser's side. It goes in through these
# endpoints and never comes back out — see `_webhook_view` above for why.
# ---------------------------------------------------------------------------


class WebhookBody(BaseModel):
    url: str = ""
    kind: str = "discord"


def _require_webhooks(user) -> None:
    if not can_use_webhooks(user.tier):
        raise _fail(
            status.HTTP_402_PAYMENT_REQUIRED,
            "PRO_REQUIRED",
            "Webhook alerts are part of the Pro plan.",
        )


@router.post("/projects/{target_id}/webhook", dependencies=[CsrfProtected])
async def save_project_webhook(
    db: DbSession, user: CurrentInternalUser, target_id: int, body: WebhookBody
) -> dict:
    from app.core.webhooks import InvalidWebhookURL, WebhookKind, validate_custom_url
    from app.models import utcnow
    from app.services.discord_service import parse_webhook_url

    target = await _owned(db, user, target_id)
    _require_webhooks(user)

    kind = WebhookKind.CUSTOM if body.kind == WebhookKind.CUSTOM else WebhookKind.DISCORD

    try:
        # Two rules, because the two are guarded differently. Discord is an
        # allowlist of four hostnames; a custom endpoint is somebody else's
        # server, so it is a deny-list of every address a request must not
        # reach. app/core/webhooks.py explains why that asymmetry is deliberate.
        stored = (
            validate_custom_url(body.url).url
            if kind is WebhookKind.CUSTOM
            else parse_webhook_url(body.url).url
        )
    except InvalidWebhookURL as exc:
        raise _fail(status.HTTP_400_BAD_REQUEST, "INVALID_WEBHOOK", str(exc)) from None

    target.webhook_kind = kind.value
    target.discord_webhook_url = stored
    # A new URL has not failed yet, and carrying the old error forward would
    # show a freshly pasted webhook as broken.
    target.discord_last_error = None
    target.discord_last_sent_at = None
    target.updated_at = utcnow()
    await db.commit()

    # Never the URL itself: this line goes to a log aggregator.
    log.info("target.webhook_saved", target_id=target.id, user_id=user.id, kind=kind.value)
    return {"data": _webhook_view(target).model_dump()}


@router.post("/projects/{target_id}/webhook/test", dependencies=[CsrfProtected])
async def test_project_webhook(db: DbSession, user: CurrentInternalUser, target_id: int) -> dict:
    """Post a message that says it is a test.

    Worth its own button. The failure this catches — a webhook pointing at the
    wrong channel, or one somebody deleted last week — is otherwise discovered
    on the day a critical finding lands and nobody hears about it.
    """
    from app.core.webhooks import WebhookKind
    from app.models import utcnow
    from app.services.discord_service import build_test_payload, post_webhook

    target = await _owned(db, user, target_id)
    _require_webhooks(user)

    if not target.discord_webhook_url:
        raise _fail(status.HTTP_400_BAD_REQUEST, "NO_WEBHOOK", "Add a webhook URL first.")

    payload = (
        {
            "source": "weedout",
            "event": "webhook.test",
            "project": target.name,
            "message": "This is a test from Weedout. Real alerts carry findings.",
        }
        if target.webhook_kind == WebhookKind.CUSTOM
        else build_test_payload(project=target.name)
    )
    result = await post_webhook(target.discord_webhook_url, payload, kind=target.webhook_kind)

    if result.ok:
        target.discord_last_sent_at = utcnow()
        target.discord_last_error = None
        await db.commit()
        return {"data": {"delivered": True, "message": "Test message sent. Check the channel."}}

    target.discord_last_error = (result.error or "Delivery failed")[:500]
    await db.commit()
    raise _fail(
        status.HTTP_502_BAD_GATEWAY,
        "DELIVERY_FAILED",
        result.error or "The test message did not go through.",
    )


@router.post("/projects/{target_id}/webhook/remove", dependencies=[CsrfProtected])
async def remove_project_webhook(db: DbSession, user: CurrentInternalUser, target_id: int) -> dict:
    from app.core.webhooks import WebhookKind
    from app.models import utcnow

    target = await _owned(db, user, target_id)

    target.discord_webhook_url = None
    target.webhook_kind = WebhookKind.DISCORD.value
    target.discord_last_error = None
    target.discord_last_sent_at = None
    target.updated_at = utcnow()
    await db.commit()

    log.info("target.webhook_removed", target_id=target.id, user_id=user.id)
    return {"data": {"configured": False}}
