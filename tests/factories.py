"""Small builders for core dataclasses, so tests state only what they exercise."""

from __future__ import annotations

from app.core.types import (
    AffectedPackage,
    AffectedRange,
    Dependency,
    Ecosystem,
    KevEntry,
    Reachability,
    Severity,
    Vulnerability,
)


def dep(
    name: str = "lodash",
    version: str = "4.17.15",
    ecosystem: Ecosystem = Ecosystem.NPM,
    reachability: Reachability = Reachability.RUNTIME_DIRECT,
    version_exact: bool = True,
    version_spec: str | None = None,
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        version_spec=version_spec if version_spec is not None else version,
        reachability=reachability,
        version_exact=version_exact,
    )


def affected(
    name: str = "lodash",
    ecosystem: Ecosystem = Ecosystem.NPM,
    introduced: str | None = "0",
    fixed: str | None = "4.17.21",
    last_affected: str | None = None,
    versions: tuple[str, ...] = (),
) -> AffectedPackage:
    ranges: tuple[AffectedRange, ...] = ()
    if introduced is not None or fixed is not None or last_affected is not None:
        ranges = (AffectedRange(introduced=introduced, fixed=fixed, last_affected=last_affected),)
    return AffectedPackage(ecosystem=ecosystem, name=name, ranges=ranges, versions=versions)


def vuln(
    vuln_id: str = "GHSA-test-0001",
    severity: Severity = Severity.HIGH,
    aliases: tuple[str, ...] = ("CVE-2020-8203",),
    affected_packages: tuple[AffectedPackage, ...] | None = None,
    withdrawn: bool = False,
    summary: str = "Prototype pollution in lodash",
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        aliases=aliases,
        summary=summary,
        details="",
        severity=severity,
        affected=affected_packages if affected_packages is not None else (affected(),),
        withdrawn=withdrawn,
    )


def kev(cve_id: str = "CVE-2020-8203", ransomware: bool = False) -> KevEntry:
    return KevEntry(
        cve_id=cve_id,
        vendor_project="Example",
        product="lodash",
        vulnerability_name="Prototype pollution",
        short_description="Attacker-controlled prototype pollution.",
        required_action="Apply updates.",
        known_ransomware_use=ransomware,
    )


async def attach_manifest(
    db,
    target,
    *,
    content: str | None = None,
    kind=None,
    path: str | None = None,
):
    """Give a target the manifest row the application would have made.

    Fixtures used to set `manifest_content` on the target itself. Manifests are
    rows now, and a target without one is a project that has never been
    uploaded to — a real state, but not the one most tests mean.

    The legacy columns are still written, because they remain the mirror of the
    primary manifest and plenty of assertions read them.
    """
    from app.core.types import ManifestKind
    from app.models import ProjectManifest
    from app.security import content_hash

    kind = kind or target.manifest_kind or ManifestKind.PACKAGE_JSON
    content = content if content is not None else (target.manifest_content or "{}")

    from sqlalchemy import select

    label = path or kind.value

    # Idempotent: a fixture that runs twice against the same target, or a
    # helper called from two places, should end up with one manifest rather
    # than a unique-constraint violation.
    manifest = await db.scalar(
        select(ProjectManifest).where(
            ProjectManifest.target_id == target.id, ProjectManifest.path == label
        )
    )
    if manifest is None:
        manifest = ProjectManifest(
            target_id=target.id,
            path=label,
            kind=kind,
            ecosystem=target.ecosystem,
            content=content,
            content_hash=content_hash(content),
        )
        db.add(manifest)
    else:
        manifest.kind = kind
        manifest.content = content
        manifest.content_hash = content_hash(content)
    await db.flush()

    target.manifest_kind = kind
    target.manifest_content = content
    target.content_hash = manifest.content_hash
    await db.refresh(target, ["manifests"])
    return manifest


async def set_manifest(db, target, content: str, *, kind=None):
    """Change what a project's primary manifest says.

    Fixtures used to assign `target.manifest_content` and re-scan. The manifest
    is a row now, so assigning the mirror changes nothing the scanner reads —
    it would silently re-scan the old file and the test would fail describing
    the wrong thing.

    Writes both, as `replace_manifest` does, so assertions that read either
    still hold.
    """
    from sqlalchemy import select

    from app.models import ProjectManifest
    from app.security import content_hash

    manifest = await db.scalar(
        select(ProjectManifest)
        .where(ProjectManifest.target_id == target.id)
        .order_by(ProjectManifest.id)
    )
    if manifest is None:
        return await attach_manifest(db, target, content=content, kind=kind)

    if kind is not None:
        # A project that started on package.json and now sends a lockfile is
        # the same project with better data — the same case `replace_manifest`
        # handles by re-detecting from the filename.
        manifest.kind = kind
        target.manifest_kind = kind
    manifest.content = content
    manifest.content_hash = content_hash(content)
    target.manifest_content = content
    target.content_hash = manifest.content_hash
    await db.flush()
    return manifest
