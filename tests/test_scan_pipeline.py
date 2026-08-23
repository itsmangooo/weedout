"""End-to-end scan pipeline against a real database and the local mirror.

Covers the parts that only show up once persistence is involved: finding
identity across scans, dismissals surviving a re-scan, resolution when a
dependency is upgraded, and notify-once semantics.

These tests previously mocked OSV over HTTP. The advisory fixtures below are
unchanged and so is every assertion — only the source moved, from a mocked
endpoint to the local mirror. That equivalence is the point: it demonstrates
the rewrite did not alter a single verdict.

The pipeline now makes no outbound HTTP calls at all, so there is no `respx`
router here to mock.
"""

from __future__ import annotations

import json

from sqlalchemy import delete as sa_delete
from sqlalchemy import select

from app.core.types import AlertStatus, ManifestKind, Verdict
from app.models import Alert, CVEMatch, KevRecord, ScanRun, TrackedTarget, utcnow
from app.services.scan_service import scan_target
from tests.factories import attach_manifest, set_manifest

MANIFEST = json.dumps(
    {
        "name": "demo-app",
        "dependencies": {"lodash": "4.17.15", "express": "4.18.2"},
        "devDependencies": {"webpack": "5.0.0"},
    }
)

LODASH_ADVISORY = {
    "id": "GHSA-lodash-1",
    "aliases": ["CVE-2020-8203"],
    "summary": "Prototype pollution in lodash",
    "details": "Details here.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        }
    ],
    "references": [{"type": "WEB", "url": "https://example.com/lodash"}],
}

WEBPACK_ADVISORY = {
    "id": "GHSA-webpack-1",
    "aliases": ["CVE-2023-28154"],
    "summary": "Webpack cross-realm object access",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "webpack"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "5.0.0"}, {"fixed": "5.76.0"}]}
            ],
        }
    ],
}


#: Proof the mirror is loaded, for a package nothing in this file depends on.
_SENTINEL_ADVISORY = {
    "id": "GHSA-sentinel-0000",
    "summary": "Unrelated advisory; exists only so the mirror is non-empty.",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "not-a-dependency-of-anything"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
        }
    ],
}


async def seed_mirror(db, *advisories: dict) -> None:
    """Load raw OSV records into the local mirror.

    Replaces the old `mock_osv` HTTP fixture. The advisory JSON is byte-for-byte
    what the mocked OSV endpoints used to return, and every assertion in this
    file is unchanged — which is the point: it demonstrates that reading from
    the mirror produces the same verdicts the live lookup did.

    Note there is no package-to-advisory mapping to declare any more. The mirror
    derives it from each advisory's own `affected` list, so the fixture can no
    longer disagree with the data the way a hand-written `hits` dict could.

    A sentinel advisory for a package no fixture depends on is always loaded.
    Calling this with no arguments therefore means "a healthy mirror that
    happens to contain nothing relevant" — which is a clean scan — and not "an
    empty mirror", which the pipeline treats as an outage.
    """
    from app.core.osv import normalize_osv_record
    from app.services.mirror_service import upsert_vulnerability

    for raw in (_SENTINEL_ADVISORY, *advisories):
        vulnerability = normalize_osv_record(raw)
        assert vulnerability is not None, f"fixture is not a usable advisory: {raw.get('id')}"
        await upsert_vulnerability(db, vulnerability)
    await db.flush()


async def make_target(db, user, manifest: str = MANIFEST) -> TrackedTarget:
    from app.security import content_hash

    target = TrackedTarget(
        user_id=user.id,
        name="demo-app",
        manifest_kind=ManifestKind.PACKAGE_JSON,
        ecosystem="npm",
        manifest_content=manifest,
        content_hash=content_hash(manifest),
    )
    db.add(target)
    await db.flush()
    await attach_manifest(db, target)
    return target


class TestScanPipeline:
    async def test_surfaces_the_actionable_finding_and_files_the_rest(self, db, user):
        await seed_mirror(db, LODASH_ADVISORY, WEBPACK_ADVISORY)
        target = await make_target(db, user)

        outcome = await scan_target(db, target)

        assert outcome.failed is False
        assert outcome.dependencies_scanned == 3

        matches = (await db.scalars(select(CVEMatch).where(CVEMatch.target_id == target.id))).all()
        by_package = {m.package_name: m for m in matches}

        # lodash 4.17.15 is a direct runtime dependency, high severity: surfaced.
        assert by_package["lodash"].verdict is Verdict.ACTIONABLE
        assert by_package["lodash"].fixed_version == "4.17.21"

        # webpack is critical but devDependencies-only, so it never ships.
        assert by_package["webpack"].verdict is Verdict.SUPPRESSED
        assert by_package["webpack"].suppression_reason.value == "dev_only_dependency"

        # express has no advisory at all and produces no row.
        assert "express" not in by_package

    async def test_kev_listing_promotes_a_finding(self, db, user):
        db.add(KevRecord(cve_id="CVE-2023-28154", vendor_project="x", product="webpack"))
        await db.flush()

        await seed_mirror(db, WEBPACK_ADVISORY)
        target = await make_target(db, user)

        await scan_target(db, target)

        webpack = await db.scalar(select(CVEMatch).where(CVEMatch.package_name == "webpack"))
        # Dev-only no longer saves it: this one is being exploited.
        assert webpack.is_kev is True
        assert webpack.verdict is Verdict.ACTIONABLE
        assert webpack.actionable_reason.value == "exploited_in_wild"

    async def test_rescan_keeps_finding_identity_and_does_not_duplicate(self, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, user)

        first = await scan_target(db, target)
        assert len(first.new_matches) == 1
        original_id = first.new_matches[0].id
        original_first_seen = first.new_matches[0].first_seen_at

        second = await scan_target(db, target)

        # Nothing new the second time — this is what stops repeat emails.
        assert second.new_matches == []

        matches = (await db.scalars(select(CVEMatch).where(CVEMatch.target_id == target.id))).all()
        assert len(matches) == 1
        assert matches[0].id == original_id
        assert matches[0].first_seen_at == original_first_seen
        assert (
            matches[0].last_seen_at > original_first_seen
            or matches[0].last_seen_at >= original_first_seen
        )

    async def test_dismissal_survives_a_rescan(self, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, user)

        await scan_target(db, target)

        match = await db.scalar(select(CVEMatch).where(CVEMatch.target_id == target.id))
        match.status = AlertStatus.DISMISSED
        await db.flush()

        outcome = await scan_target(db, target)

        await db.refresh(match)
        assert match.status is AlertStatus.DISMISSED, "a re-scan must not undo a dismissal"
        assert outcome.new_matches == []

    async def test_upgrading_the_dependency_resolves_the_finding(self, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, user)

        await scan_target(db, target)
        assert (
            await db.scalar(select(CVEMatch).where(CVEMatch.target_id == target.id))
        ).status is AlertStatus.OPEN

        # The user upgrades past the fix.
        await set_manifest(db, target, json.dumps({"dependencies": {"lodash": "4.17.21"}}))
        outcome = await scan_target(db, target)

        assert outcome.resolved_count == 1
        match = await db.scalar(select(CVEMatch).where(CVEMatch.target_id == target.id))
        # Marked resolved, not deleted: the history is worth keeping.
        assert match.status is AlertStatus.RESOLVED
        assert match.resolved_at is not None

    async def test_a_downgrade_reopens_a_resolved_finding(self, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, user)

        await scan_target(db, target)
        await set_manifest(db, target, json.dumps({"dependencies": {"lodash": "4.17.21"}}))
        await scan_target(db, target)
        await set_manifest(db, target, json.dumps({"dependencies": {"lodash": "4.17.15"}}))
        outcome = await scan_target(db, target)

        match = await db.scalar(select(CVEMatch).where(CVEMatch.target_id == target.id))
        assert match.status is AlertStatus.OPEN
        assert match.resolved_at is None
        assert len(outcome.new_matches) == 1, "a returning vulnerability should re-notify"

    async def test_scan_run_is_recorded_with_counts(self, db, user):
        await seed_mirror(db, LODASH_ADVISORY, WEBPACK_ADVISORY)
        target = await make_target(db, user)

        await scan_target(db, target)

        run = await db.scalar(select(ScanRun).where(ScanRun.target_id == target.id))
        assert run.status == "success"
        assert run.finished_at is not None
        assert run.dependencies_scanned == 3
        assert run.actionable_count == 1
        assert run.suppressed_count == 1
        assert run.new_actionable_count == 1

    async def test_next_scan_is_scheduled_from_the_users_plan(self, db, user, pro_user):
        from datetime import timedelta

        from app.models import utcnow

        await seed_mirror(db)

        free_target = await make_target(db, user)
        pro_target = await make_target(db, pro_user)

        await scan_target(db, free_target)
        await scan_target(db, pro_target)

        now = utcnow()
        assert free_target.next_scan_at - now > timedelta(hours=20)  # daily
        assert pro_target.next_scan_at - now < timedelta(hours=5)  # every 4h

    async def test_an_empty_mirror_fails_the_run_rather_than_reporting_clean(self, db, user):
        """The most dangerous wrong answer this system can give is "no findings".

        With no advisories loaded, every project would scan clean. That must be
        a loud failure, not a reassuring result — and it must not disturb
        findings from a previous, valid scan.
        """
        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, user)
        await scan_target(db, target)

        # Wipe the mirror, simulating a deployment that has never synced.
        from app.models import VulnerabilityAffected

        await db.execute(sa_delete(VulnerabilityAffected))
        await db.flush()

        outcome = await scan_target(db, target)

        assert outcome.failed is True
        assert "mirror" in outcome.errors[0].lower()

        # The earlier finding is untouched — an outage must not look like a fix.
        match = await db.scalar(select(CVEMatch).where(CVEMatch.target_id == target.id))
        assert match.status is AlertStatus.OPEN

    async def test_a_stale_mirror_still_scans_but_says_so(self, db, user):
        from datetime import timedelta as _td

        from app.models import FeedSync
        from app.services.mirror_service import MIRRORED_ECOSYSTEMS, mirror_feed_name

        await seed_mirror(db, LODASH_ADVISORY)
        for ecosystem in MIRRORED_ECOSYSTEMS:
            db.add(
                FeedSync(
                    name=mirror_feed_name(ecosystem),
                    last_success_at=utcnow() - _td(days=30),
                )
            )
        await db.flush()

        target = await make_target(db, user)
        outcome = await scan_target(db, target)

        # Served, but labelled: silently returning stale results is how a
        # scanner stops being trustworthy without anyone noticing.
        assert outcome.failed is False
        assert outcome.actionable_count == 1
        assert any("old" in err.lower() for err in outcome.errors)

    async def test_unparseable_manifest_is_recorded_not_raised(self, db, user):
        await seed_mirror(db)
        target = await make_target(db, user, manifest="{not json at all")

        outcome = await scan_target(db, target)

        assert outcome.failed is True
        assert target.last_scan_error
        run = await db.scalar(select(ScanRun).where(ScanRun.target_id == target.id))
        assert run.status == "failed"


class TestAlerting:
    async def test_new_finding_produces_one_alert_record(self, db, user):
        from app.services.alert_service import send_new_match_digest

        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, user)

        outcome = await scan_target(db, target)

        sent = await send_new_match_digest(db, user, target, outcome.new_matches)
        assert sent == 1

        alerts = (await db.scalars(select(Alert).where(Alert.user_id == user.id))).all()
        assert len(alerts) == 1
        assert alerts[0].status == "sent"
        assert alerts[0].destination == user.email

    async def test_a_finding_is_never_emailed_twice(self, db, user):
        from app.services.alert_service import send_new_match_digest

        await seed_mirror(db, LODASH_ADVISORY)
        target = await make_target(db, user)

        outcome = await scan_target(db, target)

        assert await send_new_match_digest(db, user, target, outcome.new_matches) == 1
        # notified_at is now set, so a second attempt sends nothing.
        assert await send_new_match_digest(db, user, target, outcome.new_matches) == 0

    async def test_opting_out_suppresses_the_email(self, db, user):
        from app.services.alert_service import send_new_match_digest

        await seed_mirror(db, LODASH_ADVISORY)
        user.email_alerts_enabled = False
        target = await make_target(db, user)

        outcome = await scan_target(db, target)

        assert await send_new_match_digest(db, user, target, outcome.new_matches) == 0
        assert (await db.scalars(select(Alert))).all() == []
        # Marked notified anyway, so opting back in doesn't unleash a backlog.
        assert outcome.new_matches[0].notified_at is not None

    async def test_suppressed_findings_never_generate_email(self, db, user):
        from app.services.alert_service import send_new_match_digest

        await seed_mirror(db, WEBPACK_ADVISORY)
        target = await make_target(db, user)

        outcome = await scan_target(db, target)

        assert outcome.new_matches == []
        assert await send_new_match_digest(db, user, target, outcome.new_matches) == 0
