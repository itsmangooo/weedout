"""A project watches more than one file.

The thing being proven is that a repository with a Go backend and an npm
frontend is *one* project: one entry in the list, one API key, one findings
count — and findings that say which file they came from.

The interesting cases are the ones where the old single-manifest shape gave a
wrong answer rather than no answer:

* the same package name existing in two ecosystems, which used to collapse into
  one dependency row whose ecosystem was whichever parse ran last;
* a finding in one file being marked resolved because a scan of the *other*
  file did not see it;
* one unreadable file blinding the project to the files that are fine.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.core.types import Ecosystem, ManifestKind
from app.models import CVEMatch, DependencyRecord, ProjectManifest
from app.services.scan_service import scan_target
from app.services.target_service import (
    UnsupportedManifest,
    add_manifest,
    create_target,
    load_manifests,
    remove_manifest,
)
from tests.test_scan_pipeline import LODASH_ADVISORY, seed_mirror

NPM = json.dumps({"name": "frontend", "dependencies": {"lodash": "4.17.15"}})
GO = """module example.com/backend

go 1.22

require github.com/gin-gonic/gin v1.9.0
"""
PY = "requests==2.20.0\n"


async def project_with_both(db, user):
    target = await create_target(db, user, filename="package.json", content=NPM)
    await add_manifest(db, target, filename="go.mod", content=GO, path="backend/go.mod")
    return target


class TestOneProjectManyFiles:
    async def test_a_second_ecosystem_can_be_added(self, db, user):
        target = await project_with_both(db, user)

        manifests = await load_manifests(db, target)
        assert [m.ecosystem for m in manifests] == [Ecosystem.NPM, Ecosystem.GO]
        assert [m.path for m in manifests] == ["package.json", "backend/go.mod"]

    async def test_replacing_a_file_with_another_ecosystem_is_still_refused(self, db, user):
        """Adding is the multi-language case. Replacing is a mistake.

        Reinterpreting a file's ecosystem would silently re-read every finding
        already recorded against it under different rules.
        """
        target = await create_target(db, user, filename="package.json", content=NPM)

        from app.services.target_service import replace_manifest

        with pytest.raises(UnsupportedManifest) as caught:
            await replace_manifest(db, target, content=GO, filename="go.mod")

        assert "another manifest" in str(caught.value)

    async def test_the_same_path_cannot_be_added_twice(self, db, user):
        target = await create_target(db, user, filename="package.json", content=NPM)

        with pytest.raises(UnsupportedManifest):
            await add_manifest(db, target, filename="package.json", content=NPM)

    async def test_two_files_of_one_kind_are_fine_in_different_places(self, db, user):
        """The monorepo case: four package-lock.json files, four sub-projects."""
        target = await create_target(db, user, filename="package.json", content=NPM)
        await add_manifest(
            db,
            target,
            filename="package.json",
            content=json.dumps({"dependencies": {"express": "4.18.1"}}),
            path="admin/package.json",
        )

        assert len(await load_manifests(db, target)) == 2


class TestTheSameNameInTwoEcosystems:
    async def test_both_survive_as_separate_dependencies(self, db, user):
        """`requests` is a real package on PyPI and on npm.

        Keyed on the project alone these collapsed into one row whose
        ecosystem was whichever parse ran last — which then looked the package
        up against the wrong ecosystem's advisories.
        """
        await seed_mirror(db)
        target = await create_target(
            db, user, filename="requirements.txt", content="requests==2.20.0\n"
        )
        await add_manifest(
            db,
            target,
            filename="package.json",
            content=json.dumps({"dependencies": {"requests": "2.20.0"}}),
            path="web/package.json",
        )

        await scan_target(db, target)

        rows = (
            await db.scalars(select(DependencyRecord).where(DependencyRecord.name == "requests"))
        ).all()
        assert {row.ecosystem for row in rows} == {Ecosystem.PYPI, Ecosystem.NPM}


class TestFindingsKnowWhichFile:
    async def test_a_finding_records_its_manifest(self, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        target = await project_with_both(db, user)

        await scan_target(db, target)

        match = await db.scalar(select(CVEMatch).where(CVEMatch.package_name == "lodash"))
        assert match is not None

        manifest = await db.get(ProjectManifest, match.manifest_id)
        assert manifest.path == "package.json"

    async def test_scanning_does_not_resolve_the_other_file_s_findings(self, db, user):
        """The bug this keys against: reconciling by project rather than by
        file marks everything the current parse did not see as fixed."""
        await seed_mirror(db, LODASH_ADVISORY)
        target = await create_target(db, user, filename="package.json", content=NPM)
        await add_manifest(
            db,
            target,
            filename="package.json",
            content=json.dumps({"dependencies": {"lodash": "4.17.15"}}),
            path="admin/package.json",
        )

        await scan_target(db, target)
        matches = (await db.scalars(select(CVEMatch))).all()
        assert len(matches) == 2, "one finding per file, not one for the project"
        assert all(m.resolved_at is None for m in matches)

        # A second scan must leave both alone.
        await scan_target(db, target)
        matches = (await db.scalars(select(CVEMatch))).all()
        assert all(m.resolved_at is None for m in matches)


class TestOneBrokenFile:
    async def test_the_others_are_still_scanned(self, db, user):
        """A malformed frontend lockfile must not blind you to the backend."""
        await seed_mirror(db, LODASH_ADVISORY)
        target = await create_target(db, user, filename="package.json", content=NPM)

        broken = ProjectManifest(
            target_id=target.id,
            path="admin/package.json",
            kind=ManifestKind.PACKAGE_JSON,
            ecosystem=Ecosystem.NPM,
            content="{ this is not json",
            content_hash="b" * 64,
        )
        db.add(broken)
        await db.flush()

        outcome = await scan_target(db, target)

        assert outcome.failed is False
        assert outcome.actionable_count >= 1, "the readable file still reported"
        assert any("admin/package.json" in error for error in outcome.errors), (
            "and the broken one is named rather than swallowed"
        )

    async def test_the_error_is_recorded_on_the_file_itself(self, db, user):
        await seed_mirror(db)
        target = await create_target(db, user, filename="package.json", content=NPM)
        broken = ProjectManifest(
            target_id=target.id,
            path="admin/package.json",
            kind=ManifestKind.PACKAGE_JSON,
            ecosystem=Ecosystem.NPM,
            content="{ nope",
            content_hash="c" * 64,
        )
        db.add(broken)
        await db.flush()

        await scan_target(db, target)
        # Flushed, not refreshed: `scan_target` leaves the change pending for
        # the caller to commit, and refreshing first would read the row back
        # from before it.
        await db.flush()

        assert broken.last_parse_error is not None
        assert "not valid JSON" in broken.last_parse_error

    async def test_every_file_broken_is_a_failed_scan(self, db, user):
        """Partial results are better than none. No results is still a failure."""
        await seed_mirror(db)
        target = await create_target(db, user, filename="package.json", content=NPM)

        manifests = await load_manifests(db, target)
        manifests[0].content = "{ not json at all"
        await db.flush()

        outcome = await scan_target(db, target)

        assert outcome.failed is True


class TestRemoving:
    async def test_removing_a_file_takes_its_findings_with_it(self, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        target = await project_with_both(db, user)
        await scan_target(db, target)

        before = len((await db.scalars(select(CVEMatch))).all())
        assert before >= 1

        manifests = await load_manifests(db, target)
        npm_manifest = next(m for m in manifests if m.ecosystem is Ecosystem.NPM)
        await remove_manifest(db, target, npm_manifest)

        remaining = (await db.scalars(select(CVEMatch))).all()
        assert all(m.manifest_id != npm_manifest.id for m in remaining)

    async def test_removing_the_last_one_returns_the_project_to_empty(self, db, user):
        target = await create_target(db, user, filename="package.json", content=NPM)
        manifests = await load_manifests(db, target)

        await remove_manifest(db, target, manifests[0])

        assert await load_manifests(db, target) == []
        # The mirror follows, so the project reads as "never uploaded to".
        assert target.has_manifest is False
