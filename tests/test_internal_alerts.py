"""The finding endpoints the React alert pages use.

Two properties carry the weight.

The first is ownership: a finding id is the only thing a caller supplies, and
the row itself does not carry an account — the project does. A lookup that
forgot to join through the project would hand any signed-in stranger any
finding in the service.

The second is that `resolved` cannot be claimed by hand. It is a fact a scan
establishes by not finding the vulnerability any more, and letting somebody
assert it would let a still-present finding be marked fixed. That is the one
claim this product exists not to make falsely.
"""

from __future__ import annotations

from sqlalchemy import select

from app.core.types import AlertStatus, Ecosystem, ManifestKind, Reachability, Severity, Verdict
from app.models import CVEMatch, TrackedTarget, VulnerabilityRecord
from tests.conftest import set_csrf, sign_in

DETAIL = "/api/internal/alerts/{id}"
STATUS = "/api/internal/alerts/{id}/status"


async def make_finding(db, owner, *, summary="Prototype pollution") -> CVEMatch:
    db.add(VulnerabilityRecord(id="GHSA-test-1", summary=summary))
    target = TrackedTarget(
        user_id=owner.id,
        name="theirs",
        manifest_kind=ManifestKind.PACKAGE_JSON,
        ecosystem="npm",
        manifest_content="{}",
        content_hash="z" * 64,
    )
    db.add(target)
    await db.flush()

    match = CVEMatch(
        target_id=target.id,
        vulnerability_id="GHSA-test-1",
        ecosystem=Ecosystem.NPM,
        package_name="lodash",
        package_version="4.17.15",
        reachability=Reachability.RUNTIME_DIRECT,
        verdict=Verdict.ACTIONABLE,
        severity=Severity.HIGH,
        actionable_reason="high_severity_direct",
    )
    db.add(match)
    await db.flush()
    return match


async def post(client, path: str, body: dict):
    csrf = set_csrf(client)
    return await client.post(path, json=body, headers={"X-CSRF-Token": csrf})


class TestReadingAFinding:
    async def test_the_explanation_comes_from_the_shared_functions(self, auth_client, db, user):
        """Not composed for the browser.

        These are the sentences app.core.explain writes for the alert emails
        too, so a finding is described in identical words wherever somebody
        meets it. A second explanation written here is how a page and an email
        end up disagreeing about why something was reported.
        """
        match = await make_finding(db, user)
        await db.commit()

        response = await auth_client.get(DETAIL.format(id=match.id))

        assert response.status_code == 200
        explanation = response.json()["explanation"]
        assert set(explanation) == {"risk", "why", "fix", "command", "confidence"}
        assert explanation["risk"]
        assert explanation["why"]

    async def test_it_is_never_shared_cache(self, auth_client, db, user):
        match = await make_finding(db, user)
        await db.commit()

        response = await auth_client.get(DETAIL.format(id=match.id))

        assert "no-store" in response.headers["cache-control"]
        assert response.headers["vary"] == "Cookie"

    async def test_it_names_the_project_it_belongs_to(self, auth_client, db, user):
        match = await make_finding(db, user)
        await db.commit()

        body = (await auth_client.get(DETAIL.format(id=match.id))).json()

        assert body["data"]["project"]["name"] == "theirs"


class TestOwnership:
    async def test_another_accounts_finding_is_a_404(self, client, db, user, pro_user):
        """Ownership lives on the project, not the finding row. A lookup that
        did not join through it would hand over any finding in the service."""
        match = await make_finding(db, pro_user)
        await db.commit()
        await sign_in(client, user.email)

        assert (await client.get(DETAIL.format(id=match.id))).status_code == 404

    async def test_another_accounts_finding_cannot_be_dismissed(self, client, db, user, pro_user):
        match = await make_finding(db, pro_user)
        await db.commit()
        await sign_in(client, user.email)

        response = await post(client, STATUS.format(id=match.id), {"status": "dismissed"})

        assert response.status_code == 404
        await db.refresh(match)
        assert match.status is AlertStatus.OPEN

    async def test_a_finding_that_does_not_exist_answers_the_same(self, auth_client):
        assert (await auth_client.get(DETAIL.format(id=999999))).status_code == 404

    async def test_signed_out_callers_get_nothing(self, client, db, user):
        match = await make_finding(db, user)
        await db.commit()

        assert (await client.get(DETAIL.format(id=match.id))).status_code == 401


class TestChangingStatus:
    async def test_dismissing_records_the_note_and_the_time(self, auth_client, db, user):
        match = await make_finding(db, user)
        await db.commit()

        response = await post(
            auth_client, STATUS.format(id=match.id), {"status": "dismissed", "note": "dev only"}
        )

        assert response.status_code == 200
        await db.refresh(match)
        assert match.status is AlertStatus.DISMISSED
        assert match.dismiss_note == "dev only"
        assert match.dismissed_at is not None

    async def test_reopening_clears_the_dismissal_entirely(self, auth_client, db, user):
        match = await make_finding(db, user)
        match.status = AlertStatus.DISMISSED
        match.dismiss_note = "was dev only"
        await db.commit()

        await post(auth_client, STATUS.format(id=match.id), {"status": "open"})

        await db.refresh(match)
        assert match.status is AlertStatus.OPEN
        assert match.dismissed_at is None
        # The old note must go too, or a later dismissal inherits a reason
        # nobody gave for it.
        assert match.dismiss_note is None

    async def test_resolved_cannot_be_claimed_by_hand(self, auth_client, db, user):
        """Resolution is something a scan establishes by no longer finding the
        vulnerability. Asserting it here would be contradicted by the next
        scan, and in the meantime the finding would read as fixed."""
        match = await make_finding(db, user)
        await db.commit()

        response = await post(auth_client, STATUS.format(id=match.id), {"status": "resolved"})

        assert response.status_code == 400
        await db.refresh(match)
        assert match.status is AlertStatus.OPEN

    async def test_a_nonsense_status_is_refused(self, auth_client, db, user):
        match = await make_finding(db, user)
        await db.commit()

        response = await post(auth_client, STATUS.format(id=match.id), {"status": "banana"})

        assert response.status_code == 400

    async def test_a_change_without_csrf_is_refused(self, auth_client, db, user):
        """Without this, any page on the internet could dismiss somebody's
        findings in their browser — quietly, and one at a time."""
        match = await make_finding(db, user)
        await db.commit()

        response = await auth_client.post(STATUS.format(id=match.id), json={"status": "dismissed"})

        assert response.status_code == 403
        await db.refresh(match)
        assert match.status is AlertStatus.OPEN

    async def test_dismissing_does_not_delete_anything(self, auth_client, db, user):
        """Dismissed is a view, not a removal. The row stays so a later scan
        can still resolve it and so the count on the filtered tab stays true."""
        match = await make_finding(db, user)
        await db.commit()

        await post(auth_client, STATUS.format(id=match.id), {"status": "dismissed"})

        assert await db.scalar(select(CVEMatch).where(CVEMatch.id == match.id)) is not None
