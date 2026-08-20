"""API key authentication and the CI scan endpoint.

Two properties carry the weight here. A credential must fail closed in every
direction — missing, wrong, revoked, or belonging to a suspended account — and
it must fail the *same way* each time, because a distinguishable "revoked"
response confirms to whoever is holding a leaked string that it was once real.

The second is that a scan which could not run must never be reported as a scan
that found nothing. A pipeline reads a green build as "checked and clean".
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.core.types import ManifestKind
from app.models import ApiKey, TrackedTarget
from app.security import content_hash, hash_api_key
from app.services.api_key_service import (
    MAX_ACTIVE_KEYS_PER_TARGET,
    ApiKeyError,
    issue_api_key,
    revoke_api_key,
)
from tests.test_scan_pipeline import LODASH_ADVISORY, MANIFEST, seed_mirror

VULNERABLE = json.dumps({"dependencies": {"lodash": "4.17.15"}})
PATCHED = json.dumps({"dependencies": {"lodash": "4.17.21"}})

#: A critical-severity variant of the shared lodash fixture. The shared one
#: scores HIGH, so having both is what lets these tests tell the two `--fail-on`
#: thresholds apart.
CRITICAL_LODASH = dict(
    LODASH_ADVISORY,
    id="GHSA-lodash-critical",
    aliases=["CVE-2099-0001"],
    severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
)


#: A medium-severity variant. `findings` stops here: the CLI's --fail-on offers
#: critical and high, so a medium row could never be the reason a build failed
#: and printing it into a build log only makes the log longer.
MEDIUM_LODASH = dict(
    LODASH_ADVISORY,
    id="GHSA-lodash-medium",
    aliases=["CVE-2099-0002"],
    severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"}],
)


async def make_target(db, owner, name="demo-app") -> TrackedTarget:
    target = TrackedTarget(
        user_id=owner.id,
        name=name,
        manifest_kind=ManifestKind.PACKAGE_JSON,
        ecosystem="npm",
        manifest_content=MANIFEST,
        content_hash=content_hash(MANIFEST),
        dependency_count=3,
    )
    db.add(target)
    await db.flush()
    return target


async def make_key(db, owner, target=None) -> tuple[str, ApiKey]:
    target = target or await make_target(db, owner)
    issued = await issue_api_key(db, owner, target, name="ci")
    await db.flush()
    return issued.token, issued.record


def upload(content: str = VULNERABLE, filename: str = "package.json") -> dict:
    return {"manifest": (filename, content, "application/json")}


class TestKeyIssuance:
    async def test_only_the_hash_is_stored(self, db, user):
        token, record = await make_key(db, user)

        assert record.token_hash == hash_api_key(token)
        # The plaintext must not be recoverable from anything persisted.
        assert token not in record.token_hash
        assert token not in record.prefix
        assert len(record.prefix) < len(token)

    async def test_the_prefix_identifies_without_authenticating(self, db, user):
        token, record = await make_key(db, user)

        assert token.startswith(record.prefix)
        # A prefix that could authenticate would defeat the point of hashing.
        from app.services.api_key_service import authenticate_api_key

        assert await authenticate_api_key(db, record.prefix) is None

    async def test_keys_are_prefixed_so_secret_scanners_can_find_them(self, db, user):
        token, _ = await make_key(db, user)
        assert token.startswith("wo_")

    async def test_two_keys_are_never_the_same(self, db, user):
        target = await make_target(db, user)
        first, _ = await make_key(db, user, target)
        second, _ = await make_key(db, user, target)
        assert first != second

    async def test_a_key_cannot_be_issued_against_someone_elses_project(self, db, user, pro_user):
        target = await make_target(db, pro_user)

        with pytest.raises(ApiKeyError):
            await issue_api_key(db, user, target)

    async def test_active_keys_per_project_are_capped(self, db, user):
        target = await make_target(db, user)
        for _ in range(MAX_ACTIVE_KEYS_PER_TARGET):
            await make_key(db, user, target)

        with pytest.raises(ApiKeyError):
            await issue_api_key(db, user, target)

    async def test_revoking_frees_a_slot(self, db, user):
        target = await make_target(db, user)
        keys = [await make_key(db, user, target) for _ in range(MAX_ACTIVE_KEYS_PER_TARGET)]

        await revoke_api_key(db, user, keys[0][1].id)
        await db.flush()

        issued = await issue_api_key(db, user, target)
        assert issued.token


class TestAuthentication:
    async def test_a_valid_key_is_accepted(self, client, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        token, _ = await make_key(db, user)

        response = await client.post(
            "/api/v1/scan",
            files=upload(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    async def test_a_missing_header_is_rejected(self, client, db, user):
        await make_key(db, user)
        response = await client.post("/api/v1/scan", files=upload())

        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    async def test_an_unknown_key_is_rejected(self, client, db, user):
        await make_key(db, user)
        response = await client.post(
            "/api/v1/scan",
            files=upload(),
            headers={"Authorization": "Bearer wo_not-a-real-key"},
        )
        assert response.status_code == 401

    async def test_a_revoked_key_is_rejected(self, client, db, user):
        token, record = await make_key(db, user)
        await revoke_api_key(db, user, record.id)
        await db.commit()

        response = await client.post(
            "/api/v1/scan",
            files=upload(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401

    async def test_revoked_and_unknown_are_indistinguishable(self, client, db, user):
        """Otherwise the endpoint confirms which leaked strings were once real."""
        token, record = await make_key(db, user)
        await revoke_api_key(db, user, record.id)
        await db.commit()

        revoked = await client.post(
            "/api/v1/scan", files=upload(), headers={"Authorization": f"Bearer {token}"}
        )
        unknown = await client.post(
            "/api/v1/scan", files=upload(), headers={"Authorization": "Bearer wo_nonsense"}
        )

        assert revoked.status_code == unknown.status_code
        assert revoked.json() == unknown.json()

    async def test_a_suspended_owners_key_stops_working(self, client, db, user):
        token, _ = await make_key(db, user)
        user.is_suspended = True
        await db.commit()

        response = await client.post(
            "/api/v1/scan", files=upload(), headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401

    async def test_a_malformed_authorization_header_is_rejected(self, client, db, user):
        token, _ = await make_key(db, user)
        for header in (token, f"Basic {token}", "Bearer", "Bearer   "):
            response = await client.post(
                "/api/v1/scan", files=upload(), headers={"Authorization": header}
            )
            assert response.status_code == 401, header

    async def test_the_scheme_is_case_insensitive(self, client, db, user):
        # httpx, curl and the GitHub toolkit do not agree on the casing.
        await seed_mirror(db, LODASH_ADVISORY)
        token, _ = await make_key(db, user)

        response = await client.post(
            "/api/v1/scan", files=upload(), headers={"Authorization": f"bearer {token}"}
        )
        assert response.status_code == 200

    async def test_a_session_cookie_does_not_authenticate_the_api(self, auth_client, db, user):
        """The API must not accept ambient credentials.

        If it did, any page on the internet could make an authenticated call
        from a logged-in developer's browser — which is exactly the attack CSRF
        tokens exist to stop, and why these routes need none.
        """
        await make_key(db, user)
        response = await auth_client.post("/api/v1/scan", files=upload())
        assert response.status_code == 401

    async def test_last_used_is_recorded(self, client, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        token, record = await make_key(db, user)
        assert record.last_used_at is None

        await client.post(
            "/api/v1/scan", files=upload(), headers={"Authorization": f"Bearer {token}"}
        )
        await db.refresh(record)
        assert record.last_used_at is not None


class TestScanEndpoint:
    async def _scan(self, client, token, content=VULNERABLE, filename="package.json"):
        return await client.post(
            "/api/v1/scan",
            files=upload(content, filename),
            headers={"Authorization": f"Bearer {token}"},
        )

    async def test_returns_counts_and_a_dashboard_link(self, client, db, user):
        await seed_mirror(db, CRITICAL_LODASH)
        token, record = await make_key(db, user)

        body = (await self._scan(client, token)).json()

        assert body["actionable"] == 1
        assert body["counts"]["critical"] == 1
        assert body["dashboard_url"].endswith(f"/targets/{record.target_id}")
        assert body["findings"][0]["package"] == "lodash"
        assert body["findings"][0]["fixed_in"] == "4.17.21"
        assert body["findings"][0]["severity"] == "critical"

    async def test_high_severity_findings_are_listed_inline(self, client, db, user):
        """`findings` covers both thresholds the CLI offers.

        `--fail-on high` can gate a build on a high-severity finding, and a
        gate that fails with an empty table tells the person reading the log
        nothing about what to fix. The server sends what could matter at either
        threshold; the client decides which of it does.
        """
        await seed_mirror(db, LODASH_ADVISORY)  # scores HIGH
        token, _ = await make_key(db, user)

        body = (await self._scan(client, token)).json()
        assert body["actionable"] == 1
        assert [f["severity"] for f in body["findings"]] == ["high"]
        # With enough to act on: the package, the CVE and where the fix is.
        assert body["findings"][0]["package"] == "lodash"
        assert body["findings"][0]["fixed_in"]

    async def test_medium_findings_are_not_listed_inline(self, client, db, user):
        """The floor. No --fail-on value gates on medium, so no build fails for
        one, so it does not belong in the build log."""
        await seed_mirror(db, MEDIUM_LODASH)
        token, _ = await make_key(db, user)

        body = (await self._scan(client, token)).json()
        assert body["findings"] == []

    async def test_every_severity_is_present_even_at_zero(self, client, db, user):
        # A client that cannot tell "none" from "not reported" writes bugs.
        await seed_mirror(db, LODASH_ADVISORY)
        token, _ = await make_key(db, user)

        counts = (await self._scan(client, token)).json()["counts"]
        for key in ("critical", "high", "medium", "low", "unknown", "exploited"):
            assert key in counts

    async def test_the_upload_goes_to_the_projects_the_key_belongs_to(self, client, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        mine = await make_target(db, user, name="mine")
        other = await make_target(db, user, name="other")
        token, _ = await make_key(db, user, mine)

        await self._scan(client, token)
        await db.refresh(other)

        # The request never names a project, so it cannot name the wrong one.
        assert other.manifest_content == MANIFEST
        assert other.last_scanned_at is None

    async def test_a_clean_lockfile_reports_zero(self, client, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        token, _ = await make_key(db, user)

        body = (await self._scan(client, token, PATCHED)).json()
        assert body["actionable"] == 0
        assert body["findings"] == []

    async def test_an_unsupported_file_is_rejected(self, client, db, user):
        await seed_mirror(db, LODASH_ADVISORY)
        token, _ = await make_key(db, user)

        response = await self._scan(client, token, "just some prose", "mystery.bin")
        assert response.status_code == 422
        assert response.json()["error"] == "unsupported_manifest"

    async def test_an_oversized_file_is_rejected(self, client, db, user):
        token, _ = await make_key(db, user)
        from app.config import get_settings

        oversized = "x" * (get_settings().api_scan_max_bytes + 1)
        response = await self._scan(client, token, oversized)

        assert response.status_code == 413
        assert response.json()["error"] == "file_too_large"

    async def test_an_empty_file_is_rejected(self, client, db, user):
        token, _ = await make_key(db, user)
        response = await self._scan(client, token, "   \n")

        assert response.status_code == 400
        assert response.json()["error"] == "empty_file"

    async def test_a_missing_file_is_rejected(self, client, db, user):
        token, _ = await make_key(db, user)
        response = await client.post("/api/v1/scan", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code in (400, 422)

    async def test_a_different_ecosystem_is_refused_rather_than_reinterpreted(
        self, client, db, user
    ):
        """Switching a project's ecosystem would silently rewrite its history.

        Every stored finding is keyed to a package in an ecosystem. Accepting a
        `go.mod` into an npm project does not make the old findings wrong — it
        makes them unreachable, which looks like they were fixed.
        """
        await seed_mirror(db, LODASH_ADVISORY)
        token, _ = await make_key(db, user)

        response = await self._scan(client, token, "module example.com/x\n\ngo 1.22\n", "go.mod")
        assert response.status_code == 422
        assert response.json()["error"] == "unsupported_manifest"

    async def test_a_lockfile_replaces_the_manifest_it_was_registered_with(self, client, db, user):
        # CI legitimately has better data than the file the project was added
        # with. Forcing it through the old parser would reject it as malformed.
        await seed_mirror(db, LODASH_ADVISORY)
        token, record = await make_key(db, user)

        lockfile = json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/lodash": {"version": "4.17.15"}},
            }
        )
        response = await self._scan(client, token, lockfile, "package-lock.json")

        assert response.status_code == 200
        target = await db.get(TrackedTarget, record.target_id)
        await db.refresh(target)
        assert target.manifest_kind is ManifestKind.PACKAGE_LOCK_JSON

    async def test_an_unusable_mirror_fails_loudly_rather_than_reporting_clean(
        self, client, db, user
    ):
        """The single most dangerous response this endpoint can give is 200
        with zero findings when nothing was actually checked."""
        token, _ = await make_key(db, user)  # no mirror seeded

        response = await self._scan(client, token)

        assert response.status_code == 503
        assert response.json()["error"] == "scan_failed"

    async def test_the_rate_limit_returns_429(self, client, db, user, monkeypatch):
        from app.config import get_settings

        settings = get_settings()
        monkeypatch.setattr(settings, "api_scan_rate_limit_per_hour", 2)

        await seed_mirror(db, LODASH_ADVISORY)
        token, _ = await make_key(db, user)

        for index in range(2):
            body = json.dumps({"dependencies": {"lodash": f"4.17.1{index}"}})
            assert (await self._scan(client, token, body)).status_code == 200

        limited = await self._scan(client, token, json.dumps({"dependencies": {"lodash": "4.0.0"}}))
        assert limited.status_code == 429
        assert limited.json()["error"] == "rate_limited"

    async def test_findings_returned_here_are_not_also_emailed(self, client, db, user):
        # The developer is watching the build log right now.
        from app.models import CVEMatch

        await seed_mirror(db, LODASH_ADVISORY)
        token, _ = await make_key(db, user)
        await self._scan(client, token)

        match = await db.scalar(select(CVEMatch))
        assert match.notified_at is not None

    async def test_errors_are_json_with_a_stable_code(self, client, db, user):
        token, _ = await make_key(db, user)
        response = await self._scan(client, token, "   ")

        body = response.json()
        assert set(body) >= {"error", "message"}
        assert isinstance(body["error"], str)

    async def test_an_api_error_is_never_an_html_page(self, client, db, user):
        # A CI runner that sends Accept: text/html must still get JSON.
        token, _ = await make_key(db, user)
        response = await client.post(
            "/api/v1/scan",
            files=upload("   "),
            headers={"Authorization": f"Bearer {token}", "Accept": "text/html"},
        )
        assert response.headers["content-type"].startswith("application/json")
