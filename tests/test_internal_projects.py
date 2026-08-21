"""The project endpoints the React project page uses.

The property that carries the most weight here is ownership. Every one of
these takes a project id straight from the URL, so the only thing standing
between a signed-in stranger and somebody else's project is the lookup being
scoped to the caller. There are eleven endpoints; a single one that forgot
would be enough, which is why the check is asserted on all of them rather than
on a representative sample.

The second is that a project's answers do not become an oracle: an id that
belongs to somebody else must be indistinguishable from an id that does not
exist at all.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.core.types import KeyScope, ManifestKind
from app.models import ApiKey, IgnoreRule, TrackedTarget
from app.security import content_hash
from tests.conftest import set_csrf, sign_in

MANIFEST = json.dumps({"dependencies": {"lodash": "4.17.15"}})


async def make_project(db, owner, name="demo") -> TrackedTarget:
    target = TrackedTarget(
        user_id=owner.id,
        name=name,
        manifest_kind=ManifestKind.PACKAGE_JSON,
        ecosystem="npm",
        manifest_content=MANIFEST,
        content_hash=content_hash(MANIFEST),
        dependency_count=1,
    )
    db.add(target)
    await db.flush()
    return target


async def post(client, path: str, body=None, **kwargs):
    csrf = set_csrf(client)
    return await client.post(
        path, json=body if body is not None else {}, headers={"X-CSRF-Token": csrf}, **kwargs
    )


class TestReadingAProject:
    async def test_it_returns_everything_the_page_needs_at_once(self, auth_client, db, user):
        """One response rather than six. Six round trips would render the page
        in pieces, each arriving at a different moment and shifting the layout
        under whoever is reading it."""
        target = await make_project(db, user)
        await db.commit()

        response = await auth_client.get(f"/api/internal/projects/{target.id}")

        assert response.status_code == 200
        body = response.json()
        for section in (
            "data",
            "findings",
            "dependencies",
            "recent_runs",
            "supply_chain",
            "rules",
            "thresholds",
            "policy_file",
            "api_keys",
            "webhook",
        ):
            assert section in body, f"missing {section}"
        assert body["data"]["name"] == target.name

    async def test_it_is_never_shared_cache(self, auth_client, db, user):
        target = await make_project(db, user)
        await db.commit()

        response = await auth_client.get(f"/api/internal/projects/{target.id}")

        assert "no-store" in response.headers["cache-control"]
        assert response.headers["vary"] == "Cookie"

    async def test_the_webhook_url_is_never_sent_back(self, auth_client, db, user):
        """A webhook URL is a credential — anyone holding it can post into the
        channel. The host is enough to show it is configured."""
        target = await make_project(db, user)
        target.discord_webhook_url = "https://discord.com/api/webhooks/123/sup3rs3cr3t"
        await db.commit()

        response = await auth_client.get(f"/api/internal/projects/{target.id}")

        assert "sup3rs3cr3t" not in response.text
        assert response.json()["webhook"]["configured"] is True
        assert response.json()["webhook"]["host"] == "discord.com"


#: Every project endpoint, with a body that would be valid if it were reachable.
#: Kept as one table so a new endpoint is added here or not covered at all.
ENDPOINTS = [
    ("get", "", None),
    ("post", "/rename", {"name": "stolen"}),
    ("post", "/scan", {}),
    ("post", "/delete", {}),
    ("post", "/keys", {"name": "k"}),
    ("post", "/keys/1/revoke", {}),
    ("post", "/rules", {"identifier": "CVE-2020-1", "reason": "because"}),
    ("post", "/rules/1/delete", {}),
    ("post", "/thresholds", {"direct": "high"}),
]


class TestOwnership:
    @pytest.mark.parametrize("method,suffix,body", ENDPOINTS)
    async def test_somebody_elses_project_is_a_404(
        self, auth_client, db, user, pro_user, method, suffix, body
    ):
        """404 and not 403.

        A 403 confirms the id exists, which turns any of these into a way to
        count how many projects the service holds and to probe for particular
        ones. Not existing and not being yours look identical from outside.
        """
        theirs = await make_project(db, pro_user, name="not-yours")
        await db.commit()

        path = f"/api/internal/projects/{theirs.id}{suffix}"
        if method == "get":
            response = await auth_client.get(path)
        else:
            response = await post(auth_client, path, body)

        assert response.status_code == 404, f"{method.upper()} {suffix}"

    @pytest.mark.parametrize("method,suffix,body", ENDPOINTS)
    async def test_an_unknown_project_answers_the_same_way(self, auth_client, method, suffix, body):
        path = f"/api/internal/projects/999999{suffix}"
        if method == "get":
            response = await auth_client.get(path)
        else:
            response = await post(auth_client, path, body)

        assert response.status_code == 404

    async def test_someone_elses_project_is_not_deleted(self, auth_client, db, user, pro_user):
        """The consequence, spelled out: the 404 has to happen before the
        service call, not after."""
        theirs = await make_project(db, pro_user, name="not-yours")
        await db.commit()

        await post(auth_client, f"/api/internal/projects/{theirs.id}/delete")

        assert await db.get(TrackedTarget, theirs.id) is not None

    async def test_signed_out_callers_get_nothing(self, client, db, user):
        target = await make_project(db, user)
        await db.commit()

        assert (await client.get(f"/api/internal/projects/{target.id}")).status_code == 401


class TestCreating:
    async def test_a_project_can_be_created_without_a_manifest(self, auth_client, db):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/api/internal/projects",
            data={"name": "ci-only", "ecosystem": "npm"},
            headers={"X-CSRF-Token": csrf},
        )

        assert response.status_code == 201
        assert response.json()["data"]["scanned"] is False
        assert await db.scalar(select(TrackedTarget).where(TrackedTarget.name == "ci-only"))

    async def test_a_pasted_manifest_is_scanned_immediately(self, auth_client, db):
        """An empty project right after signup is how a trial ends early."""
        from tests.test_scan_pipeline import seed_mirror

        await seed_mirror(db)
        await db.commit()

        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/api/internal/projects",
            data={"name": "pasted", "filename": "package.json", "content": MANIFEST},
            headers={"X-CSRF-Token": csrf},
        )

        assert response.status_code == 201
        assert response.json()["data"]["scanned"] is True

    async def test_creating_requires_csrf(self, auth_client, db):
        response = await auth_client.post(
            "/api/internal/projects", data={"name": "drive-by", "ecosystem": "npm"}
        )

        assert response.status_code == 403
        assert not await db.scalar(select(TrackedTarget).where(TrackedTarget.name == "drive-by"))

    async def test_a_nameless_project_is_refused(self, auth_client):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/api/internal/projects",
            data={"name": "", "ecosystem": "npm"},
            headers={"X-CSRF-Token": csrf},
        )

        assert response.status_code == 400


class TestKeys:
    async def test_the_plaintext_is_returned_once_and_stored_nowhere(self, auth_client, db, user):
        target = await make_project(db, user)
        await db.commit()

        response = await post(
            auth_client, f"/api/internal/projects/{target.id}/keys", {"name": "ci"}
        )

        assert response.status_code == 200
        token = response.json()["data"]["token"]
        assert token.startswith("wo_")

        stored = await db.scalar(select(ApiKey).where(ApiKey.target_id == target.id))
        assert token not in stored.token_hash
        assert token not in stored.prefix

    async def test_the_token_is_never_put_in_a_url(self, auth_client, db, user):
        """The rendered page was careful about this too. A live credential in a
        URL ends up in browser history, the Referer header, and every proxy log
        between here and the user."""
        target = await make_project(db, user)
        await db.commit()

        response = await post(
            auth_client, f"/api/internal/projects/{target.id}/keys", {"name": "ci"}
        )

        assert "location" not in {k.lower() for k in response.headers}

    async def test_a_key_defaults_to_the_narrowest_scope(self, auth_client, db, user):
        target = await make_project(db, user)
        await db.commit()

        await post(auth_client, f"/api/internal/projects/{target.id}/keys", {"name": "ci"})

        stored = await db.scalar(select(ApiKey).where(ApiKey.target_id == target.id))
        assert stored.scope is KeyScope.SCAN

    async def test_a_tampered_scope_falls_back_rather_than_widening(self, auth_client, db, user):
        target = await make_project(db, user)
        await db.commit()

        await post(
            auth_client,
            f"/api/internal/projects/{target.id}/keys",
            {"name": "ci", "scope": "superuser"},
        )

        stored = await db.scalar(select(ApiKey).where(ApiKey.target_id == target.id))
        assert stored.scope is KeyScope.SCAN

    async def test_a_key_can_be_revoked(self, auth_client, db, user):
        target = await make_project(db, user)
        await db.commit()

        created = await post(
            auth_client, f"/api/internal/projects/{target.id}/keys", {"name": "ci"}
        )
        key_id = created.json()["data"]["id"]

        response = await post(
            auth_client, f"/api/internal/projects/{target.id}/keys/{key_id}/revoke"
        )

        assert response.status_code == 200
        stored = await db.get(ApiKey, key_id)
        await db.refresh(stored)
        assert stored.revoked_at is not None


class TestRulesAndThresholds:
    async def test_a_free_account_cannot_add_a_rule(self, auth_client, db, user):
        target = await make_project(db, user)
        await db.commit()

        response = await post(
            auth_client,
            f"/api/internal/projects/{target.id}/rules",
            {"identifier": "CVE-2020-1", "reason": "not reachable"},
        )

        assert response.status_code == 402

    async def test_a_pro_account_can(self, client, db, pro_user):
        target = await make_project(db, pro_user)
        await db.commit()
        await sign_in(client, pro_user.email)

        response = await post(
            client,
            f"/api/internal/projects/{target.id}/rules",
            {"identifier": "CVE-2020-1", "reason": "not reachable"},
        )

        assert response.status_code == 200
        assert await db.scalar(select(IgnoreRule).where(IgnoreRule.target_id == target.id))

    async def test_a_rule_needs_a_reason(self, client, db, pro_user):
        """A rule with no reason is indistinguishable from a mistake when
        somebody reads it back in six months."""
        target = await make_project(db, pro_user)
        await db.commit()
        await sign_in(client, pro_user.email)

        response = await post(
            client,
            f"/api/internal/projects/{target.id}/rules",
            {"identifier": "CVE-2020-1", "reason": ""},
        )

        assert response.status_code == 400

    async def test_the_same_advisory_cannot_be_ignored_twice(self, client, db, pro_user):
        target = await make_project(db, pro_user)
        await db.commit()
        await sign_in(client, pro_user.email)

        body = {"identifier": "CVE-2020-1", "reason": "not reachable"}
        await post(client, f"/api/internal/projects/{target.id}/rules", body)
        second = await post(client, f"/api/internal/projects/{target.id}/rules", body)

        assert second.status_code == 409

    async def test_an_empty_threshold_means_the_default_not_a_floor(self, client, db, pro_user):
        """ "Use the default" and "alert on everything down to low" are
        different answers, so an empty value is stored as NULL."""
        target = await make_project(db, pro_user)
        target.direct_threshold = "high"
        await db.commit()
        await sign_in(client, pro_user.email)

        await post(
            client,
            f"/api/internal/projects/{target.id}/thresholds",
            {"direct": "", "transitive": ""},
        )

        await db.refresh(target)
        assert target.direct_threshold is None

    async def test_an_unknown_severity_is_refused(self, client, db, pro_user):
        target = await make_project(db, pro_user)
        await db.commit()
        await sign_in(client, pro_user.email)

        response = await post(
            client,
            f"/api/internal/projects/{target.id}/thresholds",
            {"direct": "catastrophic"},
        )

        assert response.status_code == 400

    async def test_an_out_of_range_epss_is_refused(self, client, db, pro_user):
        target = await make_project(db, pro_user)
        await db.commit()
        await sign_in(client, pro_user.email)

        response = await post(
            client,
            f"/api/internal/projects/{target.id}/thresholds",
            {"direct": "", "transitive": "", "epss": 900},
        )

        assert response.status_code == 400


class TestScanning:
    async def test_a_project_with_no_manifest_says_so(self, auth_client, db, user):
        target = await make_project(db, user)
        target.manifest_content = None
        target.manifest_kind = None
        await db.commit()

        response = await post(auth_client, f"/api/internal/projects/{target.id}/scan")

        assert response.status_code == 400
        assert response.json()["error"]["code"] == "NO_MANIFEST"

    async def test_a_scan_reports_what_it_found(self, auth_client, db, user):
        from tests.test_scan_pipeline import seed_mirror

        await seed_mirror(db)
        target = await make_project(db, user)
        await db.commit()

        response = await post(auth_client, f"/api/internal/projects/{target.id}/scan")

        assert response.status_code == 200
        assert "actionable" in response.json()["data"]
