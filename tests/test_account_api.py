"""What a signed-in machine can do, and the walls around it.

`weedout auth` puts a credential on a laptop. It exists to do the things that
have no project yet — create one, list them, mint a key for one — and the
reason it is a separate credential from a project key is that neither should be
able to do the other's job:

- A **project key** sits in CI, where anyone who can read a build log can take
  it. It reaches one project.
- A **machine credential** belongs to a person at a keyboard. It reaches the
  account, and cannot read a single finding.

Both are bad to lose, in different and smaller ways than one credential that
does everything. `TestNeitherIsTheOther` is the class that keeps that true.
"""

from __future__ import annotations

import pytest

from app.core.types import Ecosystem, KeyScope
from app.models import ApiKey, TrackedTarget
from app.services.cli_auth_service import (
    approve,
    collect,
    start_request,
)

MANIFEST = '{"dependencies":{"lodash":"4.17.15"}}'


@pytest.fixture
async def machine_token(db, pro_user) -> str:
    """A credential as `weedout auth` would leave it: approved and collected."""
    from sqlalchemy import select

    from app.models import CliAuthRequest

    started = await start_request(db, device_label="dev-laptop")
    await db.flush()
    row = await db.scalar(
        select(CliAuthRequest).where(CliAuthRequest.user_code == started.user_code)
    )
    await approve(db, row, pro_user)
    outcome = await collect(db, started.device_code)
    await db.commit()
    return outcome.token


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestAuthenticating:
    async def test_no_header_says_what_to_run(self, client):
        response = await client.get("/api/account/whoami")

        assert response.status_code == 401
        assert "weedout auth" in response.text

    async def test_a_project_key_is_refused_by_name(self, client, db, pro_user):
        """Somebody who pastes a `wo_` key here has made a comprehensible
        mistake, and naming the right credential is the difference between a
        fix and a support message."""
        from tests.conftest import api_key_for
        from tests.test_api import make_target

        target = await make_target(db, pro_user)
        key = await api_key_for(db, target, scope="manage")
        await db.commit()

        response = await client.get("/api/account/whoami", headers=bearer(key))

        assert response.status_code == 403
        assert "project key" in response.text

    async def test_nonsense_is_a_401(self, client):
        response = await client.get("/api/account/whoami", headers=bearer("woa_nope"))

        assert response.status_code == 401

    async def test_a_valid_credential_says_who_it_is(self, client, machine_token, pro_user):
        response = await client.get("/api/account/whoami", headers=bearer(machine_token))

        assert response.status_code == 200, response.text
        assert response.json()["email"] == pro_user.email
        assert response.json()["device_label"] == "dev-laptop"

    async def test_a_revoked_credential_stops_working(self, client, db, pro_user, machine_token):
        """How the CLI finds out it was signed out from the dashboard."""
        from app.services.cli_auth_service import list_tokens, revoke_token

        token_row = (await list_tokens(db, pro_user.id))[0]
        await revoke_token(db, pro_user.id, token_row.id)
        await db.commit()

        response = await client.get("/api/account/whoami", headers=bearer(machine_token))

        assert response.status_code == 401


class TestCreatingAProject:
    async def test_it_returns_the_project_and_a_key_in_one_call(self, client, machine_token):
        """One call because the alternative is a project that exists with no
        way to reach it, sitting there if the second call fails."""
        response = await client.post(
            "/api/account/projects",
            headers=bearer(machine_token),
            json={"name": "checkout-api", "filename": "package.json", "content": MANIFEST},
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["project"]["name"] == "checkout-api"
        assert body["key"].startswith("wo_")
        assert body["scope"] == "scan"

    async def test_the_key_actually_works_for_that_project(self, client, machine_token):
        created = await client.post(
            "/api/account/projects",
            headers=bearer(machine_token),
            json={"name": "checkout-api", "filename": "package.json", "content": MANIFEST},
        )

        response = await client.get("/api/v1/project", headers=bearer(created.json()["key"]))

        # A scan-scoped key cannot read, which is the correct refusal and also
        # proof the key resolved to something.
        assert response.status_code == 403

    async def test_a_wider_scope_can_be_asked_for(self, client, machine_token):
        created = await client.post(
            "/api/account/projects",
            headers=bearer(machine_token),
            json={
                "name": "checkout-api",
                "filename": "package.json",
                "content": MANIFEST,
                "scope": "read",
            },
        )

        response = await client.get("/api/v1/project", headers=bearer(created.json()["key"]))

        assert created.json()["scope"] == "read"
        assert response.status_code == 200

    async def test_an_empty_project_needs_an_ecosystem(self, client, machine_token):
        """Never guessed. A project that silently changed ecosystem would
        reinterpret every finding recorded against it."""
        response = await client.post(
            "/api/account/projects",
            headers=bearer(machine_token),
            json={"name": "no-lockfile-yet"},
        )

        assert response.status_code == 400
        assert "ecosystem" in response.text.lower()

    async def test_an_empty_project_can_be_created_with_one(self, client, machine_token):
        response = await client.post(
            "/api/account/projects",
            headers=bearer(machine_token),
            json={"name": "no-lockfile-yet", "ecosystem": Ecosystem.NPM.value},
        )

        assert response.status_code == 200, response.text
        assert response.json()["project"]["name"] == "no-lockfile-yet"

    async def test_an_unreadable_manifest_is_refused(self, client, machine_token):
        response = await client.post(
            "/api/account/projects",
            headers=bearer(machine_token),
            json={"name": "broken", "filename": "package.json", "content": "not json"},
        )

        assert response.status_code == 422

    async def test_a_bad_scope_is_refused_before_anything_is_created(
        self, client, db, machine_token
    ):
        from sqlalchemy import func, select

        response = await client.post(
            "/api/account/projects",
            headers=bearer(machine_token),
            json={
                "name": "checkout-api",
                "filename": "package.json",
                "content": MANIFEST,
                "scope": "everything",
            },
        )

        assert response.status_code == 400
        assert await db.scalar(select(func.count(TrackedTarget.id))) == 0

    async def test_free_can_create_multiple_projects(self, client, db, user):
        from sqlalchemy import select

        from app.models import CliAuthRequest

        started = await start_request(db, device_label="laptop")
        await db.flush()
        row = await db.scalar(
            select(CliAuthRequest).where(CliAuthRequest.user_code == started.user_code)
        )
        await approve(db, row, user)
        token = (await collect(db, started.device_code)).token
        await db.commit()

        first = await client.post(
            "/api/account/projects",
            headers=bearer(token),
            json={"name": "one", "filename": "package.json", "content": MANIFEST},
        )
        second = await client.post(
            "/api/account/projects",
            headers=bearer(token),
            json={
                "name": "two",
                "filename": "package.json",
                "content": '{"dependencies":{"express":"4.18.1"}}',
            },
        )

        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text


class TestListingProjects:
    async def test_it_names_them_without_saying_what_is_wrong(
        self, client, db, pro_user, machine_token
    ):
        """This credential is not for reading results. Names and identifiers
        only, which is what linking a directory needs."""
        from tests.test_api import make_target

        await make_target(db, pro_user, name="checkout-api")
        await db.commit()

        response = await client.get("/api/account/projects", headers=bearer(machine_token))

        assert response.status_code == 200
        body = response.json()
        assert [p["name"] for p in body["projects"]] == ["checkout-api"]
        assert "findings" not in response.text
        assert "severity" not in response.text

    async def test_another_account_s_projects_are_not_listed(
        self, client, db, pro_user, second_pro_user, machine_token
    ):
        from tests.test_api import make_target

        await make_target(db, pro_user, name="mine")
        await make_target(db, second_pro_user, name="theirs")
        await db.commit()

        response = await client.get("/api/account/projects", headers=bearer(machine_token))

        assert [p["name"] for p in response.json()["projects"]] == ["mine"]


class TestMintingAKey:
    async def test_it_issues_one_for_an_existing_project(self, client, db, pro_user, machine_token):
        from tests.test_api import make_target

        target = await make_target(db, pro_user)
        await db.commit()

        response = await client.post(
            "/api/account/keys",
            headers=bearer(machine_token),
            json={"project_id": target.id, "scope": "read"},
        )

        assert response.status_code == 200, response.text
        assert response.json()["key"].startswith("wo_")

    async def test_somebody_elses_project_is_a_404(
        self, client, db, second_pro_user, machine_token
    ):
        """Not a 403. Whether an id exists on another account is not this
        account's business."""
        from tests.test_api import make_target

        theirs = await make_target(db, second_pro_user)
        await db.commit()

        response = await client.post(
            "/api/account/keys",
            headers=bearer(machine_token),
            json={"project_id": theirs.id},
        )

        assert response.status_code == 404

    async def test_a_project_that_does_not_exist_is_a_404(self, client, machine_token):
        response = await client.post(
            "/api/account/keys", headers=bearer(machine_token), json={"project_id": 99999}
        )

        assert response.status_code == 404


class TestRegenerating:
    async def test_the_new_key_works_and_the_old_one_stops(
        self, client, db, pro_user, machine_token
    ):
        from tests.conftest import api_key_for
        from tests.test_api import make_target

        target = await make_target(db, pro_user)
        old = await api_key_for(db, target, scope="read")
        from sqlalchemy import select

        old_row = await db.scalar(select(ApiKey).where(ApiKey.target_id == target.id))
        await db.commit()

        response = await client.post(
            "/api/account/keys/regenerate",
            headers=bearer(machine_token),
            json={"project_id": target.id, "scope": "read", "replace_key_id": old_row.id},
        )

        assert response.status_code == 200, response.text
        assert response.json()["replaced"] is True

        new_key = response.json()["key"]
        assert (await client.get("/api/v1/project", headers=bearer(new_key))).status_code == 200
        assert (await client.get("/api/v1/project", headers=bearer(old))).status_code == 401

    async def test_the_old_one_survives_when_nothing_is_named(
        self, client, db, pro_user, machine_token
    ):
        """Rotation without a replacement id is "give me another one", not
        "throw the current one away"."""
        from tests.conftest import api_key_for
        from tests.test_api import make_target

        target = await make_target(db, pro_user)
        old = await api_key_for(db, target, scope="read")
        await db.commit()

        response = await client.post(
            "/api/account/keys/regenerate",
            headers=bearer(machine_token),
            json={"project_id": target.id, "scope": "read"},
        )

        assert response.json()["replaced"] is False
        assert (await client.get("/api/v1/project", headers=bearer(old))).status_code == 200

    async def test_another_account_s_key_cannot_be_revoked_through_it(
        self, client, db, pro_user, second_pro_user, machine_token
    ):
        from sqlalchemy import select

        from tests.conftest import api_key_for
        from tests.test_api import make_target

        mine = await make_target(db, pro_user, name="mine")
        theirs = await make_target(db, second_pro_user, name="theirs")
        theirs_key = await api_key_for(db, theirs, scope="read")
        theirs_row = await db.scalar(select(ApiKey).where(ApiKey.target_id == theirs.id))
        await db.commit()

        response = await client.post(
            "/api/account/keys/regenerate",
            headers=bearer(machine_token),
            json={"project_id": mine.id, "replace_key_id": theirs_row.id},
        )

        assert response.status_code == 200
        assert response.json()["replaced"] is False, "somebody else's key was revoked"
        assert (await client.get("/api/v1/project", headers=bearer(theirs_key))).status_code == 200


class TestNeitherIsTheOther:
    """Two credential types, and the walls between them."""

    async def test_a_machine_credential_cannot_read_findings(
        self, client, db, pro_user, machine_token
    ):
        from tests.test_api import make_target

        await make_target(db, pro_user)
        await db.commit()

        for path in ("/api/v1/project", "/api/v1/findings", "/api/v1/rules"):
            response = await client.get(path, headers=bearer(machine_token))
            assert response.status_code == 401, f"{path} accepted a machine credential"

    async def test_a_machine_credential_cannot_push_a_scan(
        self, client, db, pro_user, machine_token
    ):
        from tests.test_api import make_target

        await make_target(db, pro_user)
        await db.commit()

        response = await client.post(
            "/api/v1/scan",
            headers=bearer(machine_token),
            files={"manifest": ("package.json", MANIFEST)},
        )

        assert response.status_code == 401

    async def test_a_manage_key_cannot_create_a_project(self, client, db, pro_user):
        """The widest project key there is, and it still cannot reach the
        account."""
        from tests.conftest import api_key_for
        from tests.test_api import make_target

        target = await make_target(db, pro_user)
        key = await api_key_for(db, target, scope="manage")
        await db.commit()

        response = await client.post(
            "/api/account/projects",
            headers=bearer(key),
            json={"name": "sneaky", "filename": "package.json", "content": MANIFEST},
        )

        assert response.status_code == 403

    async def test_a_session_cookie_does_not_reach_the_account_api(self, auth_client):
        """No ambient authority. A logged-in browser must not be usable to make
        these calls, which is the same reason /api/v1 refuses one."""
        response = await auth_client.get("/api/account/whoami")

        assert response.status_code == 401

    def test_the_scopes_a_key_can_have_are_unchanged(self):
        """A guard against the obvious wrong fix: adding an "account" scope to
        `KeyScope` and widening project keys instead of keeping two types."""
        assert {scope.value for scope in KeyScope} == {"scan", "read", "manage"}


class TestNothingIsCached:
    @pytest.mark.parametrize("path", ["/api/account/whoami", "/api/account/projects"])
    async def test_responses_carry_no_store(self, client, machine_token, path):
        """Two of these return a credential, and all of them describe an
        account. Anything in between must be told not to keep them."""
        response = await client.get(path, headers=bearer(machine_token))

        assert response.headers["cache-control"] == "no-store"
