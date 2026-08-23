"""Named rule profiles, and the four-layer policy they sit inside.

The problem: a team with eight services wants the same floors on all of them, a
looser set on the internal tools, and something stricter on the one facing the
internet. Configuring that per project means eight copies that drift, and
changing the standard means eight edits.

The property worth pinning hardest is in `TestResolutionIsServerSide`.
`--profile production` is a *claim by the caller* about which rules it would
like. If a name that does not exist quietly fell back to the defaults, a
pipeline would report success while running under rules nobody chose, and
nobody would find out until it mattered.
"""

from __future__ import annotations

import pytest

from app.core.types import Severity
from app.services.profile_service import (
    MAX_PROFILES,
    NoSuchProfile,
    ProfileError,
    ProfileLimitReached,
    ProfileNameTaken,
    create_profile,
    delete_profile,
    get_profile,
    list_profiles,
    profile_for_scan,
    set_default,
    slugify_profile,
    update_profile,
)
from app.services.rules_service import build_policy
from app.services.target_service import create_target
from tests.conftest import set_csrf

STRICT = """
severity:
  direct: low
  transitive: medium
ignore:
  - cve: CVE-2020-0001
    reason: Reviewed by the platform team and not applicable to us.
"""

LOOSE = """
severity:
  direct: critical
  transitive: critical
"""


async def a_project(db, owner, content='{"dependencies":{"lodash":"4.17.15"}}'):
    return await create_target(db, owner, filename="package.json", content=content)


class TestNaming:
    @pytest.mark.parametrize(
        ("written", "slug"),
        [
            ("Production", "production"),
            ("Production APIs", "production-apis"),
            ("PRODUCTION_APIS", "production-apis"),
            ("  internal tools  ", "internal-tools"),
            ("v2 / edge", "v2-edge"),
        ],
    )
    def test_a_pipeline_does_not_have_to_reproduce_the_typing(self, written, slug):
        assert slugify_profile(written) == slug

    async def test_a_name_that_normalises_to_nothing_is_refused(self, db, pro_user):
        with pytest.raises(ProfileError):
            await create_profile(db, pro_user, name="   ///   ")

    async def test_two_profiles_cannot_share_a_slug(self, db, pro_user):
        await create_profile(db, pro_user, name="Production")

        with pytest.raises(ProfileNameTaken):
            await create_profile(db, pro_user, name="PRODUCTION")

    async def test_two_accounts_can(self, db, pro_user, second_pro_user):
        await create_profile(db, pro_user, name="Production")
        await create_profile(db, second_pro_user, name="Production")

        assert len(await list_profiles(db, pro_user.id)) == 1
        assert len(await list_profiles(db, second_pro_user.id)) == 1


class TestValidationAtSaveTime:
    """The repository file is recorded with its error and discarded at scan
    time, because refusing a push is not something the server can do. Here it
    can: somebody is standing there."""

    async def test_a_document_that_will_not_parse_is_refused(self, db, pro_user):
        with pytest.raises(ProfileError):
            await create_profile(db, pro_user, name="Broken", document="severity: [")

    async def test_nothing_is_stored_when_it_is_refused(self, db, pro_user):
        with pytest.raises(ProfileError):
            await create_profile(db, pro_user, name="Broken", document="severity: [")

        assert await list_profiles(db, pro_user.id) == []

    async def test_a_profile_cannot_name_a_profile(self, db, pro_user):
        """No useful reading, and an obvious bad one: profiles referencing each
        other in a loop."""
        with pytest.raises(ProfileError, match="cannot name another profile"):
            await create_profile(db, pro_user, name="Circular", document="profile: itself\n")

    async def test_an_empty_document_is_fine(self, db, pro_user):
        """A profile with nothing in it yet is a normal step towards one with
        something in it."""
        profile = await create_profile(db, pro_user, name="Empty")

        assert profile.document == ""

    async def test_an_edit_is_validated_too(self, db, pro_user):
        profile = await create_profile(db, pro_user, name="Production", document=STRICT)

        with pytest.raises(ProfileError):
            await update_profile(db, profile, document="severity: [")

        assert profile.document == STRICT, "the refused document must not have been written"


class TestTheDefault:
    async def test_the_first_profile_becomes_it(self, db, pro_user):
        """Somebody who creates exactly one profile means for it to apply.
        Making them take a second step is a way to end up with a profile that
        does nothing."""
        profile = await create_profile(db, pro_user, name="Production")

        assert profile.is_default is True

    async def test_the_second_does_not(self, db, pro_user):
        await create_profile(db, pro_user, name="Production")
        second = await create_profile(db, pro_user, name="Internal tools")

        assert second.is_default is False

    async def test_setting_one_clears_the_other(self, db, pro_user):
        """Two defaults would leave "which rules apply" without an answer, and
        the partial unique index would refuse the write anyway."""
        first = await create_profile(db, pro_user, name="Production")
        second = await create_profile(db, pro_user, name="Internal tools")

        await set_default(db, pro_user.id, second)

        assert first.is_default is False
        assert second.is_default is True

    async def test_it_can_be_cleared_entirely(self, db, pro_user):
        profile = await create_profile(db, pro_user, name="Production")

        await set_default(db, pro_user.id, None)

        assert profile.is_default is False

    async def test_the_default_is_listed_first(self, db, pro_user):
        await create_profile(db, pro_user, name="Alpha")
        zulu = await create_profile(db, pro_user, name="Zulu")
        await set_default(db, pro_user.id, zulu)

        assert [p.name for p in await list_profiles(db, pro_user.id)] == ["Zulu", "Alpha"]


class TestResolutionIsServerSide:
    """The property this whole feature stands on."""

    async def test_a_requested_name_resolves_against_the_account(self, db, pro_user):
        await create_profile(db, pro_user, name="Production", document=STRICT)
        target = await a_project(db, pro_user)

        resolved = await profile_for_scan(db, target, requested="PRODUCTION")

        assert resolved is not None
        assert resolved.slug == "production"

    async def test_a_name_that_does_not_exist_raises(self, db, pro_user):
        """Not a silent fall back. A pipeline running under rules nobody chose,
        reporting success, is worse than one that fails."""
        target = await a_project(db, pro_user)

        with pytest.raises(NoSuchProfile, match="production"):
            await profile_for_scan(db, target, requested="production")

    async def test_another_account_s_profile_does_not_resolve(self, db, pro_user, second_pro_user):
        await create_profile(db, second_pro_user, name="Production", document=STRICT)
        target = await a_project(db, pro_user)

        with pytest.raises(NoSuchProfile):
            await profile_for_scan(db, target, requested="production")

    async def test_the_project_s_own_choice_is_used_when_nothing_is_requested(self, db, pro_user):
        default = await create_profile(db, pro_user, name="Production")
        chosen = await create_profile(db, pro_user, name="Internal tools")
        target = await a_project(db, pro_user)
        target.profile_id = chosen.id
        await db.flush()

        resolved = await profile_for_scan(db, target)

        assert resolved is not None
        assert resolved.id == chosen.id
        assert default.id != chosen.id

    async def test_a_request_beats_the_project_s_choice(self, db, pro_user):
        """The more local statement, made at the moment the scan was asked
        for."""
        chosen = await create_profile(db, pro_user, name="Internal tools")
        await create_profile(db, pro_user, name="Production")
        target = await a_project(db, pro_user)
        target.profile_id = chosen.id
        await db.flush()

        resolved = await profile_for_scan(db, target, requested="production")

        assert resolved is not None
        assert resolved.slug == "production"

    async def test_the_account_default_applies_when_the_project_has_not_chosen(self, db, pro_user):
        default = await create_profile(db, pro_user, name="Production")
        target = await a_project(db, pro_user)

        resolved = await profile_for_scan(db, target)

        assert resolved is not None
        assert resolved.id == default.id

    async def test_nothing_applies_when_the_account_has_no_default(self, db, pro_user):
        profile = await create_profile(db, pro_user, name="Production")
        await set_default(db, pro_user.id, None)
        target = await a_project(db, pro_user)

        assert await profile_for_scan(db, target) is None
        assert profile.is_default is False

    async def test_a_profile_belonging_to_someone_else_is_not_honoured(
        self, db, pro_user, second_pro_user
    ):
        """The column is set through an endpoint that checks ownership, but the
        answer here decides what gets reported and must not depend on that."""
        theirs = await create_profile(db, second_pro_user, name="Theirs", document=STRICT)
        target = await a_project(db, pro_user)
        target.profile_id = theirs.id
        await db.flush()

        assert await profile_for_scan(db, target) is None


class TestTheLayering:
    """Four sources: the plan, the profile, the project, the file."""

    async def test_a_profile_sets_the_floors(self, db, pro_user):
        await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await a_project(db, pro_user)

        effective = await build_policy(db, target, pro_user)

        assert effective.policy.direct_threshold is Severity.LOW
        assert effective.policy.transitive_threshold is Severity.MEDIUM
        assert effective.profile_name == "Strict"

    async def test_the_project_s_own_setting_beats_the_profile(self, db, pro_user):
        """A shared standard is a baseline every project starts from. A profile
        that beat the project's own settings would make the per-project
        controls decorative."""
        await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await a_project(db, pro_user)
        target.direct_threshold = Severity.CRITICAL
        await db.flush()

        effective = await build_policy(db, target, pro_user)

        assert effective.policy.direct_threshold is Severity.CRITICAL
        # And the setting the project said nothing about still comes from the
        # profile: precedence is per setting, not all-or-nothing.
        assert effective.policy.transitive_threshold is Severity.MEDIUM

    async def test_the_repository_file_beats_both(self, db, pro_user):
        await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await a_project(db, pro_user)
        target.direct_threshold = Severity.CRITICAL
        target.policy_file = "severity:\n  direct: high\n"
        await db.flush()

        effective = await build_policy(db, target, pro_user)

        assert effective.policy.direct_threshold is Severity.HIGH

    async def test_ignores_from_every_layer_are_unioned(self, db, pro_user):
        """No layer un-ignores what another ignored. The only way to stop
        ignoring something is to remove the rule that says so."""
        from app.models import IgnoreRule

        await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await a_project(db, pro_user)
        db.add(
            IgnoreRule(
                target_id=target.id,
                identifier="CVE-2020-0002",
                reason="Reviewed on this project specifically.",
            )
        )
        target.policy_file = (
            "ignore:\n  - cve: CVE-2020-0003\n    reason: from the repository file\n"
        )
        await db.flush()

        effective = await build_policy(db, target, pro_user)

        assert effective.policy.ignored_ids == frozenset(
            {"CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"}
        )
        assert effective.ignored_from_profile == ("CVE-2020-0001",)

    async def test_a_requested_profile_reaches_the_policy(self, db, pro_user):
        await create_profile(db, pro_user, name="Loose", document=LOOSE)
        await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await a_project(db, pro_user)

        effective = await build_policy(db, target, pro_user, requested_profile="strict")

        assert effective.policy.direct_threshold is Severity.LOW
        assert effective.profile_name == "Strict"

    async def test_the_file_may_name_the_profile(self, db, pro_user):
        """How a repository says "these are production rules" without every
        pipeline passing a flag."""
        await create_profile(db, pro_user, name="Loose", document=LOOSE)
        await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await a_project(db, pro_user)
        target.policy_file = "profile: strict\n"
        await db.flush()

        effective = await build_policy(db, target, pro_user)

        assert effective.profile_name == "Strict"

    async def test_an_explicit_request_beats_the_file_s_choice(self, db, pro_user):
        """Which is a deliberate exception to "the file wins". The file wins on
        *rules*; which profile to use is chosen at the moment of invocation,
        and a flag typed there is the more local statement."""
        await create_profile(db, pro_user, name="Loose", document=LOOSE)
        await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await a_project(db, pro_user)
        target.policy_file = "profile: strict\n"
        await db.flush()

        effective = await build_policy(db, target, pro_user, requested_profile="loose")

        assert effective.profile_name == "Loose"

    async def test_an_epss_threshold_of_zero_is_not_treated_as_unset(self, db, pro_user):
        """`or` would be wrong here: 0.0 is a legitimate threshold and a falsy
        one, so a project setting it to zero would silently inherit whatever
        the profile said."""
        await create_profile(db, pro_user, name="Strict", document="epss:\n  alert_above: 0.9\n")
        target = await a_project(db, pro_user)
        target.epss_threshold = 0.0
        await db.flush()

        effective = await build_policy(db, target, pro_user)

        assert effective.policy.epss_threshold == 0.0


class TestItIsPro:
    async def test_a_free_account_gets_no_profile(self, db, user):
        """Enforced where the rules are used, like every other gate, so a
        lapsed subscription stops applying them without deleting anything."""
        profile = await create_profile(db, user, name="Strict", document=STRICT)
        target = await a_project(db, user)
        target.profile_id = profile.id
        await db.flush()

        effective = await build_policy(db, target, user)

        assert effective.policy.direct_threshold is not Severity.LOW
        assert effective.profile_name is None
        assert any("Pro plan" in note for note in effective.notes)

    async def test_a_free_account_asking_for_one_is_told_it_did_not_apply(self, db, user):
        target = await a_project(db, user)

        effective = await build_policy(db, target, user, requested_profile="anything")

        assert any("Pro plan" in note for note in effective.notes)

    async def test_the_endpoint_refuses_a_free_account(self, auth_client):
        response = await auth_client.post(
            "/api/internal/profiles",
            json={"name": "Production", "document": STRICT},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )

        assert response.status_code == 402


class TestDeleting:
    async def test_projects_using_it_fall_back(self, db, pro_user):
        """A profile nobody can delete until they have visited every project
        using it is a profile people work around by emptying its document
        instead -- which leaves a rule set that looks configured and does
        nothing."""
        profile = await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await a_project(db, pro_user)
        target.profile_id = profile.id
        await db.flush()

        await delete_profile(db, profile)
        await db.refresh(target)

        assert target.profile_id is None

    async def test_the_name_is_free_again(self, db, pro_user):
        profile = await create_profile(db, pro_user, name="Strict")
        await delete_profile(db, profile)

        await create_profile(db, pro_user, name="Strict")  # must not raise


class TestTheLimit:
    async def test_a_runaway_script_cannot_fill_the_table(self, db, pro_user):
        for index in range(MAX_PROFILES):
            await create_profile(db, pro_user, name=f"Profile {index}")

        with pytest.raises(ProfileLimitReached):
            await create_profile(db, pro_user, name="One too many")


class TestThroughTheInterface:
    async def test_creating_one_and_reading_it_back(self, pro_client):
        created = await pro_client.post(
            "/api/internal/profiles",
            json={
                "name": "Production APIs",
                "description": "What everything customer-facing runs under.",
                "document": STRICT,
            },
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )

        assert created.status_code == 200, created.text
        body = created.json()["data"]
        assert body["slug"] == "production-apis"
        assert body["is_default"] is True

        listed = await pro_client.get("/api/internal/profiles")
        assert [p["slug"] for p in listed.json()["data"]] == ["production-apis"]

    async def test_a_broken_document_is_refused_with_a_readable_reason(self, pro_client):
        response = await pro_client.post(
            "/api/internal/profiles",
            json={"name": "Broken", "document": "severity: ["},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )

        assert response.status_code == 400
        assert "YAML" in response.text

    async def test_somebody_else_s_profile_is_a_404(self, pro_client, db, second_pro_user):
        theirs = await create_profile(db, second_pro_user, name="Theirs")
        await db.commit()

        response = await pro_client.post(
            f"/api/internal/profiles/{theirs.id}",
            json={"name": "Mine now"},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )

        assert response.status_code == 404

    async def test_a_project_can_choose_one(self, pro_client, db, pro_user):
        from tests.conftest import create_project

        await create_profile(db, pro_user, name="Strict", document=STRICT)
        await db.commit()
        created = await create_project(
            pro_client, filename="package.json", content='{"dependencies":{"lodash":"4.17.15"}}'
        )
        project_id = created.json()["data"]["id"]

        chosen = await pro_client.post(
            f"/api/internal/projects/{project_id}/profile",
            json={"profile": "strict"},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )

        assert chosen.status_code == 200, chosen.text
        page = await pro_client.get(f"/api/internal/projects/{project_id}")
        assert page.json()["profiles"]["chosen"] == "strict"
        assert page.json()["profiles"]["following_default"] is False

    async def test_a_project_that_has_not_chosen_says_which_default_it_follows(
        self, pro_client, db, pro_user
    ):
        """A page showing only the chosen profile would leave "we have not
        chosen, so what are we running?" unanswered, which is the state most
        projects are in."""
        from tests.conftest import create_project

        await create_profile(db, pro_user, name="Strict", document=STRICT)
        await db.commit()
        created = await create_project(
            pro_client, filename="package.json", content='{"dependencies":{"lodash":"4.17.15"}}'
        )
        project_id = created.json()["data"]["id"]

        page = (await pro_client.get(f"/api/internal/projects/{project_id}")).json()

        assert page["profiles"]["chosen"] is None
        assert page["profiles"]["applies"] == "strict"
        assert page["profiles"]["following_default"] is True

    async def test_choosing_a_profile_that_does_not_exist_is_a_404(self, pro_client, db, pro_user):
        from tests.conftest import create_project

        created = await create_project(
            pro_client, filename="package.json", content='{"dependencies":{"lodash":"4.17.15"}}'
        )
        project_id = created.json()["data"]["id"]

        response = await pro_client.post(
            f"/api/internal/projects/{project_id}/profile",
            json={"profile": "nothing-like-this"},
            headers={"X-CSRF-Token": set_csrf(pro_client)},
        )

        assert response.status_code == 404


class TestThroughTheMachineApi:
    async def test_a_scan_can_name_a_profile(self, client, db, pro_user):
        from tests.conftest import api_key_for
        from tests.test_scan_pipeline import make_target, seed_mirror

        await seed_mirror(db)
        await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await make_target(db, pro_user)
        key = await api_key_for(db, target, scope="scan")
        await db.commit()

        response = await client.post(
            "/api/v1/scan",
            headers={"Authorization": f"Bearer {key}"},
            files={"manifest": ("package.json", '{"dependencies":{"lodash":"4.17.15"}}')},
            data={"profile": "strict"},
        )

        assert response.status_code == 200, response.text

    async def test_a_name_that_does_not_exist_fails_the_scan(self, client, db, pro_user):
        """400 rather than a scan that silently ran on the defaults. Nothing
        was recorded under rules nobody chose."""
        from tests.conftest import api_key_for
        from tests.test_scan_pipeline import make_target, seed_mirror

        await seed_mirror(db)
        target = await make_target(db, pro_user)
        key = await api_key_for(db, target, scope="scan")
        await db.commit()

        response = await client.post(
            "/api/v1/scan",
            headers={"Authorization": f"Bearer {key}"},
            files={"manifest": ("package.json", '{"dependencies":{"lodash":"4.17.15"}}')},
            data={"profile": "nothing-like-this"},
        )

        assert response.status_code == 400
        assert "no rule profile" in response.text.lower()

    async def test_the_uploaded_policy_file_can_name_the_profile(self, client, db, pro_user):
        """End to end, because this is the path that was broken.

        The server has accepted a `policy` part since the feature was written
        and no client sent one, so a repository's rules never reached a scan.
        Uploading one here checks the whole chain: the part is read, stored,
        parsed, and its `profile:` key resolves.
        """
        from tests.conftest import api_key_for
        from tests.test_scan_pipeline import make_target, seed_mirror

        await seed_mirror(db)
        await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await make_target(db, pro_user)
        key = await api_key_for(db, target, scope="scan")
        await db.commit()

        response = await client.post(
            "/api/v1/scan",
            headers={"Authorization": f"Bearer {key}"},
            files={
                "manifest": ("package.json", '{"dependencies":{"lodash":"4.17.15"}}'),
                "policy": (".weedout.yml", "profile: strict\n"),
            },
        )

        assert response.status_code == 200, response.text
        await db.refresh(target)
        assert target.policy_file == "profile: strict\n"
        assert target.policy_file_error is None

        effective = await build_policy(db, target, pro_user)
        assert effective.profile_name == "Strict"

    async def test_a_policy_file_naming_a_missing_profile_fails_the_scan(
        self, client, db, pro_user
    ):
        """Same refusal as the flag. A repository asking for rules that do not
        exist is running under rules nobody chose."""
        from tests.conftest import api_key_for
        from tests.test_scan_pipeline import make_target, seed_mirror

        await seed_mirror(db)
        target = await make_target(db, pro_user)
        key = await api_key_for(db, target, scope="scan")
        await db.commit()

        response = await client.post(
            "/api/v1/scan",
            headers={"Authorization": f"Bearer {key}"},
            files={
                "manifest": ("package.json", '{"dependencies":{"lodash":"4.17.15"}}'),
                "policy": (".weedout.yml", "profile: nothing-like-this\n"),
            },
        )

        assert response.status_code == 400
        assert "no rule profile" in response.text.lower()

    async def test_a_read_key_can_list_them(self, client, db, pro_user):
        from tests.conftest import api_key_for
        from tests.test_scan_pipeline import make_target

        await create_profile(db, pro_user, name="Strict", document=STRICT)
        target = await make_target(db, pro_user)
        key = await api_key_for(db, target, scope="read")
        await db.commit()

        response = await client.get("/api/v1/profiles", headers={"Authorization": f"Bearer {key}"})

        assert response.status_code == 200, response.text
        body = response.json()
        assert [p["slug"] for p in body["profiles"]] == ["strict"]
        # The question the listing is usually opened for.
        assert body["applies_here"] == "strict"

    async def test_a_scan_key_cannot(self, client, db, pro_user):
        """Read scope, not scan. A pipeline key that could enumerate the
        account's rule sets is more than it needs to push a manifest."""
        from tests.conftest import api_key_for
        from tests.test_scan_pipeline import make_target

        target = await make_target(db, pro_user)
        key = await api_key_for(db, target, scope="scan")
        await db.commit()

        response = await client.get("/api/v1/profiles", headers={"Authorization": f"Bearer {key}"})

        assert response.status_code == 403


class TestGetProfile:
    async def test_lookup_is_by_slug_however_it_is_typed(self, db, pro_user):
        await create_profile(db, pro_user, name="Production APIs")

        for spelling in ("production-apis", "Production APIs", "PRODUCTION_APIS"):
            assert await get_profile(db, pro_user.id, spelling) is not None

    async def test_an_unknown_name_is_none_rather_than_an_error(self, db, pro_user):
        """The raising happens in `profile_for_scan`, where a missing name
        means a scan is about to run under the wrong rules. A lookup is just a
        lookup."""
        assert await get_profile(db, pro_user.id, "nothing") is None
