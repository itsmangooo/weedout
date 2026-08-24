"""An account that is a company, and the gate on naming one in public.

Two separate things, and the second is where the care goes.

**Account kind** is a label. It changes nothing about the plan or the limits —
`TestItChangesNothingAboutTheAccount` is what keeps that true, because an
account type that quietly altered either would make "are you a company?" a
question with a wrong answer, and people would learn to answer it in whichever
direction was cheaper.

**The showcase** needs two independent things before a name appears anywhere
public: they asked, and we checked. For a security product naming a customer
says they scan their dependencies with us, which is a fact about their security
programme and theirs to disclose. And consent alone would let anybody sign up
as a well-known company and land on the front page.

`TestNothingIsPublishedWithoutBoth` is the class that would catch either half
being dropped.

This is deliberately **not** a team. One login, no members, no roles. Building
that is a materially larger feature, and `test_there_are_no_members` records
that as a decision rather than an omission.
"""

from __future__ import annotations

import pytest

from app.core.types import AccountKind, Tier
from app.services.organisation_service import (
    MAX_SHOWCASE,
    OrganisationError,
    approve_showcase,
    become_organisation,
    become_personal,
    revoke_showcase,
    set_showcase_opt_in,
    showcased_organisations,
)
from app.tiers import limits_for
from tests.conftest import set_csrf


async def a_listed_company(db, user, *, name: str = "Acme Ltd") -> None:
    """Both halves: they asked, and we checked."""
    await become_organisation(db, user, name=name, website="https://acme.example")
    await set_showcase_opt_in(db, user, opted_in=True)
    await approve_showcase(db, user)


class TestBecomingAnOrganisation:
    async def test_it_records_the_name(self, db, user):
        await become_organisation(db, user, name="  Acme Ltd  ")

        assert user.account_kind is AccountKind.ORGANIZATION
        assert user.organisation_name == "Acme Ltd"

    async def test_a_website_is_optional(self, db, user):
        await become_organisation(db, user, name="Acme Ltd")

        assert user.organisation_website is None

    async def test_a_website_must_look_like_one(self, db, user):
        with pytest.raises(OrganisationError, match="https://"):
            await become_organisation(db, user, name="Acme Ltd", website="acme.example")

    async def test_an_empty_name_is_refused(self, db, user):
        with pytest.raises(OrganisationError):
            await become_organisation(db, user, name="   ")

    async def test_going_back_to_personal_clears_everything(self, db, user):
        """Including the showcase. An account with no company name has nothing
        to show, and leaving the opt-in set would mean a later rename
        re-published somebody who had stopped being a company."""
        await a_listed_company(db, user)

        await become_personal(db, user)

        assert user.account_kind is AccountKind.PERSONAL
        assert user.organisation_name is None
        assert user.showcase_opt_in is False
        assert user.showcase_approved_at is None

    async def test_renaming_withdraws_the_approval(self, db, user):
        """We checked that one name was theirs to give. The next one is a
        different claim, and carrying the tick over would let an approved
        account swap in any name it liked."""
        await a_listed_company(db, user, name="Acme Ltd")
        assert user.is_showcased is True

        await become_organisation(db, user, name="Google")

        assert user.showcase_approved_at is None
        assert user.is_showcased is False
        # Their consent survives, because they did not withdraw it.
        assert user.showcase_opt_in is True


class TestItChangesNothingAboutTheAccount:
    """A label, not a capability."""

    async def test_the_plan_is_untouched(self, db, user):
        before = user.tier
        await become_organisation(db, user, name="Acme Ltd")

        assert user.tier is before

    async def test_the_limits_are_identical(self, db, user):
        await become_organisation(db, user, name="Acme Ltd")

        assert limits_for(user.tier) is limits_for(Tier.FREE)

    def test_there_are_no_members(self):
        """Recorded as a decision, not an omission.

        This is an account type, not a team. One login, one set of
        credentials, nobody to invite. Teams need invitations, roles,
        per-member audit and an answer to what happens to a project when the
        person who made it leaves — a materially larger feature, and calling
        this one a team would promise all of it.
        """
        from app.models import User

        assert not hasattr(User, "members")
        assert not hasattr(User, "organisation_id")


class TestNothingIsPublishedWithoutBoth:
    """The class that catches either half of the gate being dropped."""

    async def test_a_personal_account_is_never_listed(self, db, user):
        assert user.is_showcased is False
        assert await showcased_organisations(db) == []

    async def test_consent_alone_is_not_enough(self, db, user):
        """Otherwise anybody could sign up as a well-known company and land on
        our front page — impersonation with our marketing as the vehicle."""
        await become_organisation(db, user, name="Google")
        await set_showcase_opt_in(db, user, opted_in=True)

        assert user.is_showcased is False
        assert await showcased_organisations(db) == []

    async def test_approval_alone_is_not_enough(self, db, user):
        """Naming a customer says publicly that they scan their dependencies
        with us. That is theirs to disclose, not ours."""
        await become_organisation(db, user, name="Acme Ltd")
        await approve_showcase(db, user)

        assert user.is_showcased is False
        assert await showcased_organisations(db) == []

    async def test_both_together_publish(self, db, user):
        await a_listed_company(db, user)

        assert user.is_showcased is True
        assert [account.organisation_name for account in await showcased_organisations(db)] == [
            "Acme Ltd"
        ]

    async def test_withdrawing_consent_takes_effect_immediately(self, db, user):
        """And needs nobody's approval. Withdrawing consent must never be
        slower than giving it."""
        await a_listed_company(db, user)

        await set_showcase_opt_in(db, user, opted_in=False)

        assert user.is_showcased is False
        assert await showcased_organisations(db) == []

    async def test_withdrawing_approval_does_not_clear_their_consent(self, db, user):
        """They are separate facts. Conflating them would let a withdrawal by
        us look like a decision by them."""
        await a_listed_company(db, user)

        await revoke_showcase(db, user)

        assert user.showcase_opt_in is True
        assert user.is_showcased is False

    async def test_a_personal_account_cannot_opt_in(self, db, user):
        with pytest.raises(OrganisationError, match="organisation account"):
            await set_showcase_opt_in(db, user, opted_in=True)

    async def test_an_account_with_no_name_cannot_be_approved(self, db, user):
        with pytest.raises(OrganisationError):
            await approve_showcase(db, user)

    async def test_a_suspended_account_is_not_listed(self, db, user):
        """A name on the front page is an endorsement in both directions."""
        await a_listed_company(db, user)
        user.is_suspended = True
        await db.flush()

        assert await showcased_organisations(db) == []

    async def test_a_deactivated_account_is_not_listed(self, db, user):
        await a_listed_company(db, user)
        user.is_active = False
        await db.flush()

        assert await showcased_organisations(db) == []


class TestTheListing:
    async def test_it_is_capped(self, db):
        """A wall of forty is a wall nobody reads, and the section should stop
        growing before it starts looking like a directory."""
        from app.models import User
        from app.security import hash_password

        for index in range(MAX_SHOWCASE + 3):
            account = User(
                email=f"org{index}@example.com",
                password_hash=hash_password("correct-horse-battery"),
            )
            db.add(account)
            await db.flush()
            await a_listed_company(db, account, name=f"Company {index}")

        assert len(await showcased_organisations(db)) == MAX_SHOWCASE

    async def test_the_order_is_stable(self, db, user, pro_user):
        """Oldest approval first, so the section does not reshuffle on every
        deploy."""
        await a_listed_company(db, pro_user, name="First")
        await a_listed_company(db, user, name="Second")

        assert [a.organisation_name for a in await showcased_organisations(db)] == [
            "First",
            "Second",
        ]


class TestDisplayName:
    async def test_a_company_is_called_by_its_name(self, db, user):
        await become_organisation(db, user, name="Acme Ltd")

        assert user.display_name == "Acme Ltd"

    def test_a_person_is_called_by_their_email(self, user):
        """Never a guess at somebody's name from their address."""
        assert user.display_name == user.email


class TestThroughTheInterface:
    async def test_an_account_can_declare_itself_a_company(self, auth_client):
        response = await auth_client.post(
            "/api/internal/settings/organisation",
            json={"name": "Acme Ltd", "website": "https://acme.example"},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )

        assert response.status_code == 200, response.text
        assert response.json()["data"]["account_kind"] == "organization"

        page = await auth_client.get("/api/internal/settings")
        assert page.json()["data"]["organisation_name"] == "Acme Ltd"

    async def test_an_empty_name_makes_it_personal_again(self, auth_client):
        csrf = set_csrf(auth_client)
        await auth_client.post(
            "/api/internal/settings/organisation",
            json={"name": "Acme Ltd"},
            headers={"X-CSRF-Token": csrf},
        )

        response = await auth_client.post(
            "/api/internal/settings/organisation",
            json={"name": ""},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )

        assert response.json()["data"]["account_kind"] == "personal"

    async def test_opting_in_does_not_publish_on_its_own(self, auth_client):
        """The interface has to be able to say "asked for, not yet listed". An
        opt-in that looks done while nothing is published is a promise we did
        not make."""
        csrf = set_csrf(auth_client)
        await auth_client.post(
            "/api/internal/settings/organisation",
            json={"name": "Acme Ltd"},
            headers={"X-CSRF-Token": csrf},
        )

        response = await auth_client.post(
            "/api/internal/settings/showcase",
            json={"listed": True},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )

        assert response.json()["data"]["showcase_opt_in"] is True
        assert response.json()["data"]["showcase_listed"] is False

    async def test_it_needs_the_csrf_token(self, auth_client):
        set_csrf(auth_client)

        response = await auth_client.post(
            "/api/internal/settings/organisation", json={"name": "Acme Ltd"}
        )

        assert response.status_code == 403

    async def test_a_stranger_cannot_set_one(self, client):
        response = await client.post(
            "/api/internal/settings/organisation",
            json={"name": "Acme Ltd"},
            headers={"X-CSRF-Token": set_csrf(client)},
        )

        assert response.status_code == 401


class TestThroughTheAdminPanel:
    async def test_an_admin_can_approve(self, admin_client, db, user):
        await become_organisation(db, user, name="Acme Ltd")
        await set_showcase_opt_in(db, user, opted_in=True)
        await db.commit()

        response = await admin_client.post(
            f"/api/internal/admin/users/{user.id}/showcase",
            json={"approved": True},
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )

        assert response.status_code == 200, response.text
        assert response.json()["data"]["user"]["showcase_listed"] is True

    async def test_approving_is_audited(self, admin_client, db, user):
        """Publishing a customer's name is not a small thing. "Who approved
        that, and when" has to have an answer."""
        from sqlalchemy import select

        from app.models import AdminAuditLog

        await become_organisation(db, user, name="Acme Ltd")
        await set_showcase_opt_in(db, user, opted_in=True)
        await db.commit()

        await admin_client.post(
            f"/api/internal/admin/users/{user.id}/showcase",
            json={"approved": True},
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )

        entries = (await db.scalars(select(AdminAuditLog))).all()
        assert any(entry.action == "user.showcase_approved" for entry in entries)

    async def test_an_admin_can_withdraw(self, admin_client, db, user):
        await a_listed_company(db, user)
        await db.commit()

        response = await admin_client.post(
            f"/api/internal/admin/users/{user.id}/showcase",
            json={"approved": False},
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )

        assert response.json()["data"]["user"]["showcase_listed"] is False

    async def test_a_normal_account_cannot_approve_itself(self, auth_client, db, user):
        await become_organisation(db, user, name="Acme Ltd")
        await set_showcase_opt_in(db, user, opted_in=True)
        await db.commit()

        response = await auth_client.post(
            f"/api/internal/admin/users/{user.id}/showcase",
            json={"approved": True},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )

        assert response.status_code in (403, 404)


class TestOnTheLandingPage:
    async def test_a_listed_company_appears(self, client, db, user):
        await a_listed_company(db, user)
        await db.commit()

        response = await client.get("/api/internal/landing")

        assert response.status_code == 200
        assert response.json()["data"]["used_by"] == [
            {"name": "Acme Ltd", "website": "https://acme.example"}
        ]

    async def test_nobody_appears_by_default(self, client, db, user):
        await db.commit()

        response = await client.get("/api/internal/landing")

        assert response.json()["data"]["used_by"] == []

    async def test_an_email_never_reaches_the_landing_page(self, client, db, user):
        """The section names companies, not people. An account's email address
        appearing on a public page would be a different and much worse
        thing."""
        await a_listed_company(db, user)
        await db.commit()

        body = (await client.get("/api/internal/landing")).text

        assert user.email not in body
