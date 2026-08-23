"""`weedout auth`: a credential reaching a laptop without passing through one.

The thing this replaces is worse than it looks. "Create a key in Settings, copy
it, paste it into your terminal" puts a live credential through a clipboard, a
terminal scrollback, a shell history, and often a chat window where somebody
asked a colleague for help. Every one of those outlives the moment.

Most of what follows is about the ways this could be built wrong rather than
the happy path, because the happy path is three requests and the failure modes
are where credentials leak:

- `TestTheTwoSecretsDoDifferentJobs` — the short code a person reads must never
  be enough to collect a token.
- `TestApprovalIsAuthorised` — a stranger, and a cross-site page, must not be
  able to approve.
- `TestSingleUse` — one approval yields one credential, once.
- `TestTheTokenIsNotAProjectKey` — the two credential types cannot substitute
  for each other in either direction.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.models import CliAuthRequest, CliToken, utcnow
from app.security import hash_opaque_token
from app.services.cli_auth_service import (
    APPROVAL_WINDOW,
    CLI_TOKEN_PREFIX,
    MAX_TOKENS_PER_ACCOUNT,
    CliAuthError,
    approve,
    authenticate_cli_token,
    collect,
    deny,
    find_pending,
    generate_user_code,
    list_tokens,
    normalise_user_code,
    purge_expired_auth_requests,
    revoke_token,
    start_request,
)
from tests.conftest import set_csrf


async def a_request(db, **kwargs):
    started = await start_request(db, device_label="laptop", ip_address="203.0.113.9", **kwargs)
    await db.flush()
    return started


async def row_for(db, user_code: str) -> CliAuthRequest:
    from sqlalchemy import select

    return await db.scalar(select(CliAuthRequest).where(CliAuthRequest.user_code == user_code))


class TestTheCodeAPersonReads:
    def test_it_avoids_every_character_pair_that_gets_misread(self):
        """0/O, 1/I/L, 5/S and 2/Z all look alike at a glance in a sans-serif
        terminal font, and this code is copied between two windows by eye."""
        seen = set()
        for _ in range(400):
            seen.update(generate_user_code().replace("-", ""))

        assert not seen & set("01ILOSZ25"), f"ambiguous characters in use: {sorted(seen)}"

    def test_it_is_grouped_so_it_can_be_read_aloud(self):
        code = generate_user_code()

        assert len(code) == 9
        assert code[4] == "-"

    def test_two_codes_are_never_the_same(self):
        assert len({generate_user_code() for _ in range(200)}) == 200

    @pytest.mark.parametrize(
        "typed",
        ["HXKR-2FQP", "hxkr-2fqp", "hxkr2fqp", " HXKR 2FQP ", "HXKR" + chr(0x2013) + "2FQP"],
    )
    def test_the_ways_people_retype_it_all_work(self, typed):
        """Case, spaces and a missing hyphen are things a person does when
        copying eight characters between two windows. None should be a failed
        login."""
        assert normalise_user_code(typed) == "HXKR-2FQP"


class TestStarting:
    async def test_it_returns_a_code_a_secret_and_a_deadline(self, db):
        started = await a_request(db)

        assert len(started.user_code) == 9
        assert len(started.device_code) > 40
        assert started.expires_in == int(APPROVAL_WINDOW.total_seconds())
        assert started.interval > 0

    async def test_the_device_code_is_stored_hashed(self, db):
        """It is a credential. Only the hash is kept, like every other one
        here."""
        started = await a_request(db)
        row = await row_for(db, started.user_code)

        assert row.device_code_hash == hash_opaque_token(started.device_code)
        assert started.device_code not in row.device_code_hash

    async def test_the_request_starts_pending_and_belongs_to_nobody(self, db):
        started = await a_request(db)
        row = await row_for(db, started.user_code)

        assert row.is_pending is True
        assert row.approved_by_user_id is None

    async def test_the_device_label_and_address_are_recorded_for_the_page(self, db):
        """Both untrusted. They are there so a person can notice a request that
        is not theirs, not as a claim about anything."""
        started = await a_request(db)
        row = await row_for(db, started.user_code)

        assert row.device_label == "laptop"
        assert row.ip_address == "203.0.113.9"

    async def test_a_hostile_device_label_is_truncated_not_refused(self, db):
        started = await start_request(db, device_label="x" * 500)
        await db.flush()
        row = await row_for(db, started.user_code)

        assert len(row.device_label) == 120


class TestTheTwoSecretsDoDifferentJobs:
    """The property the whole design rests on.

    The user code is short because a person reads it, which makes it guessable.
    It may therefore only ever *confirm* a request that already exists. The
    device code is what actually collects the token.
    """

    async def test_knowing_the_user_code_does_not_collect_the_token(self, db, user):
        started = await a_request(db)
        row = await row_for(db, started.user_code)
        await approve(db, row, user)

        outcome = await collect(db, started.user_code)

        assert outcome.state == "expired"
        assert outcome.token is None

    async def test_only_the_device_code_collects_it(self, db, user):
        started = await a_request(db)
        row = await row_for(db, started.user_code)
        await approve(db, row, user)

        outcome = await collect(db, started.device_code)

        assert outcome.state == "approved"
        assert outcome.token is not None

    async def test_an_unknown_device_code_looks_like_an_expired_one(self, db):
        """Indistinguishable on purpose. A caller probing device codes learns
        nothing from the difference between "never existed" and "too late"."""
        assert (await collect(db, "not-a-real-device-code")).state == "expired"

    async def test_a_device_code_from_another_request_does_not_work(self, db, user):
        mine = await a_request(db)
        theirs = await a_request(db)
        await approve(db, await row_for(db, mine.user_code), user)

        assert (await collect(db, theirs.device_code)).state == "pending"


class TestFindingOneToApprove:
    async def test_a_pending_request_is_found_however_the_code_was_typed(self, db):
        started = await a_request(db)

        assert await find_pending(db, started.user_code.lower()) is not None
        assert await find_pending(db, started.user_code.replace("-", "")) is not None

    async def test_an_expired_one_is_not(self, db):
        started = await a_request(db)
        row = await row_for(db, started.user_code)
        row.expires_at = utcnow() - timedelta(seconds=1)
        await db.flush()

        assert await find_pending(db, started.user_code) is None

    async def test_an_already_approved_one_is_not(self, db, user):
        started = await a_request(db)
        await approve(db, await row_for(db, started.user_code), user)

        assert await find_pending(db, started.user_code) is None

    async def test_a_denied_one_is_not(self, db):
        started = await a_request(db)
        await deny(db, await row_for(db, started.user_code))

        assert await find_pending(db, started.user_code) is None

    async def test_an_empty_code_finds_nothing(self, db):
        assert await find_pending(db, "") is None
        assert await find_pending(db, "   ") is None


class TestSingleUse:
    async def test_a_device_code_collects_once(self, db, user):
        """A replayable device code would mint a second credential from one
        approval."""
        started = await a_request(db)
        await approve(db, await row_for(db, started.user_code), user)

        first = await collect(db, started.device_code)
        second = await collect(db, started.device_code)

        assert first.state == "approved"
        assert second.state == "expired"
        assert second.token is None

    async def test_a_request_is_approved_once(self, db, user, pro_user):
        started = await a_request(db)
        row = await row_for(db, started.user_code)
        await approve(db, row, user)

        with pytest.raises(CliAuthError):
            await approve(db, row, pro_user)

    async def test_an_approved_request_cannot_then_be_denied(self, db, user):
        started = await a_request(db)
        row = await row_for(db, started.user_code)
        await approve(db, row, user)

        with pytest.raises(CliAuthError):
            await deny(db, row)


class TestExpiry:
    async def test_an_approval_that_arrives_too_late_yields_nothing(self, db, user):
        started = await a_request(db)
        row = await row_for(db, started.user_code)
        await approve(db, row, user)
        row.expires_at = utcnow() - timedelta(seconds=1)
        await db.flush()

        assert (await collect(db, started.device_code)).state == "expired"

    async def test_a_denial_stops_the_terminal_straight_away(self, db):
        """Distinct from expiry so somebody refusing a request they did not
        make sees it die rather than watching it time out."""
        started = await a_request(db)
        await deny(db, await row_for(db, started.user_code))

        assert (await collect(db, started.device_code)).state == "denied"

    async def test_old_requests_are_purged(self, db):
        started = await a_request(db)
        row = await row_for(db, started.user_code)
        row.expires_at = utcnow() - timedelta(days=2)
        await db.flush()

        assert await purge_expired_auth_requests(db) == 1
        assert await row_for(db, started.user_code) is None

    async def test_a_live_request_is_not_purged(self, db):
        started = await a_request(db)

        assert await purge_expired_auth_requests(db) == 0
        assert await row_for(db, started.user_code) is not None


class TestTheToken:
    async def test_it_is_prefixed_so_a_leak_is_identifiable(self, db, user):
        """Distinct from `wo_` so a token found in a log is recognisable as an
        account credential rather than a project key -- by us and by a secret
        scanner."""
        started = await a_request(db)
        await approve(db, await row_for(db, started.user_code), user)

        outcome = await collect(db, started.device_code)

        assert outcome.token.startswith(CLI_TOKEN_PREFIX)

    async def test_only_the_hash_is_stored(self, db, user):
        from sqlalchemy import select

        started = await a_request(db)
        await approve(db, await row_for(db, started.user_code), user)
        outcome = await collect(db, started.device_code)

        row = await db.scalar(select(CliToken).where(CliToken.user_id == user.id))
        assert row.token_hash == hash_opaque_token(outcome.token)
        assert outcome.token not in row.token_hash

    async def test_it_authenticates(self, db, user):
        started = await a_request(db)
        await approve(db, await row_for(db, started.user_code), user)
        outcome = await collect(db, started.device_code)

        resolved = await authenticate_cli_token(db, outcome.token)

        assert resolved is not None
        assert resolved.user_id == user.id

    async def test_a_revoked_one_does_not(self, db, user):
        started = await a_request(db)
        await approve(db, await row_for(db, started.user_code), user)
        outcome = await collect(db, started.device_code)
        token_row = (await list_tokens(db, user.id))[0]

        assert await revoke_token(db, user.id, token_row.id) is True
        assert await authenticate_cli_token(db, outcome.token) is None

    async def test_an_expired_one_does_not(self, db, user):
        started = await a_request(db)
        await approve(db, await row_for(db, started.user_code), user)
        outcome = await collect(db, started.device_code)
        token_row = (await list_tokens(db, user.id))[0]
        token_row.expires_at = utcnow() - timedelta(seconds=1)
        await db.flush()

        assert await authenticate_cli_token(db, outcome.token) is None

    async def test_somebody_elses_token_cannot_be_revoked(self, db, user, pro_user):
        started = await a_request(db)
        await approve(db, await row_for(db, started.user_code), user)
        await collect(db, started.device_code)
        token_row = (await list_tokens(db, user.id))[0]

        assert await revoke_token(db, pro_user.id, token_row.id) is False
        assert token_row.revoked_at is None

    async def test_the_oldest_is_evicted_at_the_cap(self, db, user):
        """Evicting rather than refusing: a login that fails with "you have too
        many logins" is a login people work around."""
        for _ in range(MAX_TOKENS_PER_ACCOUNT + 2):
            started = await a_request(db)
            await approve(db, await row_for(db, started.user_code), user)
            await collect(db, started.device_code)

        assert len(await list_tokens(db, user.id)) == MAX_TOKENS_PER_ACCOUNT


class TestTheTokenIsNotAProjectKey:
    """Two credential types, kept apart at the type level rather than by a
    flag, so neither can be widened into the other by getting a boolean
    wrong."""

    async def test_a_project_key_does_not_authenticate_as_an_account_token(self, db, user):
        from tests.conftest import api_key_for
        from tests.test_api import make_target

        target = await make_target(db, user)
        key = await api_key_for(db, target, scope="manage")

        assert await authenticate_cli_token(db, key) is None

    async def test_an_account_token_does_not_authenticate_as_a_project_key(self, client, db, user):
        from tests.test_api import make_target

        await make_target(db, user)
        started = await a_request(db)
        await approve(db, await row_for(db, started.user_code), user)
        outcome = await collect(db, started.device_code)
        await db.commit()

        response = await client.get(
            "/api/v1/project", headers={"Authorization": f"Bearer {outcome.token}"}
        )

        assert response.status_code == 401

    async def test_the_lookup_refuses_the_wrong_prefix_before_the_database(self, db):
        """Cheap rejection, and it keeps project keys out of this code path
        entirely rather than relying on a hash miss."""
        assert await authenticate_cli_token(db, "wo_anything") is None
        assert await authenticate_cli_token(db, "") is None
        assert await authenticate_cli_token(db, None) is None


class TestThroughTheEndpoints:
    async def test_the_whole_flow(self, client, auth_client, db, user):
        """Start in one process, approve in a browser, collect in the first."""
        started = await client.post("/api/cli-auth/start", json={"device_label": "dev-laptop"})
        assert started.status_code == 200, started.text
        body = started.json()
        assert body["user_code"] in body["verification_url"]

        # Nothing yet.
        waiting = await client.post("/api/cli-auth/poll", json={"device_code": body["device_code"]})
        assert waiting.json()["state"] == "pending"

        # What the browser shows before anybody clicks.
        page = await auth_client.get(f"/api/internal/cli-auth/{body['user_code']}")
        assert page.status_code == 200, page.text
        assert page.json()["data"]["device_label"] == "dev-laptop"

        approved = await auth_client.post(
            "/api/internal/cli-auth/approve",
            json={"code": body["user_code"]},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )
        assert approved.status_code == 200, approved.text

        collected = await client.post(
            "/api/cli-auth/poll", json={"device_code": body["device_code"]}
        )
        assert collected.json()["state"] == "approved"
        assert collected.json()["token"].startswith(CLI_TOKEN_PREFIX)
        assert collected.json()["email"] == user.email

    async def test_the_token_is_never_cached(self, client):
        """It is a credential in a response body. Anything between here and the
        terminal must be told not to keep it."""
        started = await client.post("/api/cli-auth/start", json={})

        assert started.headers["cache-control"] == "no-store"

    async def test_a_stranger_cannot_see_a_pending_request(self, client, db):
        started = await a_request(db)
        await db.commit()

        response = await client.get(f"/api/internal/cli-auth/{started.user_code}")

        assert response.status_code == 401

    async def test_a_stranger_cannot_approve(self, client, db):
        started = await a_request(db)
        await db.commit()

        response = await client.post(
            "/api/internal/cli-auth/approve",
            json={"code": started.user_code},
            headers={"X-CSRF-Token": set_csrf(client)},
        )

        assert response.status_code == 401

    async def test_approval_needs_the_csrf_token(self, auth_client, db):
        """The control that matters most here. Without it, a page somebody
        visits while signed in could approve a login an attacker started and
        hand them a credential for the account."""
        started = await a_request(db)
        await db.commit()
        set_csrf(auth_client)

        response = await auth_client.post(
            "/api/internal/cli-auth/approve", json={"code": started.user_code}
        )

        assert response.status_code == 403

    async def test_an_unknown_code_is_a_404_that_says_what_to_do(self, auth_client):
        response = await auth_client.get("/api/internal/cli-auth/AAAA-BBBB")

        assert response.status_code == 404
        assert "again" in response.text

    async def test_denying_stops_the_poll(self, client, auth_client, db):
        started = await client.post("/api/cli-auth/start", json={})
        code = started.json()["user_code"]

        denied = await auth_client.post(
            "/api/internal/cli-auth/deny",
            json={"code": code},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )
        assert denied.status_code == 200, denied.text

        polled = await client.post(
            "/api/cli-auth/poll", json={"device_code": started.json()["device_code"]}
        )
        assert polled.json()["state"] == "denied"

    async def test_starting_is_rate_limited(self, client):
        """An unauthenticated endpoint that writes a row is one somebody will
        try to fill a table with."""
        from app.routes.cli_auth import START_LIMIT

        codes = set()
        for _ in range(START_LIMIT):
            response = await client.post("/api/cli-auth/start", json={})
            assert response.status_code == 200
            codes.add(response.json()["user_code"])

        blocked = await client.post("/api/cli-auth/start", json={})

        assert blocked.status_code == 429
        assert len(codes) == START_LIMIT, "the code space is not being swept by repeats"

    async def test_polling_is_rate_limited(self, client, monkeypatch):
        import app.routes.cli_auth as routes

        monkeypatch.setattr(routes, "POLL_LIMIT", 3)

        for _ in range(3):
            assert (
                await client.post("/api/cli-auth/poll", json={"device_code": "x"})
            ).status_code == 200

        blocked = await client.post("/api/cli-auth/poll", json={"device_code": "x"})

        assert blocked.status_code == 429


class TestTheMachineList:
    """A login you can grant and cannot see afterwards is a login you cannot
    take back."""

    async def test_it_names_the_machines_that_are_signed_in(self, auth_client, db, user):
        started = await start_request(db, device_label="dev-laptop")
        await db.flush()
        await approve(db, await row_for(db, started.user_code), user)
        await collect(db, started.device_code)
        await db.commit()

        response = await auth_client.get("/api/internal/cli-tokens")

        assert response.status_code == 200
        rows = response.json()["data"]
        assert [row["device_label"] for row in rows] == ["dev-laptop"]

    async def test_the_token_itself_is_never_in_the_list(self, auth_client, db, user):
        started = await start_request(db, device_label="dev-laptop")
        await db.flush()
        await approve(db, await row_for(db, started.user_code), user)
        outcome = await collect(db, started.device_code)
        await db.commit()

        response = await auth_client.get("/api/internal/cli-tokens")

        assert outcome.token not in response.text

    async def test_revoking_one_takes_effect(self, auth_client, db, user):
        started = await start_request(db, device_label="old-laptop")
        await db.flush()
        await approve(db, await row_for(db, started.user_code), user)
        outcome = await collect(db, started.device_code)
        await db.commit()

        listed = (await auth_client.get("/api/internal/cli-tokens")).json()["data"]
        revoked = await auth_client.post(
            f"/api/internal/cli-tokens/{listed[0]['id']}/revoke",
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )

        assert revoked.status_code == 200
        assert await authenticate_cli_token(db, outcome.token) is None

    async def test_somebody_elses_machine_is_a_404(self, auth_client, db, pro_user):
        started = await start_request(db, device_label="theirs")
        await db.flush()
        await approve(db, await row_for(db, started.user_code), pro_user)
        await collect(db, started.device_code)
        theirs = (await list_tokens(db, pro_user.id))[0]
        await db.commit()

        response = await auth_client.post(
            f"/api/internal/cli-tokens/{theirs.id}/revoke",
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )

        assert response.status_code == 404
