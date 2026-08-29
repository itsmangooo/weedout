"""Validation of admin inputs.

Query parameters arrive from the same untrusted place as a form body, so they
get the same treatment: the Pydantic model owns coercion and the fallback, and
a hand-edited URL shows the default view rather than an error.

The chart geometry that used to be asserted here left with the server-rendered
panel — the signup chart is drawn in the browser now, and `app/charts.py` went
with it rather than staying as arithmetic nothing calls.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas import SignupChartQuery, SuspendForm, UserListQuery
from tests.conftest import set_csrf, sign_in


class TestUserListQuery:
    def test_defaults_are_sane(self):
        query = UserListQuery()
        assert query.page == 1
        assert query.per_page == 25
        assert query.search_filter is None

    @pytest.mark.parametrize("page", [0, -1, -999])
    def test_page_below_one_is_rejected(self, page):
        with pytest.raises(ValidationError):
            UserListQuery(page=page)

    @pytest.mark.parametrize("per_page", [0, 4, 101, 100_000])
    def test_per_page_is_bounded(self, per_page):
        # An unbounded per_page is a one-request denial of service against a
        # table with no ceiling on its size.
        with pytest.raises(ValidationError):
            UserListQuery(per_page=per_page)

    def test_overlong_search_is_rejected(self):
        with pytest.raises(ValidationError):
            UserListQuery(search="x" * 500)

    def test_control_characters_are_stripped_from_search(self):
        assert UserListQuery(search="  ab\x00cd \n").search == "abcd"

    def test_unknown_status_filter_is_rejected(self):
        with pytest.raises(ValidationError):
            UserListQuery(status="deleted")

    def test_blank_filters_mean_any(self):
        # The <select> has a valueless "Any" option, so blank must be legal.
        query = UserListQuery(status="", search="")
        assert query.status_filter is None
        assert query.search_filter is None

    def test_valid_filters_are_converted(self):
        query = UserListQuery(status="suspended", search="a@b")
        assert query.status_filter == "suspended"
        assert query.search_filter == "a@b"


class TestActionForms:
    def test_suspend_reason_is_optional(self):
        assert SuspendForm().reason == ""

    def test_suspend_reason_is_length_bounded(self):
        with pytest.raises(ValidationError):
            SuspendForm(reason="x" * 501)

    @pytest.mark.parametrize("days", [0, 6, 366, -1])
    def test_chart_range_is_bounded(self, days):
        with pytest.raises(ValidationError):
            SignupChartQuery(days=days)


class TestQueryParamsAtTheRoute:
    """Bad parameters must degrade to defaults, not 500 or 422.

    Aimed at /api/internal/admin, which is where the parameters are now read.
    The rule is unchanged: somebody hand-editing a URL should get the default
    view, not an error, so the schema owns coercion *and* the fallback.
    """

    @pytest.fixture
    async def admin_client(self, client, db):
        from app.models import User
        from app.security import hash_password

        admin = User(
            email="admin@example.com",
            password_hash=hash_password("correct-horse-battery"),
            is_admin=True,
        )
        db.add(admin)
        await db.flush()

        await sign_in(client, admin.email)
        return client

    @pytest.mark.parametrize(
        "qs",
        [
            "?page=-5",
            "?page=abc",
            "?per_page=100000",
            "?per_page=0",
            "?tier=enterprise",
            "?status=deleted",
            "?search=" + "x" * 500,
            "?page=1&per_page=99999&tier=%00",
        ],
    )
    async def test_hostile_user_list_params_fall_back_to_defaults(self, admin_client, qs):
        response = await admin_client.get(f"/api/internal/admin/users{qs}")
        assert response.status_code == 200

    @pytest.mark.parametrize("qs", ["?days=0", "?days=99999", "?days=abc", "?days=-30"])
    async def test_hostile_chart_params_fall_back_to_defaults(self, admin_client, qs):
        response = await admin_client.get(f"/api/internal/admin/overview{qs}")
        assert response.status_code == 200
        assert response.json()["data"]["chart_days"] == 30

    async def test_a_missing_user_is_a_404_not_a_500(self, admin_client):
        response = await admin_client.get("/api/internal/admin/users/999999")
        assert response.status_code == 404

    async def test_acting_on_a_missing_user_is_a_404(self, admin_client):
        response = await admin_client.post(
            "/api/internal/admin/users/999999/suspend",
            json={},
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        assert response.status_code == 404

    async def test_admin_mutations_require_csrf(self, admin_client, db, user):
        response = await admin_client.post(
            f"/api/internal/admin/users/{user.id}/suspend", json={"reason": "no token"}
        )
        assert response.status_code == 403

        await db.refresh(user)
        assert user.is_suspended is False

    async def test_retired_tier_mutation_endpoint_is_absent(self, admin_client, user):
        response = await admin_client.post(
            f"/api/internal/admin/users/{user.id}/tier",
            json={"tier": "pro"},
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        assert response.status_code == 404
