"""Validation of admin inputs, and the chart geometry.

Query parameters arrive from the same untrusted place as a form body, so they
get the same treatment. The chart geometry is arithmetic, and a chart whose
axis is silently wrong is worse than no chart, so it is asserted rather than
eyeballed.
"""

from __future__ import annotations

from datetime import date

import pytest
from pydantic import ValidationError

from app.charts import build_signup_chart
from app.core.types import Tier
from app.schemas import SignupChartQuery, SuspendForm, TierChangeForm, UserListQuery
from app.services.admin_service import SignupPoint
from tests.conftest import set_csrf, sign_in


class TestUserListQuery:
    def test_defaults_are_sane(self):
        query = UserListQuery()
        assert query.page == 1
        assert query.per_page == 25
        assert query.search_filter is None
        assert query.tier_filter is None

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

    def test_unknown_tier_filter_is_rejected(self):
        with pytest.raises(ValidationError):
            UserListQuery(tier="enterprise")

    def test_unknown_status_filter_is_rejected(self):
        with pytest.raises(ValidationError):
            UserListQuery(status="deleted")

    def test_blank_filters_mean_any(self):
        # The <select> has a valueless "Any" option, so blank must be legal.
        query = UserListQuery(tier="", status="", search="")
        assert query.tier_filter is None
        assert query.status_filter is None
        assert query.search_filter is None

    def test_valid_filters_are_converted(self):
        query = UserListQuery(tier="pro", status="suspended", search="a@b")
        assert query.tier_filter is Tier.PRO
        assert query.status_filter == "suspended"
        assert query.search_filter == "a@b"


class TestActionForms:
    def test_tier_change_requires_a_known_tier(self):
        assert TierChangeForm(tier="pro").tier is Tier.PRO
        with pytest.raises(ValidationError):
            TierChangeForm(tier="platinum")

    def test_note_is_length_bounded(self):
        with pytest.raises(ValidationError):
            TierChangeForm(tier="pro", note="x" * 501)

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
    """Bad parameters must degrade to defaults, not 500 or 422."""

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
        response = await admin_client.get(f"/admin/users{qs}")
        assert response.status_code == 200

    @pytest.mark.parametrize("qs", ["?days=0", "?days=99999", "?days=abc", "?days=-30"])
    async def test_hostile_chart_params_fall_back_to_defaults(self, admin_client, qs):
        response = await admin_client.get(f"/admin{qs}")
        assert response.status_code == 200

    async def test_a_missing_user_is_a_404_not_a_500(self, admin_client):
        assert (await admin_client.get("/admin/users/999999")).status_code == 404

    async def test_acting_on_a_missing_user_is_a_404(self, admin_client):
        csrf = set_csrf(admin_client)
        response = await admin_client.post("/admin/users/999999/suspend", data={"csrf_token": csrf})
        assert response.status_code == 404

    async def test_admin_mutations_require_csrf(self, admin_client, db, user):
        response = await admin_client.post(
            f"/admin/users/{user.id}/suspend", data={"reason": "no token"}
        )
        assert response.status_code == 403

        await db.refresh(user)
        assert user.is_suspended is False

    async def test_an_invalid_tier_value_re_renders_with_an_error(self, admin_client, db, user):
        csrf = set_csrf(admin_client)
        response = await admin_client.post(
            f"/admin/users/{user.id}/tier",
            data={"tier": "platinum", "csrf_token": csrf},
        )
        assert response.status_code == 400
        assert "valid plan" in response.text

        await db.refresh(user)
        assert user.tier is Tier.FREE

    async def test_a_rejected_action_re_renders_the_user_page(self, admin_client, db, user):
        # Same tier as current -> AdminActionError -> back to the page, not a 500.
        csrf = set_csrf(admin_client)
        response = await admin_client.post(
            f"/admin/users/{user.id}/tier", data={"tier": "free", "csrf_token": csrf}
        )
        assert response.status_code == 400
        assert "already on the free plan" in response.text


def points(counts: list[int], start=date(2024, 1, 1)) -> list[SignupPoint]:
    from datetime import timedelta

    running = 0
    result = []
    for offset, count in enumerate(counts):
        running += count
        result.append(
            SignupPoint(day=start + timedelta(days=offset), count=count, cumulative=running)
        )
    return result


class TestChartGeometry:
    def test_empty_data_is_flagged_rather_than_drawn(self):
        chart = build_signup_chart([])
        assert chart.empty is True
        assert chart.points == []
        assert chart.line_path == ""

    def test_points_stay_inside_the_canvas(self):
        chart = build_signup_chart(points([1, 5, 2, 9, 0, 3]))
        assert chart.empty is False
        for point in chart.points:
            assert 0 <= point.x <= chart.width
            assert 0 <= point.y <= chart.height

    def test_the_series_is_monotonic_downward_in_y_as_values_rise(self):
        # Cumulative data only rises, so y must only fall (SVG y grows downward).
        chart = build_signup_chart(points([1, 1, 1, 1]))
        ys = [p.y for p in chart.points]
        assert ys == sorted(ys, reverse=True)

    def test_zero_baseline_sits_at_the_bottom_of_the_plot(self):
        chart = build_signup_chart(points([0, 0, 0]))
        assert all(p.y == chart.baseline_y for p in chart.points)

    def test_a_single_point_does_not_divide_by_zero(self):
        chart = build_signup_chart(points([3]))
        assert len(chart.points) == 1
        assert chart.line_path.startswith("M ")

    def test_axis_maximum_is_rounded_to_a_readable_number(self):
        assert build_signup_chart(points([37])).y_max == 50
        assert build_signup_chart(points([1])).y_max == 5
        assert build_signup_chart(points([120])).y_max == 200

    def test_axis_maximum_is_never_below_the_data(self):
        for total in (1, 7, 37, 99, 100, 101, 999, 1001):
            chart = build_signup_chart(points([total]))
            assert chart.y_max >= total

    def test_area_path_closes_back_to_the_baseline(self):
        chart = build_signup_chart(points([1, 2, 3]))
        assert chart.area_path.startswith(chart.line_path)
        assert chart.area_path.endswith("Z")

    def test_hit_targets_do_not_overhang_the_axis(self):
        chart = build_signup_chart(points([1] * 10))
        for point in chart.points:
            assert point.hit_x >= 46 - 0.01
            assert point.hit_x + point.hit_width <= chart.width - 14 + 0.01

    def test_x_labels_are_sparse_enough_not_to_collide(self):
        chart = build_signup_chart(points([1] * 90))
        assert len(chart.x_labels) <= 3

    def test_grid_includes_zero_and_the_maximum(self):
        chart = build_signup_chart(points([10]))
        labels = [g.label for g in chart.grid]
        assert labels[0] == "0"
        assert labels[-1] == str(chart.y_max)
