"""Session management, and the theme preference surviving a reload.

Revocation is the part worth testing hardest: the whole reason this app keeps
sessions in the database rather than in a self-contained token is that
revocation can take effect on the next request, and a test that only checks the
row was marked would not notice if the request path stopped consulting it.
"""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import select

from app.models import Session
from app.services.auth_service import (
    active_sessions,
    create_session,
    revoke_session_by_id,
    revoke_sessions_except,
)
from app.templating import device_name
from tests.conftest import set_csrf

STATIC = Path(__file__).resolve().parents[1] / "app" / "static"


class TestSessionListing:
    async def test_lists_only_sessions_that_could_still_be_used(self, db, user):
        live = await create_session(db, user, "Mozilla/5.0 Chrome/139", "203.0.113.7")
        stale = await create_session(db, user, "curl/8.4.0", "203.0.113.8")
        await db.flush()

        row = await db.scalar(
            select(Session).where(Session.user_id == user.id).order_by(Session.id.desc())
        )
        assert row is not None
        await revoke_session_by_id(db, user, row.id)
        await db.flush()

        listed = await active_sessions(db, user)
        assert len(listed) == 1
        assert all(s.revoked_at is None for s in listed)
        assert live and stale  # both were created; one was then revoked

    async def test_cannot_revoke_another_users_session(self, db, user, pro_user):
        await create_session(db, pro_user, "Mozilla/5.0 Chrome/139", None)
        await db.flush()

        theirs = await db.scalar(select(Session).where(Session.user_id == pro_user.id))
        assert theirs is not None

        # Scoped by owner, so a guessed id is a miss rather than someone else
        # being signed out.
        assert await revoke_session_by_id(db, user, theirs.id) is None
        await db.refresh(theirs)
        assert theirs.revoked_at is None

    async def test_revoke_others_keeps_the_one_you_are_using(self, db, user):
        keep = await create_session(db, user, "Mozilla/5.0 Chrome/139", None)
        await create_session(db, user, "Mozilla/5.0 Firefox/130", None)
        await create_session(db, user, "curl/8.4.0", None)
        await db.flush()

        from app.security import hash_session_token

        ended = await revoke_sessions_except(db, user, hash_session_token(keep))
        await db.flush()

        assert ended == 2
        remaining = await active_sessions(db, user)
        assert len(remaining) == 1
        assert remaining[0].token_hash == hash_session_token(keep)


class TestRevocationTakesEffect:
    async def test_a_revoked_session_stops_working_on_the_next_request(self, auth_client, db, user):
        # The signed-in client works.
        assert (await auth_client.get("/api/internal/dashboard")).status_code == 200

        listed = await active_sessions(db, user)
        assert listed, "the fixture should have produced a session"
        for row in listed:
            await revoke_session_by_id(db, user, row.id)
        await db.commit()

        # No new request, no logout, no cookie change — the cookie is simply no
        # longer honoured, which is the property DB-backed sessions exist for.
        after = await auth_client.get("/api/internal/dashboard")
        assert after.status_code == 401
        assert after.json()["error"]["code"] == "SESSION_EXPIRED"

    async def test_signing_out_everywhere_else_keeps_this_session(self, auth_client, db, user):
        other = await create_session(db, user, "curl/8.4.0", None)
        await db.commit()
        assert len(await active_sessions(db, user)) == 2

        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/api/internal/settings/sessions/revoke-others",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200

        remaining = await active_sessions(db, user)
        assert len(remaining) == 1
        # The one that was ended is the other one, and this client still works.
        from app.security import hash_session_token

        assert remaining[0].token_hash != hash_session_token(other)
        assert (await auth_client.get("/api/internal/dashboard")).status_code == 200


class TestDeviceNaming:
    def test_names_the_browser_and_platform_without_overclaiming(self):
        assert (
            device_name(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
            )
            == "Chrome on Windows"
        )
        # Edge and Opera both carry "chrome"; Chrome carries "safari".
        assert "Edge" in device_name("Mozilla/5.0 Chrome/139 Safari/537.36 Edg/139.0")
        assert (
            device_name(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
            )
            == "Safari on macOS"
        )
        assert device_name("curl/8.4.0") == "curl"
        assert device_name(None) == "Unknown device"
        assert device_name("") == "Unknown device"


class TestThemePersistence:
    """The theme is a client-side preference, so these assert on the contract
    the browser actually relies on rather than on a server round trip."""

    def test_the_boot_script_runs_before_the_stylesheet(self):
        base = (Path(__file__).resolve().parents[1] / "app" / "templates" / "base.html").read_text(
            encoding="utf-8"
        )

        script_at = base.index("js/theme.js")
        stylesheet_at = base.index("css/weedout.css")
        # Ordering is the whole point: applying a saved theme after the
        # stylesheet has painted shows a frame of the wrong one.
        assert script_at < stylesheet_at

        # And it must not be deferred, or it runs after first paint anyway.
        line = next(row for row in base.splitlines() if "js/theme.js" in row)
        assert "defer" not in line
        assert "async" not in line

    def test_the_boot_script_is_a_file_not_an_inline_block(self):
        # `script-src 'self'` has no room for an inline block, and weakening it
        # for a theme would be a poor trade.
        base = (Path(__file__).resolve().parents[1] / "app" / "templates" / "base.html").read_text(
            encoding="utf-8"
        )
        inline = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", base)
        assert inline == [], f"inline <script> would be blocked by the CSP: {inline}"

    def test_the_saved_choice_is_read_and_applied_to_the_root(self):
        boot = (STATIC / "js" / "theme.js").read_text(encoding="utf-8")
        assert 'saved("weedout:theme")' in boot
        assert 'setAttribute("data-theme"' in boot
        # Only the two explicit values are honoured; anything else falls
        # through to the system preference.
        assert '"light"' in boot and '"dark"' in boot

    def test_the_dark_preset_is_read_at_boot_too(self):
        # The preset has to be applied in the same pre-paint pass as the theme,
        # or someone on Midnight sees a frame of Carbon on every navigation.
        boot = (STATIC / "js" / "theme.js").read_text(encoding="utf-8")
        assert 'saved("weedout:dark")' in boot
        assert 'setAttribute("data-dark"' in boot
        assert '"midnight"' in boot and '"ash"' in boot

    def test_the_switcher_persists_and_can_return_to_system(self):
        app_js = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
        assert "store(THEME_KEY, choice)" in app_js
        # "System" has to clear the key rather than store a third value, or the
        # stylesheet's prefers-color-scheme block can never win again.
        assert "store(THEME_KEY, null)" in app_js
        assert 'removeAttribute("data-theme")' in app_js

    def test_the_preset_persists_and_carbon_is_the_absence_of_a_value(self):
        app_js = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
        assert "store(DARK_KEY, choice)" in app_js
        # Carbon is what :root already is. Storing it as a value would be a
        # second source of truth that can disagree with the stylesheet.
        assert "store(DARK_KEY, null)" in app_js
        assert 'removeAttribute("data-dark")' in app_js
        assert 'DARK_PRESETS = ["carbon", "midnight", "ash"]' in app_js

    def test_theme_and_preset_are_stored_under_separate_keys(self):
        # They answer different questions: whether you want dark at all, and
        # which dark. Collapsing them would mean choosing a preset silently
        # pins you out of "follow the system".
        app_js = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
        assert 'THEME_KEY = "weedout:theme"' in app_js
        assert 'DARK_KEY = "weedout:dark"' in app_js

    def test_both_themes_are_fully_defined_in_the_stylesheet(self):
        css = (STATIC / "css" / "weedout.css").read_text(encoding="utf-8")
        assert ':root[data-theme="light"] {' in css
        assert "prefers-color-scheme: light" in css
        # An explicit choice must beat the media query in both directions.
        assert ':root:not([data-theme="dark"]):not([data-theme="light"])' in css

    def test_every_dark_preset_defines_the_whole_elevation_stack(self):
        css = (STATIC / "css" / "weedout.css").read_text(encoding="utf-8")
        for preset in ("midnight", "ash"):
            block_start = css.index(f':root[data-theme="dark"][data-dark="{preset}"] {{')
            block = css[block_start : css.index("}", block_start)]
            for level in range(5):
                assert f"--level-{level}:" in block, f"{preset} is missing --level-{level}"

    def test_presets_do_not_touch_the_accent_or_the_severity_set(self):
        # A preset is a change of room lighting. If it could move the severity
        # colours, "critical" would mean something different depending on which
        # dark you happened to pick.
        css = (STATIC / "css" / "weedout.css").read_text(encoding="utf-8")
        for preset in ("midnight", "ash"):
            block_start = css.index(f':root[data-theme="dark"][data-dark="{preset}"] {{')
            block = css[block_start : css.index("}", block_start)]
            for reserved in (
                "--accent:",
                "--exploited:",
                "--critical:",
                "--high:",
                "--medium:",
                "--low:",
                "--digest:",
            ):
                assert reserved not in block, f"{preset} overrides {reserved}"

    def test_a_dark_preset_cannot_apply_while_light_is_active(self):
        # Scoped to dark rather than merely ordered before light. Relying on
        # source order at equal specificity is correct but fragile — it breaks
        # silently the first time a rule is moved or gains a class — and the
        # failure mode is somebody's chosen preset bleeding into light mode.
        css = (STATIC / "css" / "weedout.css").read_text(encoding="utf-8")
        for preset in ("midnight", "ash"):
            assert f':root[data-dark="{preset}"] {{' not in css, (
                f"{preset} is not scoped to dark and can leak into light mode"
            )
            assert f':root[data-theme="dark"][data-dark="{preset}"] {{' in css
            # And the system-dark path, where no theme has been chosen at all.
            assert f':root:not([data-theme="light"])[data-dark="{preset}"] {{' in css

    def test_storage_failure_does_not_break_the_page(self):
        # Private mode and blocked cookies both throw on access.
        boot = (STATIC / "js" / "theme.js").read_text(encoding="utf-8")
        assert "catch" in boot
        app_js = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
        assert app_js.count("catch (err)") >= 3
