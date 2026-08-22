"""Where a theme preference applies, and where it does not.

A landing page that changes character depending on who is looking at it cannot
be designed, and a signed-in visitor's theme is a preference about the tool
they work in -- not a request to restyle the page they are about to send to a
colleague.

So: marketing pages render one deliberate look for everybody, and the
application honours the preference. The seam is `is_public_surface`, and the
mechanism is `data-surface="public"` on `<html>`, which `theme.js` reads before
the first paint.
"""

from __future__ import annotations

import pytest

from app.templating import is_public_surface

#: The seam itself, which is a pure function over a path and still covers
#: every route whether the server renders it or React does.
PUBLIC = ("/", "/pricing", "/cli")
APP = (
    "/dashboard",
    "/settings",
    "/alerts",
    "/targets/new",
    "/docs",
    "/contact",
)

#: The subset the server still renders. A React shell carries no server-pinned
#: palette — the React layouts set data-theme themselves — so asserting on the
#: HTML for those paths would be asserting on the shell, not on the seam.
RENDERED_PUBLIC = ("/pricing", "/cli")
RENDERED_APP = ("/docs", "/contact")


class TestTheSeam:
    @pytest.mark.parametrize("path", PUBLIC)
    def test_marketing_pages_are_public(self, path):
        assert is_public_surface(path)

    @pytest.mark.parametrize("path", APP)
    def test_application_pages_are_not(self, path):
        assert not is_public_surface(path)

    def test_docs_is_deliberately_an_application_surface(self):
        """Not an oversight.

        A signed-in reader gets the sidebar and its theme switcher on /docs, so
        pinning the palette there would leave a visible control that does
        nothing -- and long-form reading is where a light-mode preference is
        most worth honouring.
        """
        assert not is_public_surface("/docs")
        assert not is_public_surface("/docs/getting-started")

    def test_a_lookalike_path_is_not_swept_in(self):
        """Matched exactly, so a later /pricing-details does not inherit this."""
        assert not is_public_surface("/pricing-details")
        assert not is_public_surface("/climate")


class TestWhatIsRendered:
    @pytest.mark.parametrize("path", RENDERED_PUBLIC)
    async def test_a_marketing_page_pins_its_palette(self, client, path):
        body = (await client.get(path)).text
        assert 'data-surface="public"' in body
        assert 'data-theme="dark"' in body

    #: `/` sends a signed-in visitor to their dashboard, so it never renders
    #: for them and the question does not arise there.
    PUBLIC_REACHABLE_WHEN_SIGNED_IN = ("/pricing", "/cli")

    @pytest.mark.parametrize("path", PUBLIC_REACHABLE_WHEN_SIGNED_IN)
    async def test_it_pins_it_for_a_signed_in_visitor_too(self, auth_client, path):
        """The point of the whole change.

        Somebody with light mode saved still gets the designed look on a page
        they might screenshot or share.
        """
        body = (await auth_client.get(path)).text
        assert 'data-surface="public"' in body
        assert 'data-theme="dark"' in body

    async def test_the_landing_page_redirects_a_signed_in_visitor(self, auth_client):
        """Which is why it is absent from the list above, rather than an
        oversight in it."""
        response = await auth_client.get("/", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

    @pytest.mark.parametrize("path", PUBLIC_REACHABLE_WHEN_SIGNED_IN)
    async def test_the_theme_switcher_is_not_offered_where_it_does_nothing(self, auth_client, path):
        """A signed-in visitor gets the sidebar on these pages. A control that
        is visible and inert is worse than no control."""
        body = (await auth_client.get(path)).text
        assert "data-theme-set" not in body

    async def test_the_application_leaves_the_palette_to_the_visitor(self, auth_client):
        body = (await auth_client.get("/docs")).text
        assert 'data-surface="public"' not in body
        # No server-pinned theme: theme.js applies the saved preference before
        # the first paint.
        assert 'data-theme="dark"' not in body
        # And the control is there to change it with.
        assert "data-theme-set" in body

    async def test_docs_still_honours_the_preference(self, auth_client, db):
        from app.services.docs_service import seed_starter_pages

        await seed_starter_pages(db)
        body = (await auth_client.get("/docs")).text
        assert 'data-surface="public"' not in body
        assert "data-theme-set" in body

    @pytest.mark.parametrize("path", RENDERED_PUBLIC)
    async def test_colour_scheme_advertises_only_what_is_offered(self, client, path):
        """`color-scheme: dark light` on a page that only renders dark makes the
        browser paint form controls and scrollbars for a mode it will not get."""
        body = (await client.get(path)).text
        assert '<meta name="color-scheme" content="dark">' in body


class TestTheBootScript:
    def test_it_bails_out_on_a_public_surface(self):
        """Belt and braces: the server pins the attribute, and the script that
        would otherwise overwrite it returns before it can."""
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[1] / "app" / "static" / "js" / "theme.js"
        ).read_text(encoding="utf-8")

        assert 'root.getAttribute("data-surface") === "public"' in source
        # Before it reads storage, or it would apply the preference and then
        # bail having already done the damage.
        assert source.index("data-surface") < source.index("localStorage")
