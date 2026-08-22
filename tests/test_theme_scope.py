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


class TestWhatTheServerStillDecides:
    """The theming itself moved to React with the pages.

    `FoundationLayout` pins the marketing palette and `AppShell` leaves it to
    the visitor; both are asserted in the frontend suite, which is where that
    markup now lives. What stays here is the part the server still owns.

    `is_public_surface` above is untouched and still tested — it is a pure
    function over a path, and it is what any future server-rendered page would
    consult.
    """

    async def test_the_landing_page_redirects_a_signed_in_visitor(self, auth_client):
        response = await auth_client.get("/", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

    async def test_the_error_page_still_renders(self, client):
        """The last server-rendered page. It has to work without the React
        bundle, because one of the things it reports is the bundle being
        unavailable."""
        response = await client.get("/docs/definitely-not-a-page", follow_redirects=False)

        assert response.status_code in {200, 404}
