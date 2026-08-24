"""Documentation: public reads, admin CRUD, and the boundary between them.

The access-control tests follow the same pattern as `tests/test_admin_access.py`
— a non-admin must never reach an admin docs route, and must never see a draft.
The second half of that matters as much as the first: "unpublished" is only
meaningful if there is no way to read one from outside.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import pytest
from sqlalchemy import select

from app.markdown import extract_summary, render_markdown, slugify
from app.models import DocPage, User
from app.security import hash_password
from app.services.docs_service import (
    SlugTaken,
    create_page,
    get_published,
    list_public,
    seed_starter_pages,
    update_page,
)
from tests.conftest import set_csrf, sign_in


@pytest.fixture
async def admin(db) -> User:
    record = User(
        email="admin@example.com",
        password_hash=hash_password("correct-horse-battery"),
        is_admin=True,
    )
    db.add(record)
    await db.flush()
    return record


@pytest.fixture
async def admin_client(client, admin):
    response = await sign_in(client, admin.email)
    assert response.status_code == 200
    return client


async def make_page(db, slug="a-page", title="A page", published=True, **kwargs) -> DocPage:
    page = DocPage(
        slug=slug,
        title=title,
        summary=kwargs.pop("summary", ""),
        content=kwargs.pop("content", "# Hello\n\nSome body text."),
        published=published,
        position=kwargs.pop("position", 0),
    )
    db.add(page)
    await db.flush()
    return page


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


class TestMarkdown:
    def test_renders_basic_structure(self):
        html = render_markdown("# Title\n\nA paragraph with **bold**.")
        assert "<h1>Title</h1>" in html
        assert "<strong>bold</strong>" in html

    def test_raw_html_is_escaped_not_executed(self):
        # The setting that matters. Docs are admin-authored, but a CMS that
        # renders arbitrary HTML turns one compromised admin account, or one
        # careless paste, into stored XSS across the public site.
        html = render_markdown('<script>alert("xss")</script>\n\nAfter.')
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_inline_html_attributes_are_escaped(self):
        html = render_markdown('Text <img src=x onerror="alert(1)"> more')
        assert "onerror" not in html or "&lt;img" in html
        assert "<img" not in html

    def test_javascript_urls_are_not_linkified(self):
        html = render_markdown("[click](javascript:alert(1))")
        assert 'href="javascript:' not in html

    def test_external_links_get_noopener(self):
        html = render_markdown("[docs](https://example.com/x)")
        assert 'rel="noopener noreferrer"' in html
        assert 'target="_blank"' in html

    def test_internal_links_stay_in_place(self):
        html = render_markdown("[other page](/docs/other)")
        assert 'target="_blank"' not in html

    def test_tables_and_code_blocks_render(self):
        html = render_markdown("| a | b |\n|---|---|\n| 1 | 2 |\n\n```\ncode\n```")
        assert "<table>" in html
        assert "<pre><code>" in html

    def test_empty_input_renders_nothing(self):
        assert render_markdown("") == ""
        assert render_markdown("   \n  ") == ""


class TestSlugify:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("Getting Started", "getting-started"),
            ("  Spaces  ", "spaces"),
            ("Sévèrity & Tiers!", "s-v-rity-tiers"),
            ("already-a-slug", "already-a-slug"),
            ("../../etc/passwd", "etc-passwd"),
            ("!!!", "page"),
            ("", "page"),
        ],
    )
    def test_produces_url_safe_segments(self, value, expected):
        assert slugify(value) == expected

    def test_result_never_needs_url_escaping(self):
        for raw in ("a b/c?d#e", "%2e%2e", "a\x00b", "a\nb"):
            slug = slugify(raw)
            assert all(ch.isalnum() or ch == "-" for ch in slug)


class TestExtractSummary:
    def test_takes_the_first_prose_paragraph(self):
        assert extract_summary("# Title\n\nThe first sentence here.") == "The first sentence here."

    def test_skips_headings_lists_and_code(self):
        source = "# Title\n\n- a list\n\n```\ncode\n```\n\nReal prose."
        assert extract_summary(source) == "Real prose."

    def test_truncates_long_paragraphs(self):
        assert extract_summary("x " * 300, limit=50).endswith("…")

    def test_returns_empty_when_there_is_no_prose(self):
        assert extract_summary("# Only a heading") == ""


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------


class TestPublicDocs:
    async def test_index_lists_published_pages(self, client, db):
        await make_page(db, slug="one", title="One")
        await make_page(db, slug="two", title="Two")

        response = await client.get("/api/internal/docs")
        assert response.status_code == 200
        titles = [page["title"] for page in response.json()["data"]["pages"]]
        assert titles == ["One", "Two"]

    async def test_index_hides_drafts(self, client, db):
        await make_page(db, slug="live", title="Live One")
        await make_page(db, slug="draft", title="Secret Draft", published=False)

        response = await client.get("/api/internal/docs")
        titles = [page["title"] for page in response.json()["data"]["pages"]]
        assert "Live One" in titles
        assert "Secret Draft" not in titles
        assert "Secret Draft" not in response.text

    async def test_a_published_page_renders_its_markdown(self, client, db):
        await make_page(db, slug="guide", title="Guide", content="## Section\n\nBody here.")

        response = await client.get("/api/internal/docs/guide")
        assert response.status_code == 200
        body = response.json()["data"]["body_html"]
        # Still rendered on the server, so the browser is not shipped a
        # markdown parser to redo work already done.
        assert "<h2>Section</h2>" in body
        assert "Body here." in body

    async def test_a_draft_is_a_404_for_anonymous_visitors(self, client, db):
        await make_page(db, slug="draft", title="Draft", published=False)
        response = await client.get("/api/internal/docs/draft")
        assert response.status_code == 404

    async def test_a_draft_is_a_404_for_signed_in_non_admins(self, auth_client, db):
        await make_page(db, slug="draft", title="Draft", published=False)
        assert (await auth_client.get("/api/internal/docs/draft")).status_code == 404

    async def test_a_draft_is_also_hidden_from_the_admin_public_view(self, admin_client, db):
        # Drafts are edited through the admin panel, not previewed at the public
        # URL — so "unpublished" means the same thing to everyone.
        await make_page(db, slug="draft", title="Draft", published=False)
        assert (await admin_client.get("/api/internal/docs/draft")).status_code == 404

    async def test_an_unknown_slug_is_a_404(self, client):
        assert (await client.get("/api/internal/docs/nothing-here")).status_code == 404

    async def test_docs_are_reachable_without_signing_in(self, client, db):
        await make_page(db)
        assert (await client.get("/api/internal/docs")).status_code == 200

    async def test_pages_appear_in_position_order(self, client, db):
        await make_page(db, slug="second", title="Second", position=2)
        await make_page(db, slug="first", title="First", position=1)

        pages = (await client.get("/api/internal/docs")).json()["data"]["pages"]
        titles = [page["title"] for page in pages]
        assert titles.index("First") < titles.index("Second")

    async def test_the_docs_are_reachable_from_the_application(self, client):
        """The React header links here; that markup is covered by the frontend
        suite. What this asserts is the half that has to hold server-side —
        the address serves a page rather than a 404."""
        assert (await client.get("/docs")).status_code == 200


# ---------------------------------------------------------------------------
# Admin access control — the point of this file
# ---------------------------------------------------------------------------


#: The doc CMS moved to /api/internal/admin/docs when the panel became React.
#: The shell at /admin/docs is served to anyone and holds nothing; these are
#: the paths that hold the pages.
ADMIN_DOC_ROUTES = [
    ("GET", "/api/internal/admin/docs"),
    ("POST", "/api/internal/admin/docs"),
    ("GET", "/api/internal/admin/docs/{id}"),
    ("POST", "/api/internal/admin/docs/{id}"),
    ("POST", "/api/internal/admin/docs/{id}/delete"),
]


def doc_payload(**overrides) -> dict:
    return {"title": "", "slug": "", "summary": "", "content": "", "published": False, **overrides}


class TestAdminDocsAccessControl:
    async def test_no_admin_docs_route_is_reachable_by_a_non_admin(self, auth_client, db):
        page = await make_page(db)
        csrf = set_csrf(auth_client)

        failures = []
        for method, template in ADMIN_DOC_ROUTES:
            url = template.replace("{id}", str(page.id))
            if method == "GET":
                response = await auth_client.get(url)
            else:
                response = await auth_client.post(
                    url, json=doc_payload(), headers={"X-CSRF-Token": csrf}
                )
            if response.status_code != 403:
                failures.append(f"{method} {url} -> {response.status_code}")

        assert not failures, "non-admin reached: " + "; ".join(failures)

    async def test_anonymous_callers_get_401(self, client):
        """401 rather than a redirect: this is a JSON endpoint, and a `fetch`
        cannot do anything useful with the login page's HTML."""
        response = await client.get("/api/internal/admin/docs")
        assert response.status_code == 401

    async def test_a_non_admin_cannot_create_a_page(self, auth_client, db):
        csrf = set_csrf(auth_client)
        response = await auth_client.post(
            "/api/internal/admin/docs",
            json=doc_payload(title="Sneaky", content="x"),
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 403
        assert await db.scalar(select(DocPage).where(DocPage.title == "Sneaky")) is None

    async def test_a_non_admin_cannot_edit_a_page(self, auth_client, db):
        page = await make_page(db, title="Original")
        csrf = set_csrf(auth_client)

        response = await auth_client.post(
            f"/api/internal/admin/docs/{page.id}",
            json=doc_payload(title="Hijacked", slug=page.slug, content="x"),
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 403

        await db.refresh(page)
        assert page.title == "Original"

    async def test_a_non_admin_cannot_delete_a_page(self, auth_client, db):
        page = await make_page(db)
        csrf = set_csrf(auth_client)

        response = await auth_client.post(
            f"/api/internal/admin/docs/{page.id}/delete",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 403
        assert await db.get(DocPage, page.id) is not None

    async def test_a_non_admin_sees_no_admin_link_in_the_docs_nav(self, auth_client, db):
        await make_page(db)
        response = await auth_client.get("/docs")
        assert "/admin/docs" not in response.text


# ---------------------------------------------------------------------------
# Admin CRUD
# ---------------------------------------------------------------------------


class TestAdminDocsCrud:
    async def test_creates_a_page_and_derives_the_slug(self, admin_client, db):
        response = await admin_client.post(
            "/api/internal/admin/docs",
            json=doc_payload(title="Getting Started Here", content="# Hi\n\nBody.", published=True),
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        assert response.status_code == 200

        page = await db.scalar(select(DocPage).where(DocPage.title == "Getting Started Here"))
        assert page is not None
        assert page.slug == "getting-started-here"
        assert page.published is True

    async def test_a_new_page_defaults_to_draft(self, admin_client, db):
        await admin_client.post(
            "/api/internal/admin/docs",
            json=doc_payload(title="Quiet", content="x"),
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        page = await db.scalar(select(DocPage).where(DocPage.title == "Quiet"))
        assert page.published is False

    async def test_edits_an_existing_page(self, admin_client, db):
        page = await make_page(db, slug="old", title="Old")

        response = await admin_client.post(
            f"/api/internal/admin/docs/{page.id}",
            json=doc_payload(
                title="New Title", slug="new-slug", content="Updated body.", published=True
            ),
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        assert response.status_code == 200

        await db.refresh(page)
        assert page.title == "New Title"
        assert page.slug == "new-slug"
        assert page.content == "Updated body."

    async def test_unpublishing_takes_a_page_offline(self, admin_client, client, db):
        page = await make_page(db, slug="live", title="Live")
        assert (await client.get("/api/internal/docs/live")).status_code == 200

        await admin_client.post(
            f"/api/internal/admin/docs/{page.id}",
            json=doc_payload(title="Live", slug="live", content="x", published=False),
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        assert (await client.get("/api/internal/docs/live")).status_code == 404

    async def test_deletes_a_page(self, admin_client, db):
        page = await make_page(db)

        response = await admin_client.post(
            f"/api/internal/admin/docs/{page.id}/delete",
            json={},
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        assert response.status_code == 200
        assert await db.get(DocPage, page.id) is None

    async def test_a_duplicate_slug_is_rejected(self, admin_client, db):
        await make_page(db, slug="taken", title="Taken")

        response = await admin_client.post(
            "/api/internal/admin/docs",
            json=doc_payload(title="Another", slug="taken", content="x"),
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        assert response.status_code == 400
        assert "already exists" in response.json()["error"]["message"]

    async def test_a_page_can_keep_its_own_slug_on_edit(self, admin_client, db):
        page = await make_page(db, slug="keep", title="Keep")

        response = await admin_client.post(
            f"/api/internal/admin/docs/{page.id}",
            json=doc_payload(title="Keep", slug="keep", content="y"),
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        assert response.status_code == 200

    async def test_a_missing_title_is_rejected(self, admin_client, db):
        response = await admin_client.post(
            "/api/internal/admin/docs",
            json=doc_payload(title="", content="x"),
            headers={"X-CSRF-Token": set_csrf(admin_client)},
        )
        assert response.status_code == 400
        assert (await db.scalars(select(DocPage))).all() == []

    async def test_crud_requires_csrf(self, admin_client, db):
        response = await admin_client.post(
            "/api/internal/admin/docs", json=doc_payload(title="No token")
        )
        assert response.status_code == 403
        assert await db.scalar(select(DocPage).where(DocPage.title == "No token")) is None

    async def test_editing_a_missing_page_is_a_404(self, admin_client):
        assert (await admin_client.get("/api/internal/admin/docs/999999")).status_code == 404

    async def test_the_admin_list_shows_drafts(self, admin_client, db):
        await make_page(db, slug="draft", title="Hidden Draft", published=False)

        pages = (await admin_client.get("/api/internal/admin/docs")).json()["data"]["pages"]
        draft = next(page for page in pages if page["title"] == "Hidden Draft")
        assert draft["published"] is False


# ---------------------------------------------------------------------------
# Service layer
# ---------------------------------------------------------------------------


class TestDocsService:
    async def test_list_public_never_returns_drafts(self, db):
        await make_page(db, slug="a", published=True)
        await make_page(db, slug="b", published=False)
        assert [p.slug for p in await list_public(db)] == ["a"]

    async def test_get_published_never_returns_a_draft(self, db):
        await make_page(db, slug="b", published=False)
        assert await get_published(db, "b") is None
        assert await get_published(db, "") is None

    async def test_creating_derives_a_summary_when_absent(self, db):
        page = await create_page(db, title="T", content="# Head\n\nThe summary sentence.")
        assert page.summary == "The summary sentence."

    async def test_an_explicit_summary_is_never_overwritten(self, db):
        page = await create_page(db, title="T", content="Body.", summary="Mine")
        assert page.summary == "Mine"

    async def test_new_pages_go_to_the_end_of_the_order(self, db):
        first = await create_page(db, title="First")
        second = await create_page(db, title="Second")
        assert second.position > first.position

    async def test_duplicate_slugs_raise(self, db):
        await create_page(db, title="One", slug="dupe")
        with pytest.raises(SlugTaken):
            await create_page(db, title="Two", slug="dupe")

    async def test_update_rejects_a_slug_owned_by_another_page(self, db):
        await create_page(db, title="One", slug="one")
        two = await create_page(db, title="Two", slug="two")

        with pytest.raises(SlugTaken):
            await update_page(db, two, title="Two", slug="one", content="x")


class TestStarterSeed:
    async def test_creates_the_starter_pages(self, db):
        """Counts derived from the source, not written out.

        These were hardcoded to four and broke the day a fifth page was added,
        which teaches the next person to edit the number rather than read the
        failure. What is worth asserting is that seeding produces exactly the
        set that is declared — however many that is.
        """
        from app.services.docs_service import STARTER_PAGES

        created = await seed_starter_pages(db)
        assert created == len(STARTER_PAGES)

        slugs = {p.slug for p in await list_public(db)}
        assert slugs == {page["slug"] for page in STARTER_PAGES}

    async def test_is_idempotent(self, db):
        from app.services.docs_service import STARTER_PAGES

        assert await seed_starter_pages(db) == len(STARTER_PAGES)
        assert await seed_starter_pages(db) == 0
        assert len(await list_public(db)) == len(STARTER_PAGES)

    async def test_does_not_overwrite_an_edited_page(self, db):
        await seed_starter_pages(db)
        page = await get_published(db, "getting-started")
        page.content = "My own words."
        await db.flush()

        await seed_starter_pages(db)
        await db.refresh(page)
        assert page.content == "My own words."

    async def test_seeded_content_renders(self, db, client):
        await seed_starter_pages(db)
        response = await client.get("/api/internal/docs/understanding-severity-tiers")
        assert response.status_code == 200
        assert "Exploited in the wild" in response.text

    async def test_a_superseded_page_is_retired_on_an_existing_deployment(self, db):
        """The old CI page tells people to authenticate with a session cookie.

        Seeding is idempotent by slug, so a rename would leave that page
        published forever — still the top result for anyone searching the docs
        for how to wire up CI.
        """
        from app.services.docs_service import create_page

        await create_page(
            db,
            title="CI integration",
            slug="ci-integration",
            content="Send your session cookie.",
            published=True,
        )
        await seed_starter_pages(db)

        assert await get_published(db, "ci-integration") is None
        assert await get_published(db, "gate-your-pipeline") is not None

    async def test_a_retired_page_is_unpublished_not_deleted(self, db):
        # An administrator may have edited it. A draft is recoverable.
        from app.models import DocPage
        from app.services.docs_service import create_page

        await create_page(
            db, title="CI integration", slug="ci-integration", content="Mine.", published=True
        )
        await seed_starter_pages(db)

        page = await db.scalar(select(DocPage).where(DocPage.slug == "ci-integration"))
        assert page is not None
        assert page.published is False
        assert page.content == "Mine."


class TestStarterContentUpdates:
    """Getting improved starter copy onto a deployment that already has it.

    Seeding never overwrites, which is right — an administrator's edits are
    theirs. The consequence is that "the docs were improved" and "the docs on
    the site improved" are different statements, and closing that gap has to be
    a deliberate act rather than a side effect of deploying.
    """

    async def test_a_fresh_deployment_reports_every_page_as_missing(self, db):
        from app.services.docs_service import STARTER_PAGES, starter_page_drift

        drift = await starter_page_drift(db)

        assert len(drift) == len(STARTER_PAGES)
        assert all(exists is False for _, exists in drift)

    async def test_a_freshly_seeded_deployment_has_no_drift(self, db):
        from app.services.docs_service import starter_page_drift

        await seed_starter_pages(db)

        assert await starter_page_drift(db) == []

    async def test_an_edited_page_shows_as_drifted(self, db):
        from app.services.docs_service import starter_page_drift

        await seed_starter_pages(db)
        page = await get_published(db, "getting-started")
        page.content = "My own words."
        await db.flush()

        drift = dict(await starter_page_drift(db))
        assert drift == {"getting-started": True}

    async def test_reseeding_replaces_the_content(self, db):
        from app.services.docs_service import reseed_starter_pages, starter_page_drift

        await seed_starter_pages(db)
        page = await get_published(db, "getting-started")
        page.content = "Stale."
        await db.flush()

        updated = await reseed_starter_pages(db)

        assert updated == ["getting-started"]
        await db.refresh(page)
        assert page.content != "Stale."
        assert await starter_page_drift(db) == []

    async def test_reseeding_touches_only_what_differs(self, db):
        from app.services.docs_service import reseed_starter_pages

        await seed_starter_pages(db)
        page = await get_published(db, "gate-your-pipeline")
        page.content = "Changed."
        await db.flush()

        assert await reseed_starter_pages(db) == ["gate-your-pipeline"]

    async def test_reseeding_is_idempotent(self, db):
        from app.services.docs_service import reseed_starter_pages

        await seed_starter_pages(db)

        assert await reseed_starter_pages(db) == []

    async def test_reseeding_preserves_publication_and_order(self, db):
        """Copy is ours; visibility and ordering are the administrator's."""
        from app.services.docs_service import reseed_starter_pages

        await seed_starter_pages(db)
        page = await db.scalar(select(DocPage).where(DocPage.slug == "getting-started"))
        page.content = "Stale."
        page.published = False
        page.position = 99
        await db.flush()

        await reseed_starter_pages(db)
        await db.refresh(page)

        assert page.published is False
        assert page.position == 99
        assert page.content != "Stale."

    async def test_reseeding_recreates_a_deleted_page(self, db):
        from app.services.docs_service import delete_page, reseed_starter_pages

        await seed_starter_pages(db)
        page = await get_published(db, "getting-started")
        await delete_page(db, page)
        await db.flush()

        assert "getting-started" in await reseed_starter_pages(db)
        assert await get_published(db, "getting-started") is not None


class TestTheDocsKeepUpWithTheCli:
    """Commands the CLI has that the documentation has not heard of.

    The failure is the quiet one: a command ships, works, and nobody outside
    the person who wrote it finds out. The CLI repository guards its own help
    text and README the same way, by parsing its dispatch switch; this side
    cannot read that source, so the list below is the seam between the two.

    Keeping it here rather than deriving it is a deliberate trade. It is a
    second copy, which is normally the thing to avoid -- but the alternative is
    a test that reaches across repositories or over the network, and a
    guardrail that is flaky is a guardrail somebody deletes. The cost is one
    line to add when a command is added; the failure message says so.
    """

    #: Every command a user could reasonably look up, and the page that should
    #: answer them. Aliases and `help` are left out.
    DOCUMENTED_IN: ClassVar[dict[str, str]] = {
        "auth": "the-cli",
        "create": "the-cli",
        "link": "the-cli",
        "unlink": "the-cli",
        "whoami": "the-cli",
        "logout": "the-cli",
        "key": "the-cli",
        "scan": "the-cli",
        "status": "the-cli",
        "findings": "the-cli",
        "history": "the-cli",
        "supply-chain": "the-cli",
        "profiles": "the-cli",
        "rules": "the-cli",
        "init": "the-cli",
        "version": "the-cli",
        "update": "the-cli",
    }

    def _page(self, slug: str) -> str:
        from app.services.docs_service import STARTER_PAGES

        return next(page["content"] for page in STARTER_PAGES if page["slug"] == slug)

    #: Where the CLI lives when both repositories are checked out together.
    #: Relative to this one, because that is how they sit on a working machine.
    SIBLING = Path(__file__).resolve().parent.parent.parent / "weedout-cli"

    def _commands_the_cli_dispatches(self) -> set[str] | None:
        """Parsed from the CLI's own source, or None when it is not here.

        The same regex the CLI's `usage_test.go` uses, for the same reason: a
        list maintained by hand is the problem one level down.
        """
        source = self.SIBLING / "internal" / "cli" / "cli.go"
        if not source.exists():
            return None

        text = source.read_text(encoding="utf-8")
        # A leading dash means a flag handled in the same switch --
        # --interactive, --version, -h -- not a command. They are documented
        # as flags, and demanding a command entry would mean listing
        # `weedout --version` as one.
        found = {
            name
            for name in re.findall(r'(?m)^\tcase "([a-z-]+)"', text)
            if not name.startswith("-")
        }
        # A parser that silently matches nothing would make this pass forever.
        return found if len(found) >= 10 else None

    def test_the_documented_list_matches_the_cli(self):
        """Verified against the real dispatch when both repositories are here.

        Skipped otherwise, which is most CI runs. That is a weaker guarantee
        than deriving the list, and it is the strongest one available across a
        repository boundary without a network call -- and a guardrail that is
        flaky is a guardrail somebody deletes.
        """
        dispatched = self._commands_the_cli_dispatches()
        if dispatched is None:
            pytest.skip("the CLI repository is not checked out beside this one")

        # Aliases and `help` never need a documentation entry of their own.

        aliases = {
            "help",
            "interactive",
            "signals",
            "keys",
            "profile",
            "login",
            "upgrade",
            "self-update",
            "add",
            "remove",
            "rm",
            "list",
            "unignore",
            "ignore",
            "regenerate",
            "rotate",
            "on",
            "off",
        }
        expected = dispatched - aliases

        undocumented = sorted(expected - set(self.DOCUMENTED_IN))
        assert undocumented == [], (
            f"the CLI dispatches {undocumented}, which this file has never heard of. "
            f"Add them to DOCUMENTED_IN and to the page it names."
        )

        # And the other direction: an entry here for a command that no longer
        # exists is an entry nobody will remove, guarding nothing.
        stale = sorted(set(self.DOCUMENTED_IN) - dispatched)
        assert stale == [], f"documented but no longer a command: {stale}"

    def test_every_command_is_documented_somewhere(self):
        missing = [
            command
            for command, slug in self.DOCUMENTED_IN.items()
            if f"weedout {command}" not in self._page(slug)
        ]

        assert missing == [], (
            f"the {sorted({self.DOCUMENTED_IN[c] for c in missing})} page(s) do not mention: "
            f"{missing}. If a command was added to the CLI, add it here and to the page."
        )

    def test_the_cli_page_has_a_complete_command_table(self):
        """One place a reader can see everything, rather than a command
        mentioned in passing three sections apart."""
        page = self._page("the-cli")

        assert "## Every command" in page
        table = page[page.index("## Every command") :]
        missing = [c for c in self.DOCUMENTED_IN if f"weedout {c}" not in table]

        assert missing == [], f"absent from the reference table: {missing}"

    def test_the_newer_flags_are_documented(self):
        """A flag nobody knows about is a feature nobody uses."""
        page = self._page("the-cli")

        for flag in ("--profile", "--ecosystem", "--scope", "--no-browser", "--show", "--all"):
            assert flag in page, f"{flag} is not documented"

    def test_the_policy_file_upload_is_explained(self):
        """The least discoverable thing the binary does: a file you commit
        changes what a scan reports, with nothing to configure and no flag."""
        for slug in ("the-cli", "scanning-your-project", "gate-your-pipeline"):
            assert ".weedout.yml" in self._page(slug), slug

    def test_the_two_files_are_never_confused(self):
        """`.weedout` holds a credential and `.weedout.yml` holds rules.
        Pointing somebody at the wrong one is how a key gets committed."""
        for slug in ("the-cli", "scanning-your-project"):
            page = self._page(slug)
            assert "not the same file" in page or "is not `.weedout.yml`" in page, slug

    def test_nothing_still_tells_people_init_writes_the_rules_file(self):
        """It writes `.weedout`. Three pages said otherwise once.

        Scoped to the sentence making the claim rather than a window of
        characters around it. Every one of these pages goes on to explain that
        `.weedout` is not `.weedout.yml`, and a proximity check reads that
        clarification as the mistake it exists to prevent.
        """
        from app.services.docs_service import STARTER_PAGES

        for page in STARTER_PAGES:
            flattened = " ".join(page["content"].split())
            if "weedout init" not in flattened:
                continue

            index = flattened.index("weedout init")
            stop = flattened.find(".", index + len("weedout init` writes"))
            sentence = flattened[index : stop if stop != -1 else index + 200]

            assert ".weedout.yml" not in sentence, (
                f"{page['slug']} says `weedout init` writes .weedout.yml, which holds "
                f"rules and belongs in the repository: {sentence!r}"
            )


class TestStarterContentIsCliFirst:
    """The CLI is the primary flow now, so the docs have to lead with it."""

    async def test_getting_started_leads_with_the_command(self, db, client):
        await seed_starter_pages(db)

        response = await client.get("/api/internal/docs/getting-started")
        body = response.json()["data"]["body_html"]

        # The install line, not a package manager that no longer ships it:
        # the CLI is a Go binary now and `pip install weedout-cli` would send
        # somebody to a PyPI package that is not the product.
        assert "install.sh" in body
        assert "weedout scan" in body

    async def test_getting_started_still_offers_the_browser_path(self, db, client):
        """Not everyone wants to install something to evaluate a product."""
        await seed_starter_pages(db)

        assert "Add a project" in (await client.get("/api/internal/docs/getting-started")).text

    async def test_the_gating_example_uses_the_published_action(self, db, client):
        """The example has to be copy-pasteable.

        It previously named `itsmangooo/weedout/.github@v1`, a path that has
        never existed. A workflow snippet in documentation is the one kind of
        code nobody proof-reads before running.
        """
        await seed_starter_pages(db)
        body = (await client.get("/api/internal/docs/gate-your-pipeline")).text

        assert "itsmangooo/weedout-cli@v1" in body
        assert "weedout/.github@v1" not in body

    async def test_no_doc_page_tells_anyone_to_pip_install_the_cli(self, db, client):
        """The CLI is a Go binary. `pip install weedout-cli` would point people
        at a PyPI package that is not this product."""
        await seed_starter_pages(db)

        for slug in ("getting-started", "gate-your-pipeline"):
            body = (await client.get(f"/docs/{slug}")).text
            assert "pip install weedout" not in body, f"{slug} still says pip install"

    async def test_the_gating_example_makes_the_scan_a_dependency(self, db, client):
        """`needs:` is the entire mechanism. Without it the example would show a
        red cross beside a successful deploy."""
        await seed_starter_pages(db)

        body = (await client.get("/api/internal/docs/gate-your-pipeline")).text
        assert "needs: security-scan" in body
        assert "needs: [security-scan, build]" in body

    async def test_the_severity_page_explains_what_ci_fails_on(self, db, client):
        """The alerting bar and the gating bar are deliberately different, and
        somebody wiring up a gate needs to know which one they get."""
        await seed_starter_pages(db)

        body = (await client.get("/api/internal/docs/understanding-severity-tiers")).text
        assert "--ci" in body
