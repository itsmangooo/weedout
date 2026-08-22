"""The CLI page tells the truth about the CLI.

The risk this page carries is specific: it is a page arguing that we are honest
about dependencies. A hardcoded list that drifts from the real go.mod would be
worse there than anywhere else in the product, so what is tested here is that
nothing on it is written by hand.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services import cli_release_service as svc

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _clear_cache():
    svc.reset_cache()
    yield
    svc.reset_cache()


class TestGoModParsing:
    def test_parses_the_parenthesised_require_block(self):
        parsed = svc.parse_go_mod(
            """module github.com/acme/tool

go 1.22

require (
	github.com/spf13/cobra v1.8.0
	golang.org/x/term v0.17.0 // indirect
)
"""
        )
        assert parsed.module_path == "github.com/acme/tool"
        assert parsed.go_version == "1.22"
        assert len(parsed.dependencies) == 2
        assert [d.module for d in parsed.direct] == ["github.com/spf13/cobra"]
        assert [d.module for d in parsed.indirect] == ["golang.org/x/term"]

    def test_parses_the_single_line_require_form(self):
        # A module with one dependency is usually written the short way, and
        # would otherwise be reported as having none.
        parsed = svc.parse_go_mod(
            "module github.com/acme/tool\n\ngo 1.22\n\nrequire github.com/pkg/errors v0.9.1\n"
        )
        assert [d.module for d in parsed.dependencies] == ["github.com/pkg/errors"]
        assert parsed.dependencies[0].version == "v0.9.1"
        assert parsed.dependencies[0].indirect is False

    def test_a_module_with_no_requires_is_stdlib_only(self):
        parsed = svc.parse_go_mod("module github.com/acme/tool\n\ngo 1.22\n")
        assert parsed.dependencies == ()
        assert parsed.is_stdlib_only is True
        assert parsed.third_party_count == 0

    def test_comments_inside_the_block_are_not_dependencies(self):
        parsed = svc.parse_go_mod(
            """module m

go 1.22

require (
	// this explains the next line
	github.com/a/b v1.0.0
)
"""
        )
        assert [d.module for d in parsed.dependencies] == ["github.com/a/b"]

    def test_a_dependency_in_go_mod_is_never_reported_as_stdlib(self):
        # Standard-library imports never appear in go.mod at all, so anything
        # in the require block is third-party by definition. Kept as a property
        # so no caller can construct one that claims otherwise.
        parsed = svc.parse_go_mod("module m\n\nrequire github.com/a/b v1.0.0\n")
        assert parsed.dependencies[0].is_stdlib is False

    def test_dependencies_are_ordered_direct_first(self):
        parsed = svc.parse_go_mod(
            """module m

require (
	github.com/z/z v1.0.0 // indirect
	github.com/a/a v1.0.0
)
"""
        )
        assert parsed.dependencies[0].module == "github.com/a/a"
        assert parsed.dependencies[0].indirect is False


class TestItReflectsTheRealGoMod:
    def test_the_actual_cli_go_mod_parses(self):
        """Parse the real file from the sibling repository, when it is there.

        This is the check that matters: the page's claim is about *this* CLI,
        so the parser has to handle the file it actually ships with, not just
        the synthetic ones above.
        """
        go_mod = ROOT.parent / "weedout-cli" / "go.mod"
        if not go_mod.is_file():
            pytest.skip("the CLI repository is not checked out alongside this one")

        parsed = svc.parse_go_mod(go_mod.read_text(encoding="utf-8"))
        assert parsed.module_path == "github.com/itsmangooo/weedout-cli"
        assert parsed.go_version
        # If this ever fails, the page's "zero dependencies" claim has stopped
        # being true and the section will say so on its own — but the failure
        # here is the reminder to go and look at why.
        assert parsed.is_stdlib_only, (
            f"the CLI has picked up dependencies: {[d.module for d in parsed.dependencies]}"
        )


class TestDegradesHonestly:
    def test_a_failed_fetch_reports_unavailable_rather_than_empty(self, monkeypatch):
        # An empty require block and a failed fetch look identical in the data
        # but mean opposite things: "we depend on nothing" versus "we don't
        # know". Conflating them would let the page claim the strongest
        # possible result during an outage.
        monkeypatch.setattr(svc, "_fetch", lambda *a, **k: None)
        module = svc.go_module(refresh=True)
        assert module.available is False
        assert module.is_stdlib_only is False

    def test_a_failed_release_fetch_still_links_to_the_releases_page(self, monkeypatch):
        monkeypatch.setattr(svc, "_fetch", lambda *a, **k: None)
        release = svc.latest_release(refresh=True)
        assert release.available is False
        assert svc.REPO in release.notes_url

    def test_a_stale_value_is_preferred_to_no_value(self, monkeypatch):
        monkeypatch.setattr(svc, "_fetch", lambda *a, **k: "module m\n\ngo 1.22\n")
        first = svc.go_module(refresh=True)
        assert first.available is True

        # The next fetch fails. An hour-old dependency list is far more useful
        # than an error, and it is still not hand-written.
        monkeypatch.setattr(svc, "_fetch", lambda *a, **k: None)
        second = svc.go_module(refresh=True)
        assert second.available is True
        assert second.module_path == "m"


class TestReleaseAssets:
    def test_only_binaries_are_offered_for_download(self):
        release = svc.parse_release(
            {
                "tag_name": "v1.0.0",
                "html_url": "https://example.test/releases/v1.0.0",
                "assets": [
                    {
                        "name": "weedout-linux-amd64",
                        "browser_download_url": "u1",
                        "size": 4_200_000,
                    },
                    {"name": "checksums.txt", "browser_download_url": "u2", "size": 400},
                ],
            }
        )
        names = [a.name for a in release.assets]
        # checksums.txt is for the install script to verify against, not for a
        # person to pick out of a table of binaries.
        assert names == ["weedout-linux-amd64"]

    def test_platform_and_size_read_cleanly(self):
        release = svc.parse_release(
            {
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "name": "weedout-windows-amd64.exe",
                        "browser_download_url": "u",
                        "size": 4_500_000,
                    }
                ],
            }
        )
        asset = release.assets[0]
        assert asset.platform == "windows-amd64"
        assert asset.size_label == "4.5 MB"


class TestPageRenders:
    async def test_the_cli_page_is_public(self, client, monkeypatch):
        """Reachable with no account, and still reachable when the upstream
        lookups fail — the page is about the tool, not about the release
        feed."""
        monkeypatch.setattr(svc, "_fetch", lambda *a, **k: None)

        assert (await client.get("/cli")).status_code == 200
        assert (await client.get("/api/internal/cli")).status_code == 200

    async def test_the_install_script_is_served_as_readable_text(self, client):
        # `curl -sSL https://weedout.dev/install.sh | sh` is a documented
        # address. It must also be readable in a browser: anyone sensible reads
        # a script before piping it into a shell.
        response = await client.get("/install.sh")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert "attachment" not in response.headers.get("content-disposition", "")
        assert "weedout" in response.text

    async def test_the_served_script_matches_the_one_in_the_cli_repo(self):
        # Two hand-maintained copies would drift, and the one people actually
        # run would be the stale one.
        source = ROOT.parent / "weedout-cli" / "install.sh"
        if not source.is_file():
            pytest.skip("the CLI repository is not checked out alongside this one")

        served = ROOT / "app" / "static" / "install.sh"
        assert served.read_text(encoding="utf-8") == source.read_text(encoding="utf-8"), (
            "app/static/install.sh has drifted from the CLI repo. "
            "Run: python scripts/sync_cli.py ../weedout-cli"
        )

    async def test_the_zero_dependency_claim_is_not_hardcoded(self, client):
        """The page says how many dependencies the CLI has. That number has to
        come from the parsed go.mod, because a hardcoded claim on a page about
        dependency honesty is the worst possible thing to let go stale."""
        body = (await client.get("/api/internal/cli")).json()["data"]

        # Served from the parse, not written down.
        assert "dependencies" in body["go_module"]
        assert isinstance(body["go_module"]["dependencies"], list)

        # And the component renders that list rather than spelling a number.
        component = (ROOT / "frontend" / "src" / "pages" / "CliPage.jsx").read_text(
            encoding="utf-8"
        )
        assert "module.dependencies.length" in component
        assert "module?.available" in component
