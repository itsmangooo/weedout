"""The design system is applied everywhere, and nothing opts out of it.

These are guardrails rather than assertions about how anything looks. A visual
pass across twenty templates decays the moment somebody adds the twenty-first,
so what is checked here is the property that made the pass necessary in the
first place: pages inventing their own colours, their own spacing and their own
type sizes instead of using the tokens.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "templates"
CSS = ROOT / "app" / "static" / "css" / "weedout.css"

#: Templates rendered inside another one rather than extending a layout.
PARTIALS = {"base.html"}

#: Inline styles that are computed per instance and cannot be a class: a bar
#: width from a count, a stagger delay from a loop index.
COMPUTED_STYLE = re.compile(r"\{\{|--fill:|flex:|transition-delay:")

HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")
STYLE_ATTR = re.compile(r'style="([^"]*)"')


def templates() -> list[Path]:
    return sorted(
        p
        for p in TEMPLATES.rglob("*.html")
        if str(p.relative_to(TEMPLATES)).replace("\\", "/") not in PARTIALS
    )


def rel(path: Path) -> str:
    return str(path.relative_to(TEMPLATES)).replace("\\", "/")


class TestTemplatesUseTheSystem:
    def test_no_template_declares_a_raw_colour(self):
        # A hex in a template is a colour that no theme can restyle, which is
        # exactly how a page ends up looking right in dark and wrong in light.
        offenders = {
            rel(p): HEX.findall(p.read_text(encoding="utf-8"))
            for p in templates()
            if HEX.search(p.read_text(encoding="utf-8"))
        }
        assert offenders == {}, f"raw colours outside the token block: {offenders}"

    def test_inline_styles_are_only_for_computed_values(self):
        offenders = {}
        for path in templates():
            hard_coded = [
                decl
                for decl in STYLE_ATTR.findall(path.read_text(encoding="utf-8"))
                if not COMPUTED_STYLE.search(decl)
            ]
            if hard_coded:
                offenders[rel(path)] = hard_coded
        assert offenders == {}, f"inline styles that should be tokens or utilities: {offenders}"

    def test_every_page_is_rendered_through_the_shell(self):
        # Either it extends a layout, or it is included by something that does.
        included = set()
        for path in templates():
            for match in re.findall(r'{%\s*include\s+"([^"]+)"', path.read_text(encoding="utf-8")):
                included.add(match)

        orphans = []
        for path in templates():
            name = rel(path)
            text = path.read_text(encoding="utf-8")
            if "{% extends" in text or name in included:
                continue
            orphans.append(name)
        assert orphans == [], f"templates on no layout: {orphans}"


class TestTokens:
    @pytest.fixture
    def css(self) -> str:
        return CSS.read_text(encoding="utf-8")

    def test_severity_is_a_dedicated_set_apart_from_the_accent(self, css: str):
        # The accent may never be a severity and a severity may never be the
        # accent, or "needs attention" and "primary button" become one colour.
        for theme_marker in (":root {", ':root[data-theme="light"] {'):
            start = css.index(theme_marker)
            block = css[start : css.index("\n}", start)]
            accent = re.search(r"^\s+--accent:\s*(#[0-9a-fA-F]+);", block, re.M)
            assert accent, f"no --accent in {theme_marker}"
            for tier in ("--exploited", "--critical", "--high", "--medium", "--low", "--digest"):
                value = re.search(rf"^\s+{tier}:\s*(#[0-9a-fA-F]+);", block, re.M)
                assert value, f"{tier} missing from {theme_marker}"
                assert value.group(1).lower() != accent.group(1).lower(), (
                    f"{tier} is the same colour as the accent in {theme_marker}"
                )

    def test_both_themes_define_every_severity_tier(self, css: str):
        tiers = (
            "--exploited",
            "--critical",
            "--high",
            "--medium",
            "--low",
            "--digest",
            "--exploited-fill",
            "--critical-fill",
        )
        for marker in (":root {", ':root[data-theme="light"] {'):
            start = css.index(marker)
            block = css[start : css.index("\n}", start)]
            missing = [t for t in tiers if f"{t}:" not in block]
            assert missing == [], f"{marker} is missing {missing}"

    def test_the_two_act_now_tiers_are_filled_not_tinted(self, css: str):
        # Fill vs tint is the channel that survives monochrome and colour-vision
        # deficiency, and it is what makes the top of the ladder scannable.
        assert "--exploited-fill" in css and "--exploited-on-fill" in css
        assert "--critical-fill" in css and "--critical-on-fill" in css
        block_start = css.index(".pill--exploited {")
        block = css[block_start : css.index("}", block_start)]
        assert "background: var(--exploited-fill)" in block

    def test_light_mode_severity_is_chosen_not_derived(self, css: str):
        # Darkening the dark-mode values is what produced the muted tan a
        # tester flagged; the light tiers are their own values.
        dark_start = css.index(":root {")
        dark = css[dark_start : css.index("\n}", dark_start)]
        light_start = css.index(':root[data-theme="light"] {')
        light = css[light_start : css.index("\n}", light_start)]
        for tier in ("--exploited", "--critical", "--high"):
            d = re.search(rf"^\s+{tier}:\s*(#[0-9a-fA-F]+);", dark, re.M).group(1)
            lt = re.search(rf"^\s+{tier}:\s*(#[0-9a-fA-F]+);", light, re.M).group(1)
            assert d.lower() != lt.lower(), f"{tier} is identical in both themes"


class TestStylesheetUsesTokens:
    """The template guard above missed the stylesheet itself.

    A hardcoded `color: #14161a` sat in the primary button rule for several
    rounds — invisible to the template check, and the reason the button ink
    never followed the theme. Colours below the token block have to justify
    themselves.
    """

    #: The only literals allowed outside the token block, each because it must
    #: NOT follow the current theme.
    ALLOWED: ClassVar[set[str]] = {
        # Theme swatches show a preset that is not the one applied, so they
        # cannot be expressed in tokens that resolve to the active theme.
        "swatch__chip",
        # A QR code needs a real white plate to be scannable, in every theme.
        "totp__qr",
        # A mask's #000 is an alpha value meaning "opaque", not a colour. It
        # never renders, and theming it would be meaningless.
        "cli-hero__canvas",
    }

    def test_no_hardcoded_colours_below_the_token_block(self):
        css = CSS.read_text(encoding="utf-8")
        body = css[css.index("   Reset & base") :]

        offenders = []
        rule = "(unknown)"
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.endswith("{"):
                rule = stripped
            if HEX.search(line) and not any(a in rule for a in self.ALLOWED):
                offenders.append(f"{rule} -> {stripped}")

        assert offenders == [], f"hardcoded colours outside the tokens: {offenders}"


class TestButtonContrast:
    def test_the_filled_button_has_its_own_accent(self):
        # One accent cannot be both light enough to read as text on a dark
        # surface and dark enough to carry white text as a fill. Splitting them
        # is what lets the button drop its near-black ink.
        css = CSS.read_text(encoding="utf-8")
        assert "--accent-solid:" in css
        assert "--accent-on-solid:" in css

        start = css.index(".btn--primary {")
        block = css[start : css.index("}", start)]
        assert "var(--accent-solid)" in block
        assert "var(--accent-on-solid)" in block
        assert "#" not in block, "the primary button is hardcoding a colour again"

    def test_hover_darkens_rather_than_lightens(self):
        # White sits on this fill. Lightening it on hover drops the contrast
        # under the label exactly when the control is being used.
        css = CSS.read_text(encoding="utf-8")
        start = css.index(".btn--primary:hover {")
        block = css[start : css.index("}", start)]
        assert "var(--accent-solid-hover)" in block
        assert "white" not in block


class TestStaticAssetsAreCacheBusted:
    """Static URLs must change when the file changes.

    They were keyed on the application version, which nobody bumps — so
    `weedout.css?v=0.1.0` stayed one URL across every edit. A browser that had
    loaded it once kept serving the old copy, and the CLI page shipped looking
    completely unstyled to anybody who had visited the site before.
    """

    def test_no_template_versions_an_asset_by_app_version(self):
        offenders = [
            rel(p) for p in templates() if "request.app.version" in p.read_text(encoding="utf-8")
        ]
        assert offenders == [], (
            "these version assets by app.version, which does not change when "
            f"the file does: {offenders}"
        )

    def test_every_versioned_asset_goes_through_the_helper(self):
        offenders = {}
        for path in templates():
            text = path.read_text(encoding="utf-8")
            raw = re.findall(r'(?:href|src)="/static/[^"]*\?v=[^"]*"', text)
            if raw:
                offenders[rel(path)] = raw
        assert offenders == {}, f"hand-written cache-busting: {offenders}"

    def test_the_hash_tracks_the_contents(self, tmp_path, monkeypatch):
        from app import assets

        monkeypatch.setattr(assets, "STATIC_DIR", tmp_path)
        assets._cache.clear()

        target = tmp_path / "probe.css"
        target.write_bytes(b"a{}")
        first = assets.digest("probe.css")

        target.write_bytes(b"a{color:red}")
        second = assets.digest("probe.css")

        assert first and second
        assert first != second, "the hash did not change when the file did"

    def test_a_missing_asset_does_not_raise(self, tmp_path, monkeypatch):
        from app import assets

        monkeypatch.setattr(assets, "STATIC_DIR", tmp_path)
        assets._cache.clear()
        # A broken page either way; this must fail as a 404 on the file rather
        # than as a 500 inside the template.
        assert assets.asset("nope.css") == "/static/nope.css"


class TestReducedMotionIsSafe:
    def test_delays_are_reset_not_just_durations(self):
        # The load-in animations use `backwards` fill, which holds the *from*
        # keyframe — opacity 0 — for the whole delay. Zeroing the duration but
        # leaving the delay means the content is invisible until it elapses.
        css = CSS.read_text(encoding="utf-8")
        # There is more than one reduced-motion block now: components may carry
        # their own local fallback, and the mobile nav does. The one that has to
        # reset delays is the global reset, identified by its universal
        # selector rather than by happening to come first in the file.
        marker = css.index("@media (prefers-reduced-motion: reduce) {\n  *,")
        block = css[marker : css.index("\n}", marker)]
        assert "animation-delay: 0s !important" in block
        assert "transition-delay: 0s !important" in block


class TestSearchHasOneEntryPoint:
    def test_only_one_control_opens_the_command_palette(self):
        triggers = []
        for path in TEMPLATES.rglob("*.html"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if "data-open-palette" in line:
                    triggers.append(f"{rel(path)}: {line.strip()[:70]}")
        assert len(triggers) == 1, f"expected one palette trigger, found: {triggers}"

    def test_the_trigger_lives_in_the_sidebar(self):
        base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        trigger_at = base.index("data-open-palette")
        sidebar_open = base.index('<aside class="sidebar"')
        sidebar_close = base.index("</aside>")
        assert sidebar_open < trigger_at < sidebar_close

    def test_no_leftover_search_control_in_the_app_bar(self):
        css = CSS.read_text(encoding="utf-8")
        base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        assert "appbar__search" not in base
        assert "appbar__search" not in css


class TestButtonsKeepTheirOwnColour:
    """Chrome that paints its links must not paint its buttons.

    `.nav a { color: var(--text-muted) }` is (0,1,1) and `.btn--primary` is
    (0,1,0), so the marketing header's "Start free" button wore the muted link
    colour: near-white in dark mode, which hid the bug, and dark grey on solid
    purple in light mode, about 1.5:1.

    Scoped to the containers that actually hold buttons -- a link colour inside
    prose or a footer is not a hazard, because no button lives there, and
    demanding `:not(.btn)` everywhere would be noise rather than a guard.
    """

    #  The chrome regions whose templates put a .btn next to a link.
    BUTTON_BEARING: ClassVar[tuple[str, ...]] = (
        ".nav",
        ".appbar",
        ".sidebar",
        ".page-head",
        ".btn-row",
        ".empty",
        ".modal",
    )

    #  ".something a" / ".something a:hover" -- a descendant-link rule. The @
    #  exclusion keeps at-rules out, where " and (" reads as one.
    LINK_RULE = re.compile(r"^([^@\n{}]*?\s+a(?![\w-])[^\n{},]*)\{([^}]*)\}", re.M)

    def offenders(self, css: str) -> list[str]:
        found = []
        for match in self.LINK_RULE.finditer(css):
            selector, body = match.group(1).strip(), match.group(2)
            if "color:" not in body or ".btn" in selector:
                continue
            if selector.startswith(self.BUTTON_BEARING):
                found.append(selector)
        return found

    def test_no_chrome_link_rule_repaints_a_button(self):
        found = self.offenders(CSS.read_text(encoding="utf-8"))
        assert not found, (
            f"these paint every link inside them, buttons included; add :not(.btn): {found}"
        )

    def test_the_guard_would_notice(self):
        """Only worth having if it fails on the bug it was written for."""
        assert self.offenders(".nav a {\n  color: var(--text-muted);\n}\n") == [".nav a"]
        assert self.offenders(".prose-doc a {\n  color: var(--accent);\n}\n") == []
