"""The `weedout` command-line client.

Three things are load-bearing and all three are tested against the real
implementations rather than mocks of them:

* Lockfile detection picks the file that says what is *installed*, in every
  ecosystem, and never wanders into `node_modules`.
* Key resolution order — the environment must beat a committed `.weedout`,
  or a CI job can silently authenticate as the wrong account.
* Exit codes distinguish "found something" from "could not check". A pipeline
  that conflates them will eventually treat an expired key as a clean build.
"""

from __future__ import annotations

import io
import json

import pytest
from weedout_cli import cli as cli_module
from weedout_cli.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, Printer, main
from weedout_cli.client import ApiError, ScanResult
from weedout_cli.config import CONFIG_FILENAME, resolve
from weedout_cli.detect import CANDIDATES, find_all_manifests, find_manifest

PACKAGE_JSON = json.dumps({"name": "demo", "dependencies": {"lodash": "^4.17.15"}})
PACKAGE_LOCK = json.dumps({"lockfileVersion": 3, "packages": {}})
REQUIREMENTS = "flask==2.0.0\nrequests==2.28.0\n"
GO_MOD = "module example.com/demo\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.0\n"


def write(directory, name: str, content: str):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestDetection:
    def test_finds_a_npm_manifest(self, tmp_path):
        write(tmp_path, "package.json", PACKAGE_JSON)
        found = find_manifest(tmp_path)

        assert found is not None
        assert found[0].name == "package.json"
        assert found[1].ecosystem == "npm"

    def test_finds_a_python_manifest(self, tmp_path):
        write(tmp_path, "requirements.txt", REQUIREMENTS)
        found = find_manifest(tmp_path)

        assert found[0].name == "requirements.txt"
        assert found[1].ecosystem == "PyPI"

    def test_finds_a_go_manifest(self, tmp_path):
        write(tmp_path, "go.mod", GO_MOD)
        found = find_manifest(tmp_path)

        assert found[0].name == "go.mod"
        assert found[1].ecosystem == "Go"

    def test_a_lockfile_beats_the_manifest_it_came_from(self, tmp_path):
        """The lockfile records what is installed; the manifest records what
        was asked for. Scanning the manifest means guessing at the floor its
        range permits, and the lockfile removes the guess."""
        write(tmp_path, "package.json", PACKAGE_JSON)
        write(tmp_path, "package-lock.json", PACKAGE_LOCK)

        found = find_manifest(tmp_path)
        assert found[0].name == "package-lock.json"
        assert found[1].locked is True

    def test_node_modules_is_never_searched(self, tmp_path):
        # It holds a package.json per installed package — thousands of files,
        # none of which describes the project being built.
        write(tmp_path / "node_modules" / "lodash", "package.json", PACKAGE_JSON)

        assert find_manifest(tmp_path) is None

    def test_common_junk_directories_are_skipped(self, tmp_path):
        for directory in (".git", ".venv", "dist", "vendor", "__pycache__"):
            write(tmp_path / directory, "package.json", PACKAGE_JSON)

        assert find_manifest(tmp_path) is None

    def test_a_manifest_in_a_subdirectory_is_found(self, tmp_path):
        write(tmp_path / "backend", "requirements.txt", REQUIREMENTS)
        found = find_manifest(tmp_path)

        assert found is not None
        assert found[0].parent.name == "backend"

    def test_a_root_manifest_beats_one_in_a_subdirectory(self, tmp_path):
        write(tmp_path, "requirements.txt", REQUIREMENTS)
        write(tmp_path / "tools", "requirements.txt", REQUIREMENTS)

        found = find_manifest(tmp_path)
        assert found[0].parent == tmp_path.resolve()

    def test_the_search_does_not_descend_forever(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d"
        write(deep, "package.json", PACKAGE_JSON)

        # A repository root is where a manifest lives. Walking a whole monorepo
        # would make the tool pick an arbitrary sub-package and report on the
        # wrong thing, which is worse than reporting nothing.
        assert find_manifest(tmp_path) is None

    def test_nothing_to_find_returns_none(self, tmp_path):
        write(tmp_path, "README.md", "# hello")
        assert find_manifest(tmp_path) is None

    def test_all_three_ecosystems_are_detected_together(self, tmp_path):
        write(tmp_path, "package.json", PACKAGE_JSON)
        write(tmp_path, "requirements.txt", REQUIREMENTS)
        write(tmp_path, "go.mod", GO_MOD)

        names = {path.name for path, _ in find_all_manifests(tmp_path)}
        assert names == {"package.json", "requirements.txt", "go.mod"}

    def test_detection_is_stable(self, tmp_path):
        # Filesystem iteration order must not change which file gets scanned.
        for name in ("go.mod", "requirements.txt", "package.json"):
            write(tmp_path, name, "x")

        first = [p.name for p, _ in find_all_manifests(tmp_path)]
        second = [p.name for p, _ in find_all_manifests(tmp_path)]
        assert first == second


class TestDetectionMatchesTheServer:
    def test_every_filename_the_cli_offers_is_one_the_server_accepts(self):
        """The client must not upload files the server will reject.

        The two live in separate distributions — the CLI has no dependency on
        the app — so this is the seam where drift would otherwise show up as a
        confusing 422 in somebody's pipeline instead of as a failing test.
        """
        from app.core.manifests import detect_manifest_kind

        for candidate in CANDIDATES:
            kind = detect_manifest_kind(candidate.filename, "")
            assert kind is not None, candidate.filename
            assert str(kind.ecosystem) == candidate.ecosystem, candidate.filename

    def test_the_cli_offers_every_manifest_the_server_supports(self):
        from app.core.types import ManifestKind

        offered = {candidate.filename for candidate in CANDIDATES}
        assert offered == {kind.value for kind in ManifestKind}


class TestKeyResolution:
    def test_the_command_line_wins(self, tmp_path):
        write(tmp_path, CONFIG_FILENAME, "api_key = from-file")
        config = resolve(tmp_path, cli_key="from-flag", env={"WEEDOUT_API_KEY": "from-env"})

        assert config.api_key == "from-flag"
        assert config.key_source == "--api-key"

    def test_the_environment_beats_the_config_file(self, tmp_path):
        """The one that matters.

        CI injects secrets as environment variables. A `.weedout` that got
        committed must never quietly override the key the pipeline was
        configured with — authenticating as the wrong account is worse than
        failing to authenticate at all.
        """
        write(tmp_path, CONFIG_FILENAME, "api_key = from-file")
        config = resolve(tmp_path, env={"WEEDOUT_API_KEY": "from-env"})

        assert config.api_key == "from-env"
        assert config.key_source == "WEEDOUT_API_KEY"

    def test_the_config_file_is_the_fallback(self, tmp_path):
        write(tmp_path, CONFIG_FILENAME, "api_key = from-file")
        config = resolve(tmp_path, env={})

        assert config.api_key == "from-file"
        assert CONFIG_FILENAME in config.key_source

    def test_no_key_anywhere_resolves_to_none(self, tmp_path):
        config = resolve(tmp_path, env={})
        assert config.api_key is None
        assert config.key_source == "nowhere"

    def test_an_empty_environment_variable_does_not_count_as_a_key(self, tmp_path):
        # An unset secret in CI is an empty string, not an absent variable.
        # Treating it as a key produces a confusing 401 instead of "no key".
        write(tmp_path, CONFIG_FILENAME, "api_key = from-file")
        config = resolve(tmp_path, env={"WEEDOUT_API_KEY": ""})

        assert config.api_key == "from-file"

    def test_the_config_file_is_found_in_a_parent_directory(self, tmp_path):
        write(tmp_path, CONFIG_FILENAME, "api_key = from-file")
        nested = tmp_path / "src" / "app"
        nested.mkdir(parents=True)

        assert resolve(nested, env={}).api_key == "from-file"

    def test_quotes_and_comments_are_handled(self, tmp_path):
        write(
            tmp_path,
            CONFIG_FILENAME,
            '# a comment\n\napi_key = "wo_quoted"\nurl = https://example.test\n',
        )
        config = resolve(tmp_path, env={})

        assert config.api_key == "wo_quoted"
        assert config.base_url == "https://example.test"

    def test_a_malformed_config_file_does_not_crash(self, tmp_path):
        write(tmp_path, CONFIG_FILENAME, "this is not a config\n\x00\n")
        config = resolve(tmp_path, env={})

        assert config.api_key is None

    def test_the_url_falls_back_to_production(self, tmp_path):
        assert resolve(tmp_path, env={}).base_url == "https://weedout.dev"

    def test_a_trailing_slash_on_the_url_is_dropped(self, tmp_path):
        config = resolve(tmp_path, env={"WEEDOUT_URL": "https://example.test/"})
        assert config.base_url == "https://example.test"


def result(**overrides) -> ScanResult:
    payload = {
        "project": "demo",
        "dependencies_scanned": 42,
        "actionable": 0,
        "suppressed": 31,
        "new": 0,
        "resolved": 0,
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "exploited": 0},
        "findings": [],
        "warnings": [],
        "dashboard_url": "https://weedout.dev/targets/1",
    }
    payload.update(overrides)
    return ScanResult.from_json(payload)


CRITICAL_FINDING = {
    "cve": "CVE-2020-8203",
    "package": "lodash",
    "version": "4.17.15",
    "fixed_in": "4.17.21",
    "severity": "critical",
    "exploited": False,
}

EXPLOITED_HIGH_FINDING = {
    "cve": "CVE-2021-44228",
    "package": "log4j",
    "version": "2.14.0",
    "fixed_in": "2.17.1",
    "severity": "high",
    "exploited": True,
}


@pytest.fixture
def project(tmp_path):
    write(tmp_path, "package.json", PACKAGE_JSON)
    write(tmp_path, CONFIG_FILENAME, "api_key = wo_test-key")
    return tmp_path


@pytest.fixture
def capture(monkeypatch):
    """Replace the printer's stream so output can be asserted on."""
    stream = io.StringIO()
    monkeypatch.setattr(cli_module, "Printer", lambda *a, **kw: Printer(stream))
    return stream


class TestExitCodes:
    def _run(self, monkeypatch, project, scan_result, *args):
        def fake_post(base_url, api_key, path, timeout=120):
            if isinstance(scan_result, Exception):
                raise scan_result
            return scan_result

        monkeypatch.setattr(cli_module, "post_scan", fake_post)
        return main(["scan", str(project), *args])

    def test_a_clean_scan_exits_zero(self, monkeypatch, project, capture):
        assert self._run(monkeypatch, project, result()) == EXIT_OK

    def test_findings_without_ci_still_exit_zero(self, monkeypatch, project, capture):
        """Adding the tool to a pipeline must not be what breaks it first.

        Without `--ci` the findings are reported and the command succeeds, so a
        team can adopt it, look at the output, and opt into gating separately.
        """
        outcome = result(
            actionable=1,
            counts={"critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 0, "exploited": 0},
            findings=[CRITICAL_FINDING],
        )
        assert self._run(monkeypatch, project, outcome) == EXIT_OK

    def test_ci_exits_one_on_a_critical_finding(self, monkeypatch, project, capture):
        outcome = result(
            actionable=1,
            counts={"critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 0, "exploited": 0},
            findings=[CRITICAL_FINDING],
        )
        assert self._run(monkeypatch, project, outcome, "--ci") == EXIT_FINDINGS

    def test_ci_exits_one_on_an_exploited_finding_below_critical(
        self, monkeypatch, project, capture
    ):
        # Confirmed exploitation outranks the CVSS score. A high-severity bug
        # being used in the wild right now is not something to let through.
        outcome = result(
            actionable=1,
            counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0, "exploited": 1},
            findings=[EXPLOITED_HIGH_FINDING],
        )
        assert self._run(monkeypatch, project, outcome, "--ci") == EXIT_FINDINGS

    def test_ci_exits_zero_when_nothing_is_blocking(self, monkeypatch, project, capture):
        outcome = result(
            actionable=2,
            counts={"critical": 0, "high": 2, "medium": 0, "low": 0, "unknown": 0, "exploited": 0},
            findings=[],
        )
        assert self._run(monkeypatch, project, outcome, "--ci") == EXIT_OK

    def test_a_finding_that_is_both_critical_and_exploited_counts_once(self):
        both = dict(CRITICAL_FINDING, exploited=True)
        outcome = result(
            counts={"critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 0, "exploited": 1},
            findings=[both],
        )
        assert outcome.blocking == 1

    def test_an_api_error_exits_two_not_one(self, monkeypatch, project, capture):
        """The distinction the whole exit-code contract rests on.

        A pipeline that treats every non-zero exit as "vulnerabilities found"
        will one day treat an expired API key as a security finding, and
        somebody will fix it by deleting the step.
        """
        error = ApiError("That API key was not accepted.", code="unauthorized", status=401)
        assert self._run(monkeypatch, project, error, "--ci") == EXIT_ERROR

    def test_an_unavailable_service_exits_two(self, monkeypatch, project, capture):
        error = ApiError("Nothing was checked.", code="scan_failed", status=503)
        assert self._run(monkeypatch, project, error, "--ci") == EXIT_ERROR

    def test_no_manifest_exits_two(self, tmp_path, capture):
        write(tmp_path, CONFIG_FILENAME, "api_key = wo_test-key")
        assert main(["scan", str(tmp_path)]) == EXIT_ERROR
        assert "No manifest found" in capture.getvalue()

    def test_no_key_exits_two_without_calling_the_api(self, tmp_path, monkeypatch, capture):
        write(tmp_path, "package.json", PACKAGE_JSON)

        def explode(*args, **kwargs):
            raise AssertionError("must not call the API without a key")

        monkeypatch.setattr(cli_module, "post_scan", explode)
        monkeypatch.delenv("WEEDOUT_API_KEY", raising=False)

        assert main(["scan", str(tmp_path)]) == EXIT_ERROR
        assert "No API key" in capture.getvalue()

    def test_a_missing_path_exits_two(self, tmp_path, capture):
        assert main(["scan", str(tmp_path / "nope")]) == EXIT_ERROR


class TestOutput:
    def _run(self, monkeypatch, project, outcome, *args):
        monkeypatch.setattr(cli_module, "post_scan", lambda *a, **kw: outcome)
        return main(["scan", str(project), *args])

    def test_a_clean_scan_says_so_plainly(self, monkeypatch, project, capture):
        self._run(monkeypatch, project, result())
        assert "Nothing to act on" in capture.getvalue()

    def test_the_filtered_count_is_shown(self, monkeypatch, project, capture):
        # The number this product is proud of is not what it found, it is what
        # it decided not to interrupt anyone about.
        self._run(monkeypatch, project, result(suppressed=31))
        assert "31 filtered out" in capture.getvalue()

    def test_findings_are_printed_with_their_fix(self, monkeypatch, project, capture):
        self._run(
            monkeypatch,
            project,
            result(
                actionable=1,
                counts={
                    "critical": 1,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                    "exploited": 0,
                },
                findings=[CRITICAL_FINDING],
            ),
        )
        output = capture.getvalue()
        assert "lodash@4.17.15" in output
        assert "CVE-2020-8203" in output
        assert "4.17.21" in output

    def test_the_dashboard_link_is_printed(self, monkeypatch, project, capture):
        self._run(monkeypatch, project, result())
        assert "https://weedout.dev/targets/1" in capture.getvalue()

    def test_warnings_are_surfaced(self, monkeypatch, project, capture):
        # A stale mirror still scans, but the caller has to be told.
        self._run(monkeypatch, project, result(warnings=["Advisory data is 60h old."]))
        assert "60h old" in capture.getvalue()

    def test_output_has_no_escape_codes_when_not_a_terminal(self, monkeypatch, project, capture):
        self._run(monkeypatch, project, result())
        assert "\033[" not in capture.getvalue()


class TestInit:
    def test_writes_a_config_file(self, tmp_path, capture):
        write(tmp_path, "package.json", PACKAGE_JSON)
        assert main(["init", str(tmp_path), "--api-key", "wo_abc"]) == EXIT_OK

        content = (tmp_path / CONFIG_FILENAME).read_text(encoding="utf-8")
        assert "api_key = wo_abc" in content

    def test_the_file_warns_that_it_holds_a_credential(self, tmp_path, capture):
        main(["init", str(tmp_path), "--api-key", "wo_abc"])

        content = (tmp_path / CONFIG_FILENAME).read_text(encoding="utf-8")
        assert ".gitignore" in content
        assert ".gitignore" in capture.getvalue()

    def test_an_existing_file_is_not_overwritten(self, tmp_path, capture):
        write(tmp_path, CONFIG_FILENAME, "api_key = keep-me")

        assert main(["init", str(tmp_path), "--api-key", "wo_new"]) == EXIT_ERROR
        assert "keep-me" in (tmp_path / CONFIG_FILENAME).read_text(encoding="utf-8")

    def test_force_overwrites(self, tmp_path, capture):
        write(tmp_path, CONFIG_FILENAME, "api_key = replace-me")

        assert main(["init", str(tmp_path), "--api-key", "wo_new", "--force"]) == EXIT_OK
        assert "wo_new" in (tmp_path / CONFIG_FILENAME).read_text(encoding="utf-8")

    def test_it_reports_what_will_be_scanned(self, tmp_path, capture):
        write(tmp_path, "go.mod", GO_MOD)
        main(["init", str(tmp_path), "--api-key", "wo_abc"])

        assert "go.mod" in capture.getvalue()

    def test_no_key_available_is_an_error(self, tmp_path, monkeypatch, capture):
        monkeypatch.delenv("WEEDOUT_API_KEY", raising=False)
        assert main(["init", str(tmp_path)]) == EXIT_ERROR
        assert not (tmp_path / CONFIG_FILENAME).exists()

    def test_the_key_can_come_from_the_environment(self, tmp_path, monkeypatch, capture):
        monkeypatch.setenv("WEEDOUT_API_KEY", "wo_from_env")
        assert main(["init", str(tmp_path)]) == EXIT_OK
        assert "wo_from_env" in (tmp_path / CONFIG_FILENAME).read_text(encoding="utf-8")


def encoded_stream(encoding: str) -> io.TextIOWrapper:
    """A real stream with a real encoding, not a faked attribute.

    `io.StringIO` accepts any text, so it can never reproduce the bug this
    class exists for. A `TextIOWrapper` over bytes actually raises.
    """
    return io.TextIOWrapper(io.BytesIO(), encoding=encoding, errors="strict", newline="")


class TestTerminalCompatibility:
    """A tool that crashes while printing its own results is worse than one
    that prints plain ASCII. A default Windows `cmd.exe` is still cp1252."""

    def test_plain_symbols_are_chosen_for_a_legacy_code_page(self):
        printer = Printer(encoded_stream("cp1252"))

        assert printer.symbols is cli_module.PLAIN_SYMBOLS
        assert printer.symbol("arrow") == "->"

    def test_unicode_symbols_are_used_where_they_encode(self):
        assert Printer(encoded_stream("utf-8")).symbols is cli_module.FANCY_SYMBOLS

    def test_a_stream_with_no_encoding_gets_plain_symbols(self):
        # io.StringIO has no `encoding` attribute at all.
        assert Printer(io.StringIO()).symbols is cli_module.PLAIN_SYMBOLS

    def test_the_whole_report_encodes_on_a_legacy_code_page(self, monkeypatch, tmp_path):
        """The regression this class exists for.

        Every glyph the report can emit has to survive the round trip, not just
        the ones a particular fixture happens to exercise.
        """
        write(tmp_path, "package.json", PACKAGE_JSON)
        write(tmp_path, CONFIG_FILENAME, "api_key = wo_test-key")

        stream = encoded_stream("cp1252")
        monkeypatch.setattr(cli_module, "Printer", lambda *a, **kw: Printer(stream))
        monkeypatch.setattr(
            cli_module,
            "post_scan",
            lambda *a, **kw: result(
                actionable=2,
                counts={
                    "critical": 1,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                    "exploited": 1,
                },
                findings=[
                    CRITICAL_FINDING,
                    EXPLOITED_HIGH_FINDING,
                    dict(CRITICAL_FINDING, fixed_in=None),
                ],
                warnings=["Advisory data is 60h old."],
            ),
        )

        # Would raise UnicodeEncodeError here before the fix.
        main(["scan", str(tmp_path)])

        stream.flush()
        output = stream.buffer.getvalue().decode("cp1252")
        assert "->" in output
        assert "critical" in output


class TestUnexpectedFailures:
    def test_a_crash_exits_two_not_one(self, monkeypatch, tmp_path, capsys):
        """Exit 1 means "critical vulnerabilities found".

        A bug in the client that exited 1 would fail builds that are fine, and
        be indistinguishable from a real finding — so it would get worked
        around rather than reported.
        """
        write(tmp_path, "package.json", PACKAGE_JSON)
        write(tmp_path, CONFIG_FILENAME, "api_key = wo_test-key")

        def explode(*args, **kwargs):
            raise RuntimeError("something in the client broke")

        monkeypatch.setattr(cli_module, "post_scan", explode)

        assert main(["scan", str(tmp_path), "--ci"]) == EXIT_ERROR

    def test_the_crash_is_still_reported(self, monkeypatch, tmp_path, capsys):
        write(tmp_path, "package.json", PACKAGE_JSON)
        write(tmp_path, CONFIG_FILENAME, "api_key = wo_test-key")
        monkeypatch.setattr(
            cli_module, "post_scan", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom"))
        )

        main(["scan", str(tmp_path)])
        captured = capsys.readouterr()

        # Swallowing it silently would be its own failure mode.
        assert "boom" in captured.out + captured.err
        assert "Nothing was checked" in captured.out + captured.err
