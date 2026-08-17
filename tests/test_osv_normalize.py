"""Normalising raw OSV advisory JSON.

Fixtures here mirror the shapes OSV actually returns for the three ecosystems we
support, including the awkward ones: multiple disjoint affected windows, GIT
ranges with commit hashes, withdrawn records, and severity expressed three
different ways.
"""

from __future__ import annotations

from typing import ClassVar

from app.core.osv import normalize_osv_record, parse_affected, parse_ecosystem, parse_osv_datetime
from app.core.types import Ecosystem, Severity


class TestParseEcosystem:
    def test_supported_ecosystems(self):
        assert parse_ecosystem("npm") is Ecosystem.NPM
        assert parse_ecosystem("PyPI") is Ecosystem.PYPI
        assert parse_ecosystem("Go") is Ecosystem.GO

    def test_case_insensitive(self):
        assert parse_ecosystem("NPM") is Ecosystem.NPM
        assert parse_ecosystem("pypi") is Ecosystem.PYPI

    def test_release_qualified_ecosystem_uses_the_base(self):
        assert parse_ecosystem("Alpine:v3.10") is None  # unsupported, but parsed

    def test_unsupported_ecosystems_are_skipped_not_guessed(self):
        for value in ["Maven", "Debian", "crates.io", "NuGet", "", None]:
            assert parse_ecosystem(value) is None


class TestParseAffected:
    def test_simple_introduced_fixed_window(self):
        affected = parse_affected(
            [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                        }
                    ],
                }
            ]
        )
        assert len(affected) == 1
        assert affected[0].name == "lodash"
        assert affected[0].ranges[0].introduced == "0"
        assert affected[0].ranges[0].fixed == "4.17.21"

    def test_multiple_disjoint_windows_are_paired_correctly(self):
        # The single most error-prone shape: a flat event list encoding two
        # separate affected ranges.
        affected = parse_affected(
            [
                {
                    "package": {"ecosystem": "PyPI", "name": "django"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "3.2.18"},
                                {"introduced": "4.0"},
                                {"fixed": "4.0.10"},
                            ],
                        }
                    ],
                }
            ]
        )
        ranges = affected[0].ranges
        assert len(ranges) == 2
        assert (ranges[0].introduced, ranges[0].fixed) == ("0", "3.2.18")
        assert (ranges[1].introduced, ranges[1].fixed) == ("4.0", "4.0.10")

    def test_last_affected_is_preserved_separately_from_fixed(self):
        affected = parse_affected(
            [
                {
                    "package": {"ecosystem": "Go", "name": "github.com/x/y"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "1.0.0"}, {"last_affected": "1.4.2"}],
                        }
                    ],
                }
            ]
        )
        rng = affected[0].ranges[0]
        assert rng.fixed is None
        assert rng.last_affected == "1.4.2"

    def test_unclosed_window_means_still_affected(self):
        affected = parse_affected(
            [
                {
                    "package": {"ecosystem": "npm", "name": "x"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}],
                }
            ]
        )
        rng = affected[0].ranges[0]
        assert rng.introduced == "2.0.0"
        assert rng.fixed is None
        assert rng.last_affected is None

    def test_git_ranges_are_ignored(self):
        # Commit hashes have no ordering we can evaluate; treating them as
        # versions would either crash or match everything.
        affected = parse_affected(
            [
                {
                    "package": {"ecosystem": "Go", "name": "github.com/x/y"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://github.com/x/y",
                            "events": [{"introduced": "0"}, {"fixed": "a1b2c3d4"}],
                        },
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}, {"fixed": "1.2.0"}],
                        },
                    ],
                }
            ]
        )
        assert len(affected[0].ranges) == 1
        assert affected[0].ranges[0].fixed == "1.2.0"

    def test_entry_with_neither_ranges_nor_versions_is_dropped(self):
        # Keeping it would mean "affects every version", flagging every user.
        assert parse_affected([{"package": {"ecosystem": "npm", "name": "x"}}]) == ()

    def test_unsupported_ecosystem_entries_are_dropped(self):
        affected = parse_affected(
            [
                {
                    "package": {"ecosystem": "Maven", "name": "org.foo:bar"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                },
                {
                    "package": {"ecosystem": "npm", "name": "keep-me"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                },
            ]
        )
        assert [a.name for a in affected] == ["keep-me"]

    def test_malformed_entries_do_not_raise(self):
        assert parse_affected([None, "string", {}, {"package": "not-a-dict"}]) == ()
        assert parse_affected(None) == ()

    def test_enumerated_versions_are_kept(self):
        affected = parse_affected(
            [
                {
                    "package": {"ecosystem": "PyPI", "name": "x"},
                    "versions": ["1.0.0", "1.0.1"],
                }
            ]
        )
        assert affected[0].versions == ("1.0.0", "1.0.1")


class TestNormalizeOsvRecord:
    RECORD: ClassVar[dict] = {
        "id": "GHSA-p6mc-m468-83gg",
        "aliases": ["CVE-2020-8203"],
        "summary": "Prototype Pollution in lodash",
        "details": "Versions of lodash before 4.17.20 are vulnerable...",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.20"}]}
                ],
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"},
            {"type": "WEB", "url": "https://github.com/lodash/lodash/issues/4744"},
        ],
        "published": "2020-07-15T19:15:00Z",
    }

    def test_maps_the_core_fields(self):
        vuln = normalize_osv_record(self.RECORD)
        assert vuln.id == "GHSA-p6mc-m468-83gg"
        assert vuln.aliases == ("CVE-2020-8203",)
        assert vuln.summary.startswith("Prototype Pollution")
        assert vuln.withdrawn is False

    def test_computes_severity_from_the_cvss_vector(self):
        vuln = normalize_osv_record(self.RECORD)
        assert vuln.severity is Severity.HIGH
        assert vuln.cvss_score == 7.4

    def test_extracts_cve_ids_from_aliases(self):
        assert normalize_osv_record(self.RECORD).cve_ids == ("CVE-2020-8203",)

    def test_primary_cve_is_the_first_one(self):
        record = dict(self.RECORD, aliases=["GHSA-other", "CVE-2021-1111", "CVE-2021-2222"])
        vuln = normalize_osv_record(record)
        assert vuln.primary_cve == "CVE-2021-1111"

    def test_cve_ids_are_uppercased_and_deduplicated(self):
        record = dict(self.RECORD, aliases=["cve-2020-8203", "CVE-2020-8203"])
        assert normalize_osv_record(record).cve_ids == ("CVE-2020-8203",)

    def test_record_whose_own_id_is_a_cve(self):
        record = dict(self.RECORD, id="CVE-2021-44228", aliases=[])
        assert normalize_osv_record(record).cve_ids == ("CVE-2021-44228",)

    def test_falls_back_to_the_qualitative_label(self):
        record = dict(self.RECORD)
        record.pop("severity")
        record["database_specific"] = {"severity": "MODERATE"}
        vuln = normalize_osv_record(record)
        assert vuln.severity is Severity.MEDIUM
        assert vuln.cvss_score is None

    def test_severity_label_on_the_affected_entry_is_found(self):
        record = dict(self.RECORD)
        record.pop("severity")
        record["affected"] = [
            dict(record["affected"][0], database_specific={"severity": "CRITICAL"})
        ]
        assert normalize_osv_record(record).severity is Severity.CRITICAL

    def test_no_severity_information_yields_unknown(self):
        record = dict(self.RECORD)
        record.pop("severity")
        assert normalize_osv_record(record).severity is Severity.UNKNOWN

    def test_withdrawn_field_sets_the_flag(self):
        record = dict(self.RECORD, withdrawn="2021-03-01T00:00:00Z")
        assert normalize_osv_record(record).withdrawn is True

    def test_references_are_urls_only_and_deduplicated(self):
        record = dict(
            self.RECORD,
            references=[
                {"type": "WEB", "url": "https://example.com/a"},
                {"type": "WEB", "url": "https://example.com/a"},
                {"type": "WEB", "url": "javascript:alert(1)"},
                {"type": "WEB"},
                "not-a-dict",
            ],
        )
        assert normalize_osv_record(record).references == ("https://example.com/a",)

    def test_record_without_an_id_is_rejected(self):
        assert normalize_osv_record(dict(self.RECORD, id="")) is None
        record = dict(self.RECORD)
        record.pop("id")
        assert normalize_osv_record(record) is None

    def test_record_with_no_usable_affected_entry_is_rejected(self):
        assert normalize_osv_record(dict(self.RECORD, affected=[])) is None

    def test_non_dict_input_is_rejected(self):
        assert normalize_osv_record("not a record") is None  # type: ignore[arg-type]

    def test_missing_optional_text_fields_default_to_empty(self):
        record = {"id": "X-1", "affected": self.RECORD["affected"]}
        vuln = normalize_osv_record(record)
        assert vuln.summary == ""
        assert vuln.details == ""
        assert vuln.aliases == ()


class TestParseOsvDatetime:
    def test_parses_rfc3339_with_z(self):
        parsed = parse_osv_datetime("2020-07-15T19:15:00Z")
        assert parsed.year == 2020
        assert parsed.tzinfo is not None

    def test_naive_timestamps_are_assumed_utc(self):
        assert parse_osv_datetime("2020-07-15T19:15:00").tzinfo is not None

    def test_garbage_returns_none(self):
        assert parse_osv_datetime("not-a-date") is None
        assert parse_osv_datetime(None) is None
        assert parse_osv_datetime(12345) is None
