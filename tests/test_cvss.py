"""CVSS scoring and severity normalisation.

Severity decides whether a user gets interrupted, so the scoring formula is
verified against published vectors with known official scores rather than
against its own output.
"""

from __future__ import annotations

import pytest

from app.core.cvss import (
    label_to_severity,
    normalize_severity,
    score_cvss_vector,
    score_to_severity,
)
from app.core.types import Severity


class TestScoreCvssVector:
    @pytest.mark.parametrize(
        ("vector", "expected"),
        [
            # Log4Shell (CVE-2021-44228), official base score 10.0.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            # Heartbleed-style network read, official 7.5.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
            # Local, high privileges, low impact.
            ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
            # Scope-changed medium: the 1.08 multiplier and changed-scope PR
            # weights both apply.
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
            # Full local compromise, official 7.8.
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            # CVE-2020-8203 lodash prototype pollution, official NVD score 7.4.
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.4),
            # v3.0 vectors score identically.
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            # No impact at all scores zero.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ],
    )
    def test_matches_official_base_scores(self, vector, expected):
        assert score_cvss_vector(vector) == pytest.approx(expected)

    def test_temporal_and_environmental_metrics_are_ignored(self):
        base = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert score_cvss_vector(f"{base}/E:P/RL:O/RC:C") == score_cvss_vector(base)

    @pytest.mark.parametrize(
        "vector",
        [
            "",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # no CVSS: prefix
            "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",  # v2 uses a different formula
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",  # v4 needs a lookup table
            "CVSS:3.1/AV:N/AC:L",  # incomplete base metrics
            "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # invalid metric value
        ],
    )
    def test_unscorable_vectors_return_none_rather_than_a_guess(self, vector):
        assert score_cvss_vector(vector) is None


class TestScoreToSeverity:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (10.0, Severity.CRITICAL),
            (9.0, Severity.CRITICAL),
            (8.9, Severity.HIGH),
            (7.0, Severity.HIGH),
            (6.9, Severity.MEDIUM),
            (4.0, Severity.MEDIUM),
            (3.9, Severity.LOW),
            (0.1, Severity.LOW),
            (0.0, Severity.UNKNOWN),
            (None, Severity.UNKNOWN),
        ],
    )
    def test_bands(self, score, expected):
        assert score_to_severity(score) is expected


class TestLabelToSeverity:
    @pytest.mark.parametrize(
        ("label", "expected"),
        [
            ("CRITICAL", Severity.CRITICAL),
            ("high", Severity.HIGH),
            ("Important", Severity.HIGH),  # Red Hat vocabulary
            ("MODERATE", Severity.MEDIUM),  # GitHub vocabulary
            ("MEDIUM", Severity.MEDIUM),
            ("LOW", Severity.LOW),
            ("", Severity.UNKNOWN),
            (None, Severity.UNKNOWN),
            ("something-else", Severity.UNKNOWN),
        ],
    )
    def test_publisher_vocabularies_are_folded(self, label, expected):
        assert label_to_severity(label) is expected


class TestNormalizeSeverity:
    def test_cvss_vector_wins_over_qualitative_label(self):
        severity, score, vector = normalize_severity(
            [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
            qualitative_label="LOW",
        )
        assert severity is Severity.CRITICAL
        assert score == pytest.approx(10.0)
        assert vector.startswith("CVSS:3.1")

    def test_falls_back_to_label_when_no_scorable_vector(self):
        severity, score, _ = normalize_severity(
            [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}],
            qualitative_label="HIGH",
        )
        assert severity is Severity.HIGH
        assert score is None

    def test_v4_vector_is_kept_for_display_even_though_unscored(self):
        _, _, vector = normalize_severity(
            [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L"}], qualitative_label="HIGH"
        )
        assert vector == "CVSS:4.0/AV:N/AC:L"

    def test_highest_score_wins_when_several_vectors_present(self):
        severity, score, _ = normalize_severity(
            [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
            ]
        )
        assert severity is Severity.CRITICAL
        assert score == pytest.approx(10.0)

    def test_bare_numeric_score_is_accepted(self):
        severity, score, _ = normalize_severity([{"type": "CVSS_V3", "score": "8.1"}])
        assert severity is Severity.HIGH
        assert score == pytest.approx(8.1)

    def test_no_information_at_all_is_unknown(self):
        assert normalize_severity(None, None) == (Severity.UNKNOWN, None, None)
        assert normalize_severity([], "") == (Severity.UNKNOWN, None, None)

    def test_malformed_entries_are_skipped_not_fatal(self):
        severity, score, _ = normalize_severity(
            [
                "not-a-dict",  # type: ignore[list-item]
                {"type": "CVSS_V3"},
                {"type": "CVSS_V3", "score": None},
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
            ]
        )
        assert severity is Severity.HIGH
        assert score == pytest.approx(7.5)


class TestSeverityLadder:
    def test_severities_are_totally_ordered(self):
        assert Severity.UNKNOWN < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_unknown_is_below_every_threshold(self):
        # Otherwise an unrated advisory would alert as if it were critical.
        assert Severity.UNKNOWN < Severity.HIGH
        assert not Severity.UNKNOWN >= Severity.LOW
