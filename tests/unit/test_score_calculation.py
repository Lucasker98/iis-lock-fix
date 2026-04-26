"""
Unit Tests: Security Score Calculation
=======================================
Tests the scoring formula used to produce the headline security score.

Formula (mirrors Start-Dashboard.ps1 line ~169):
  score = round((passCount / totalChecks) * 10, 1)

Why this matters:
  The score is the primary metric presented in reports and in the dashboard.
  An incorrect formula would mislead stakeholders about actual security posture.

What failure means:
  A failing test means reported scores are mathematically wrong —
  a server with 0 passing checks might show a non-zero score, or vice versa.

Source logic: scripts/Start-Dashboard.ps1 → Invoke-ScanAndSave()
Python implementation: src/iis_check_engine.py → calculate_score()
"""

import pytest
from src.iis_check_engine import calculate_score


@pytest.mark.unit
class TestScoreCalculation:
    def test_all_issues_gives_zero(self):
        """All checks failing → score must be 0.0."""
        checks = [{"IsIssue": 1}] * 10
        assert calculate_score(checks) == 0.0

    def test_all_passing_gives_ten(self):
        """All checks passing → score must be 10.0."""
        checks = [{"IsIssue": 0}] * 10
        assert calculate_score(checks) == 10.0

    def test_half_passing_gives_five(self):
        """5 out of 10 passing → score must be 5.0."""
        checks = [{"IsIssue": 0}] * 5 + [{"IsIssue": 1}] * 5
        assert calculate_score(checks) == 5.0

    def test_seven_out_of_ten_gives_seven(self):
        """7 out of 10 passing → score must be 7.0 (typical post-hardening score)."""
        checks = [{"IsIssue": 0}] * 7 + [{"IsIssue": 1}] * 3
        assert calculate_score(checks) == 7.0

    def test_empty_checks_gives_zero(self):
        """Empty check list → score must be 0.0 (safe fallback)."""
        assert calculate_score([]) == 0.0

    def test_single_passing_check(self):
        """1 pass out of 10 → score must be 1.0."""
        checks = [{"IsIssue": 0}] + [{"IsIssue": 1}] * 9
        assert calculate_score(checks) == 1.0


@pytest.mark.unit
def test_hardened_score_always_exceeds_vulnerable_score():
    """
    Hardened server must always score higher than the same server before hardening.
    This ordering is guaranteed by the formula — verify it holds.
    """
    vulnerable = [{"IsIssue": 1}] * 10         # score = 0.0
    hardened   = [{"IsIssue": 0}] * 7 + [{"IsIssue": 1}] * 3  # score = 7.0
    assert calculate_score(hardened) > calculate_score(vulnerable)


@pytest.mark.unit
def test_score_is_rounded_to_one_decimal():
    """Score must be rounded to one decimal place (matches PowerShell Round(..., 1))."""
    checks = [{"IsIssue": 0}] * 1 + [{"IsIssue": 1}] * 2  # 1/3 = 3.333...
    score = calculate_score(checks)
    assert score == round(score, 1)
