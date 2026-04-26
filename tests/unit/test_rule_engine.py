"""
Unit Tests: IIS Security Rule Engine
=====================================
Tests the core logic that classifies HTTP response headers as safe or unsafe.

Why this matters:
  The rule engine is the heart of the scanner. If it misclassifies a header,
  every report and score derived from it will be wrong.

What failure means:
  A failing test means the security classification logic is broken —
  the scanner may silently miss real vulnerabilities or flag safe servers.

Source logic: scripts/Start-Dashboard.ps1 → Invoke-ScanAndSave() check array
Python implementation: src/iis_check_engine.py → evaluate_http_headers()
"""

import pytest
from src.iis_check_engine import evaluate_http_headers


# ---------------------------------------------------------------------------
# HSTS
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestHSTSCheck:
    def test_hsts_missing_is_issue(self):
        """HSTS header absent → must be flagged as issue (downgrade attack risk)."""
        results = evaluate_http_headers({"Content-Type": "text/html"})
        hsts = next(r for r in results if r["Check"] == "HSTS")
        assert hsts["IsIssue"] == 1
        assert hsts["Status"] == "Issue"

    def test_hsts_present_is_ok(self):
        """Strict-Transport-Security present → must be classified as OK."""
        results = evaluate_http_headers(
            {"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload"}
        )
        hsts = next(r for r in results if r["Check"] == "HSTS")
        assert hsts["IsIssue"] == 0
        assert hsts["Status"] == "OK"


# ---------------------------------------------------------------------------
# Clickjacking
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestClickjackingCheck:
    def test_no_frame_protection_is_issue(self):
        """Neither X-Frame-Options nor CSP frame-ancestors → clickjacking risk."""
        results = evaluate_http_headers({})
        check = next(r for r in results if r["Check"] == "Clickjacking")
        assert check["IsIssue"] == 1

    def test_x_frame_options_protects(self):
        """X-Frame-Options: DENY satisfies the clickjacking check."""
        results = evaluate_http_headers({"X-Frame-Options": "DENY"})
        check = next(r for r in results if r["Check"] == "Clickjacking")
        assert check["IsIssue"] == 0

    def test_csp_frame_ancestors_protects(self):
        """CSP with frame-ancestors directive also satisfies the clickjacking check."""
        results = evaluate_http_headers(
            {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}
        )
        check = next(r for r in results if r["Check"] == "Clickjacking")
        assert check["IsIssue"] == 0


# ---------------------------------------------------------------------------
# Information-disclosure headers (Server, X-Powered-By)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestServerHeaderCheck:
    def test_server_header_present_is_issue(self):
        """Server header exposed → reveals software version (attacker intelligence)."""
        results = evaluate_http_headers({"Server": "Microsoft-IIS/10.0"})
        check = next(r for r in results if r["Check"] == "Server header")
        assert check["IsIssue"] == 1
        assert "Microsoft-IIS/10.0" in check["Details"]

    def test_server_header_absent_is_ok(self):
        """Server header removed → version fingerprinting prevented."""
        results = evaluate_http_headers({"Content-Type": "text/html"})
        check = next(r for r in results if r["Check"] == "Server header")
        assert check["IsIssue"] == 0
        assert check["Details"] == "Hidden"


@pytest.mark.unit
class TestXPoweredByCheck:
    def test_x_powered_by_present_is_issue(self):
        """X-Powered-By reveals the technology stack — must be flagged."""
        results = evaluate_http_headers({"X-Powered-By": "ASP.NET"})
        check = next(r for r in results if r["Check"] == "X-Powered-By")
        assert check["IsIssue"] == 1
        assert "ASP.NET" in check["Details"]

    def test_x_powered_by_absent_is_ok(self):
        """X-Powered-By absent → technology stack hidden."""
        results = evaluate_http_headers({})
        check = next(r for r in results if r["Check"] == "X-Powered-By")
        assert check["IsIssue"] == 0


# ---------------------------------------------------------------------------
# Full-server scenarios
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fully_vulnerable_server_fails_all_checks():
    """
    A server with no security headers and info-disclosure headers exposed
    must fail all 7 HTTP checks.
    """
    headers = {
        "Server": "Microsoft-IIS/10.0",
        "X-Powered-By": "ASP.NET",
        "Content-Type": "text/html",
    }
    results = evaluate_http_headers(headers)
    issue_count = sum(1 for r in results if r["IsIssue"] == 1)
    assert issue_count == 7, f"Expected 7 issues, got {issue_count}"


@pytest.mark.unit
def test_fully_hardened_server_passes_all_checks():
    """
    A server with all recommended headers applied and info-disclosure removed
    must pass all 7 HTTP checks.
    """
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "default-src 'self'",
        # Server and X-Powered-By intentionally absent
    }
    results = evaluate_http_headers(headers)
    issue_count = sum(1 for r in results if r["IsIssue"] == 1)
    assert issue_count == 0, f"Expected 0 issues, got {issue_count}"


@pytest.mark.unit
def test_evaluate_returns_seven_http_checks():
    """evaluate_http_headers() must always return exactly 7 check objects."""
    results = evaluate_http_headers({})
    assert len(results) == 7


@pytest.mark.unit
def test_all_checks_have_required_fields():
    """Every check result must have the fields required by the JSON state schema."""
    results = evaluate_http_headers({"Server": "IIS/10"})
    required = {"Check", "Category", "Status", "IsIssue", "Details"}
    for r in results:
        assert required.issubset(r.keys()), f"Missing fields in: {r}"
        assert r["Category"] == "HTTP"
        assert r["Status"] in ("OK", "Issue")
        assert r["IsIssue"] in (0, 1)
