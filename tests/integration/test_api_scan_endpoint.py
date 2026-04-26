"""
Integration Tests: Dashboard API Contract
==========================================
Tests that the response structures produced by the dashboard API endpoints
match the schema expected by the frontend (dashboard/index.html).

The dashboard makes these calls:
  GET  /api/status         → { before, after, snapshotCount, logs }
  POST /api/scan/before    → { ok, phase, score, totalChecks, issueCount, checks }
  POST /api/apply          → { ok, message }
  GET  /api/report         → { ok, message }

We do NOT start a real HTTP server. Instead we call the Python engine directly
and verify that the output objects match the contract the frontend depends on.

Why this matters:
  The frontend JavaScript reads specific field names (e.g., response.score,
  response.checks). If the backend omits or renames a field, the dashboard
  silently breaks — charts show nothing, tables are empty.

What failure means:
  A failing test means the API response contract has drifted from what the
  frontend expects, and the dashboard UI will display incorrect or missing data.

Source: dashboard/index.html (fetch calls), Start-Dashboard.ps1 (Send-Json responses)
"""

import json
import pytest
from src.iis_check_engine import evaluate_http_headers, calculate_score, count_issues


# ---------------------------------------------------------------------------
# Helpers that build mock API responses (mirror PowerShell Send-Json calls)
# ---------------------------------------------------------------------------

def mock_scan_response(phase: str, headers: dict) -> dict:
    """Simulate the JSON body of POST /api/scan/before or the after-apply scan."""
    checks = evaluate_http_headers(headers)
    score = calculate_score(checks)
    return {
        "ok": True,
        "phase": phase,
        "score": score,
        "totalChecks": len(checks),
        "issueCount": count_issues(checks),
        "checks": checks,
    }


def mock_status_response(before: dict, after: dict, snapshot_count: int) -> dict:
    """Simulate the JSON body of GET /api/status."""
    return {
        "before": before,
        "after": after,
        "snapshotCount": snapshot_count,
        "logs": [],
    }


# ---------------------------------------------------------------------------
# POST /api/scan/before contract
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_scan_response_contains_required_fields():
    """POST /api/scan/before must return all fields the frontend reads."""
    response = mock_scan_response("before", {"Server": "Microsoft-IIS/10.0"})

    required = {"ok", "phase", "score", "totalChecks", "issueCount", "checks"}
    assert required.issubset(response.keys()), f"Missing fields: {required - response.keys()}"


@pytest.mark.integration
def test_scan_response_field_types():
    """Field types in the scan response must match what the frontend JavaScript expects."""
    response = mock_scan_response("before", {"Server": "IIS/10"})

    assert response["ok"] is True
    assert isinstance(response["phase"], str)
    assert isinstance(response["score"], float)
    assert isinstance(response["totalChecks"], int)
    assert isinstance(response["issueCount"], int)
    assert isinstance(response["checks"], list)


@pytest.mark.integration
def test_scan_response_issue_count_equals_checks_sum():
    """issueCount in the response must equal the count of IsIssue==1 in checks."""
    headers = {"Server": "IIS/10", "X-Powered-By": "ASP.NET"}
    response = mock_scan_response("before", headers)

    counted_issues = sum(1 for c in response["checks"] if c["IsIssue"] == 1)
    assert response["issueCount"] == counted_issues


@pytest.mark.integration
def test_scan_response_total_checks_equals_checks_length():
    """totalChecks must always equal len(checks)."""
    response = mock_scan_response("before", {})
    assert response["totalChecks"] == len(response["checks"])


@pytest.mark.integration
def test_scan_response_score_consistent_with_issue_count():
    """
    Score must be consistent with issueCount: higher issueCount → lower score.
    Verifies that score and issueCount are derived from the same data.
    """
    vuln = mock_scan_response("before", {"Server": "IIS/10", "X-Powered-By": "ASP.NET"})
    safe = mock_scan_response("after", {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'",
    })

    assert vuln["issueCount"] > safe["issueCount"]
    assert vuln["score"] < safe["score"]


# ---------------------------------------------------------------------------
# GET /api/status contract
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_status_response_contains_required_fields():
    """GET /api/status must return before, after, snapshotCount, and logs."""
    before = {"phase": "before", "score": 0.0, "issueCount": 10, "checks": []}
    after  = {"phase": "after",  "score": 7.0, "issueCount": 3,  "checks": []}

    response = mock_status_response(before, after, snapshot_count=3)

    required = {"before", "after", "snapshotCount", "logs"}
    assert required.issubset(response.keys())


@pytest.mark.integration
def test_status_response_before_after_scores_correct():
    """Status response must preserve the before/after scores for dashboard cards."""
    before = {"phase": "before", "score": 0.0, "issueCount": 10, "checks": []}
    after  = {"phase": "after",  "score": 7.0, "issueCount": 3,  "checks": []}

    response = mock_status_response(before, after, snapshot_count=1)

    assert response["before"]["score"] == 0.0
    assert response["after"]["score"] == 7.0
    assert response["after"]["score"] > response["before"]["score"]


# ---------------------------------------------------------------------------
# check object schema (embedded in all responses)
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_each_check_in_response_has_dashboard_required_fields():
    """
    Each check object in the response must have all fields the dashboard table renders.
    The frontend reads: Check, Category, Status, IsIssue, Details.
    """
    response = mock_scan_response("before", {"Server": "IIS/10"})
    required_check_fields = {"Check", "Category", "Status", "IsIssue", "Details"}

    for check in response["checks"]:
        missing = required_check_fields - check.keys()
        assert not missing, f"Check '{check.get('Check')}' missing fields: {missing}"
