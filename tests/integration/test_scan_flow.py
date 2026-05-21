"""
Integration Tests: Scan Flow — Header Evaluation → Score → State
=================================================================
Tests the end-to-end pipeline: raw HTTP headers → rule engine → score →
structured state object → JSON round-trip.

Why this matters:
  The scan flow is the core user-facing workflow. If evaluate_http_headers()
  produces wrong results, or calculate_score() receives the wrong input,
  or the state dict cannot be serialized/deserialized, the entire dashboard
  displays incorrect data.

What failure means:
  A failing test means the pipeline is broken at some boundary. The dashboard
  may show an incorrect score, missing findings, or fail to persist scan data.

Source logic:
  Start-Dashboard.ps1 → Invoke-ScanAndSave()
  Data contract: reports/state/before.json / after.json
"""

import json
import pytest
from pathlib import Path
from src.iis_check_engine import (
    evaluate_http_headers,
    calculate_score,
    count_issues,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Fixtures: load JSON snapshots from tests/fixtures/
# ---------------------------------------------------------------------------

@pytest.fixture
def vulnerable_state():
    return json.loads((FIXTURES_DIR / "vulnerable_iis_snapshot.json").read_text(encoding="utf-8"))


@pytest.fixture
def hardened_state():
    return json.loads((FIXTURES_DIR / "hardened_iis_snapshot.json").read_text(encoding="utf-8"))


@pytest.fixture
def ps_sample():
    return json.loads((FIXTURES_DIR / "powershell_sample_output.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Fixture integrity: both JSON files must be valid and contain required keys
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_vulnerable_fixture_loads_and_has_required_keys(vulnerable_state):
    """The vulnerable fixture must load cleanly and have the expected schema keys."""
    required = {"phase", "score", "totalChecks", "issueCount", "checks", "rawHeaders"}
    assert required.issubset(vulnerable_state.keys())
    assert vulnerable_state["phase"] == "before"


@pytest.mark.integration
def test_hardened_fixture_loads_and_has_required_keys(hardened_state):
    """The hardened fixture must load cleanly and have the expected schema keys."""
    required = {"phase", "score", "totalChecks", "issueCount", "checks", "rawHeaders"}
    assert required.issubset(hardened_state.keys())
    assert hardened_state["phase"] == "after"


# ---------------------------------------------------------------------------
# Scan pipeline: raw headers → rule engine → score
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_pipeline_vulnerable_headers_produces_seven_issues():
    """
    Vulnerable server headers fed through the pipeline must produce exactly
    7 HTTP issues (all HTTP checks fail).
    """
    raw_headers = {
        "Server": "Microsoft-IIS/10.0",
        "X-Powered-By": "ASP.NET",
        "Content-Type": "text/html",
    }
    checks = evaluate_http_headers(raw_headers)
    issues = count_issues(checks)
    assert issues == 7


@pytest.mark.integration
def test_pipeline_vulnerable_headers_score_is_zero():
    """Vulnerable server with all 7 HTTP checks failing must score 0.0."""
    raw_headers = {
        "Server": "Microsoft-IIS/10.0",
        "X-Powered-By": "ASP.NET",
    }
    checks = evaluate_http_headers(raw_headers)
    score = calculate_score(checks)
    assert score == 0.0


@pytest.mark.integration
def test_pipeline_hardened_headers_produces_zero_issues():
    """All recommended headers applied + no info-disclosure → 0 HTTP issues."""
    raw_headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "default-src 'self'",
    }
    checks = evaluate_http_headers(raw_headers)
    issues = count_issues(checks)
    assert issues == 0


@pytest.mark.integration
def test_pipeline_hardened_headers_score_is_ten():
    """All 7 HTTP checks passing → score must be 10.0."""
    raw_headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "default-src 'self'",
    }
    checks = evaluate_http_headers(raw_headers)
    score = calculate_score(checks)
    assert score == 10.0


# ---------------------------------------------------------------------------
# Fixture consistency: pipeline output must match fixture snapshots
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_pipeline_score_matches_vulnerable_fixture(vulnerable_state):
    """
    Running the engine over the vulnerable fixture's rawHeaders must reproduce
    the score stored in the fixture (confirms engine matches PS logic).
    """
    raw = vulnerable_state["rawHeaders"]
    checks = evaluate_http_headers(raw)
    score = calculate_score(checks)
    # Vulnerable server has no security headers → score must be 0.0
    assert score == 0.0
    assert vulnerable_state["score"] == 0.0


@pytest.mark.integration
def test_pipeline_hardened_headers_give_full_http_score(hardened_state):
    """
    After full hardening (HTTP headers + HTTPS binding), all 10 checks pass.
    evaluate_http_headers() over the hardened rawHeaders must produce 10.0.
    The fixture also stores 10.0 — HTTP and full-scan scores agree.
    """
    raw = hardened_state["rawHeaders"]
    checks = evaluate_http_headers(raw)
    http_score = calculate_score(checks)
    # All 7 HTTP checks pass → 10.0
    assert http_score == 10.0
    # Full scan (HTTP + TLS) also 10.0 — TLS passes after HTTPS binding
    assert hardened_state["score"] == 10.0


# ---------------------------------------------------------------------------
# State serialization: JSON round-trip must preserve all data
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_state_serialization_round_trip():
    """
    A state object built from scan output must survive JSON serialization and
    deserialization without any data loss.
    """
    raw_headers = {"Strict-Transport-Security": "max-age=31536000"}
    checks = evaluate_http_headers(raw_headers)
    score = calculate_score(checks)

    state = {
        "phase": "after",
        "score": score,
        "totalChecks": len(checks),
        "issueCount": count_issues(checks),
        "checks": checks,
        "rawHeaders": raw_headers,
    }

    serialized = json.dumps(state)
    deserialized = json.loads(serialized)

    assert deserialized["phase"] == "after"
    assert deserialized["totalChecks"] == len(checks)
    assert deserialized["score"] == score
    assert len(deserialized["checks"]) == len(checks)
