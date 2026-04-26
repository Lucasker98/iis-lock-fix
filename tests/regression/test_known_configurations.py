"""
Regression Tests: Known IIS Configuration Snapshots
=====================================================
Tests that known inputs always produce the same expected outputs.

Regression tests guard against accidental breakage — changes to scoring,
rule logic, or parsing that silently alter previously validated behaviour.

Why this matters:
  Each test here captures a specific, verified result from a previous audit.
  If any of these tests start failing, it means the tool now behaves differently
  from when it was last reviewed — which could mean a real vulnerability is
  being missed, or a previously-clean server is now being flagged incorrectly.

What failure means:
  A failing test is a regression alarm. Do NOT mark it as "expected failure"
  without fully understanding and documenting why the behaviour changed.

Fixtures:
  tests/fixtures/vulnerable_iis_snapshot.json  — real before.json from 2026-04-24 scan
  tests/fixtures/hardened_iis_snapshot.json    — expected after-hardening state
"""

import json
import pytest
from pathlib import Path
from src.iis_check_engine import (
    evaluate_http_headers,
    calculate_score,
    parse_nmap_tls_output,
    count_issues,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture(scope="module")
def vulnerable_snapshot():
    return json.loads((FIXTURES_DIR / "vulnerable_iis_snapshot.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def hardened_snapshot():
    return json.loads((FIXTURES_DIR / "hardened_iis_snapshot.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Vulnerable snapshot — must reproduce specific known findings
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_vulnerable_snapshot_score_is_zero(vulnerable_snapshot):
    """
    The real before-scan produced score=0. The engine must reproduce this
    when given the same rawHeaders. A non-zero score would mean a check
    that was previously flagged is now passing incorrectly.
    """
    score = calculate_score(vulnerable_snapshot["checks"])
    assert score == 0.0, f"Expected 0.0, got {score} — scoring regression detected"


@pytest.mark.regression
def test_vulnerable_snapshot_all_ten_checks_are_issues(vulnerable_snapshot):
    """All 10 checks (7 HTTP + 3 TLS) must be flagged for the vulnerable server."""
    total_issues = count_issues(vulnerable_snapshot["checks"])
    assert total_issues == 10


@pytest.mark.regression
def test_vulnerable_snapshot_hsts_is_issue(vulnerable_snapshot):
    """HSTS must always be flagged in the vulnerable snapshot. Removing this check is a regression."""
    hsts = next((c for c in vulnerable_snapshot["checks"] if c["Check"] == "HSTS"), None)
    assert hsts is not None, "HSTS check missing from snapshot"
    assert hsts["IsIssue"] == 1, "HSTS must be an issue in the vulnerable snapshot"


@pytest.mark.regression
def test_vulnerable_snapshot_server_header_exposed(vulnerable_snapshot):
    """Server header must be visible in the vulnerable raw headers."""
    raw = vulnerable_snapshot["rawHeaders"]
    assert "Server" in raw, "Server header must be present in vulnerable snapshot"
    assert "Microsoft-IIS" in raw["Server"]


@pytest.mark.regression
def test_vulnerable_snapshot_x_powered_by_exposed(vulnerable_snapshot):
    """X-Powered-By must be visible in the vulnerable raw headers."""
    raw = vulnerable_snapshot["rawHeaders"]
    assert "X-Powered-By" in raw, "X-Powered-By must be present in vulnerable snapshot"
    assert "ASP.NET" in raw["X-Powered-By"]


@pytest.mark.regression
def test_vulnerable_snapshot_engine_reproduces_all_issues(vulnerable_snapshot):
    """
    Running evaluate_http_headers() over the vulnerable rawHeaders must produce
    the same issue count as stored in the fixture. This links the engine to the
    real scan data.
    """
    raw = vulnerable_snapshot["rawHeaders"]
    checks = evaluate_http_headers(raw)
    engine_issues = count_issues(checks)
    # All 7 HTTP checks must fail for this server
    assert engine_issues == 7


# ---------------------------------------------------------------------------
# Hardened snapshot — must reflect post-hardening improvements
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_hardened_snapshot_score_is_seven(hardened_snapshot):
    """
    Post-hardening score must be 7.0 (7 HTTP checks pass, 3 TLS checks still fail
    because the demo site runs on plain HTTP — TLS requires IIS HTTPS binding).
    """
    score = hardened_snapshot["score"]
    assert score == 7.0, f"Expected 7.0, got {score}"


@pytest.mark.regression
def test_hardened_snapshot_http_checks_all_pass(hardened_snapshot):
    """After hardening, every HTTP check must pass (0 HTTP issues)."""
    http_issues = count_issues(hardened_snapshot["checks"], category="HTTP")
    assert http_issues == 0, f"Expected 0 HTTP issues after hardening, got {http_issues}"


@pytest.mark.regression
def test_hardened_snapshot_hsts_resolved(hardened_snapshot):
    """HSTS must be resolved (IsIssue=0) in the hardened snapshot."""
    hsts = next((c for c in hardened_snapshot["checks"] if c["Check"] == "HSTS"), None)
    assert hsts is not None
    assert hsts["IsIssue"] == 0, "HSTS must NOT be an issue after hardening"


@pytest.mark.regression
def test_hardened_snapshot_server_header_hidden(hardened_snapshot):
    """Server header must be removed after hardening (removeServerHeader=true in policy)."""
    raw = hardened_snapshot["rawHeaders"]
    assert "Server" not in raw, "Server header must be absent after hardening"


@pytest.mark.regression
def test_hardened_snapshot_engine_reproduces_zero_http_issues(hardened_snapshot):
    """Engine must reproduce zero HTTP issues when given the hardened rawHeaders."""
    raw = hardened_snapshot["rawHeaders"]
    checks = evaluate_http_headers(raw)
    http_issues = count_issues(checks, category="HTTP")
    assert http_issues == 0


# ---------------------------------------------------------------------------
# Ordering invariants — must hold across any future change
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_hardened_score_always_exceeds_vulnerable_score(vulnerable_snapshot, hardened_snapshot):
    """
    Hardened score > vulnerable score is a fundamental invariant.
    If this fails, the scoring direction has been reversed — a critical regression.
    """
    assert hardened_snapshot["score"] > vulnerable_snapshot["score"], (
        f"Hardened score ({hardened_snapshot['score']}) must exceed "
        f"vulnerable score ({vulnerable_snapshot['score']})"
    )


@pytest.mark.regression
def test_hardened_fewer_issues_than_vulnerable(vulnerable_snapshot, hardened_snapshot):
    """Issue count must decrease after hardening — never stay the same or increase."""
    assert hardened_snapshot["issueCount"] < vulnerable_snapshot["issueCount"]


# ---------------------------------------------------------------------------
# Score formula stability — changing the formula is a deliberate regression
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_score_formula_7_out_of_10_is_seven():
    """
    7 passing / 10 total → score = 7.0. Locked in because this is the
    post-hardening score shown in all project demonstrations.
    """
    checks = [{"IsIssue": 0}] * 7 + [{"IsIssue": 1}] * 3
    assert calculate_score(checks) == 7.0


@pytest.mark.regression
def test_score_formula_0_out_of_10_is_zero():
    """0 passing / 10 total → score = 0.0. Matches the real before-scan result."""
    checks = [{"IsIssue": 1}] * 10
    assert calculate_score(checks) == 0.0


# ---------------------------------------------------------------------------
# Known nmap output regression — weak protocol detection must be stable
# ---------------------------------------------------------------------------

@pytest.mark.regression
def test_known_nmap_weak_output_always_flags_weak_protocols():
    """
    This specific nmap output pattern was seen in the original scan.
    WeakProtocolsEnabled must always be flagged for this input.
    """
    nmap_output = "| SSLv3:\n|   TLSv1.0:\n|     ciphers: TLS_RSA_WITH_AES_128_CBC_SHA"
    results = parse_nmap_tls_output(nmap_output)
    weak = next(r for r in results if r["Check"] == "WeakProtocolsEnabled")
    assert weak["IsIssue"] == 1


@pytest.mark.regression
def test_known_nmap_modern_output_never_flags_modern_as_issue():
    """
    Modern TLS (1.2 + 1.3) must never be flagged as an issue.
    If this regresses, a properly configured server would show false positives.
    """
    nmap_output = "| TLSv1.2:\n|   ciphers: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n| TLSv1.3:\n|   ciphers: TLS_AKE"
    results = parse_nmap_tls_output(nmap_output)
    modern = next(r for r in results if r["Check"] == "ModernTlsPresent")
    assert modern["IsIssue"] == 0
