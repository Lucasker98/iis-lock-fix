"""
Unit Tests: Data Parsers
=========================
Tests parsing of nmap TLS output and JSON state file structures.

Why this matters:
  TLS protocol detection relies on parsing nmap's text output with specific
  regex patterns. If a pattern changes or nmap reformats its output, TLS
  vulnerabilities may be silently missed or incorrectly reported.

What failure means:
  A failing test means TLS protocol detection is broken, or the state file
  pipeline cannot deserialize saved scan data correctly.

Source logic: scripts/Start-Dashboard.ps1 → Get-TlsChecks()
Python implementation: src/iis_check_engine.py → parse_nmap_tls_output(), load_state_file()
"""

import json
import pytest
from src.iis_check_engine import parse_nmap_tls_output, load_state_file

# ---------------------------------------------------------------------------
# nmap output samples (mimic real nmap ssl-enum-ciphers output)
# ---------------------------------------------------------------------------

NMAP_MODERN_ONLY = """
Starting Nmap 7.95
Host is up (0.0010s latency).

PORT     STATE SERVICE
8080/tcp open  http-proxy
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|   TLSv1.3:
|     ciphers:
|       TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|_  least strength: A
"""

NMAP_WEAK_AND_MODERN = """
| ssl-enum-ciphers:
|   SSLv3:
|     ciphers:
|       TLS_RSA_WITH_RC4_128_SHA - F
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA - C
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 - A
"""

NMAP_NO_TLS = """
Starting Nmap 7.95
Host is up.
PORT     STATE SERVICE
8080/tcp open  http

Nmap done: 1 IP address scanned
"""

NMAP_TLS1_1_ONLY = """
| ssl-enum-ciphers:
|   TLSv1.1:
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA - C
"""


# ---------------------------------------------------------------------------
# TLS output parser tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_modern_tls_only_all_pass():
    """TLSv1.2 + TLSv1.3 only → any=OK, weak=OK, modern=OK."""
    results = parse_nmap_tls_output(NMAP_MODERN_ONLY)
    by_name = {r["Check"]: r for r in results}

    assert by_name["AnyTlsSupported"]["IsIssue"] == 0
    assert by_name["WeakProtocolsEnabled"]["IsIssue"] == 0
    assert by_name["ModernTlsPresent"]["IsIssue"] == 0


@pytest.mark.unit
def test_weak_protocols_detected_when_sslv3_present():
    """SSLv3 or TLSv1.0/1.1 in output → WeakProtocolsEnabled must be flagged."""
    results = parse_nmap_tls_output(NMAP_WEAK_AND_MODERN)
    weak = next(r for r in results if r["Check"] == "WeakProtocolsEnabled")
    assert weak["IsIssue"] == 1
    assert weak["Status"] == "Issue"


@pytest.mark.unit
def test_modern_tls_still_present_alongside_weak():
    """Even with weak protocols, modern TLS must be detected if TLSv1.2 is listed."""
    results = parse_nmap_tls_output(NMAP_WEAK_AND_MODERN)
    modern = next(r for r in results if r["Check"] == "ModernTlsPresent")
    assert modern["IsIssue"] == 0


@pytest.mark.unit
def test_no_tls_all_three_checks_fail():
    """No TLS at all → AnyTlsSupported=Issue, WeakProtocols=Issue, Modern=Issue."""
    results = parse_nmap_tls_output(NMAP_NO_TLS)
    by_name = {r["Check"]: r for r in results}

    assert by_name["AnyTlsSupported"]["IsIssue"] == 1
    assert by_name["WeakProtocolsEnabled"]["IsIssue"] == 1
    assert by_name["ModernTlsPresent"]["IsIssue"] == 1


@pytest.mark.unit
def test_no_tls_weak_details_is_critical_message():
    """Plain HTTP (no TLS) must produce the specific CRITICAL message used in reports."""
    results = parse_nmap_tls_output(NMAP_NO_TLS)
    weak = next(r for r in results if r["Check"] == "WeakProtocolsEnabled")
    assert "CRITICAL" in weak["Details"]
    assert "Plain Text" in weak["Details"]


@pytest.mark.unit
def test_tls1_1_only_weak_flagged_modern_missing():
    """TLSv1.1 only → any TLS detected, weak flagged, modern missing."""
    results = parse_nmap_tls_output(NMAP_TLS1_1_ONLY)
    by_name = {r["Check"]: r for r in results}

    assert by_name["AnyTlsSupported"]["IsIssue"] == 0   # some TLS exists
    assert by_name["WeakProtocolsEnabled"]["IsIssue"] == 1  # TLSv1.1 is weak
    assert by_name["ModernTlsPresent"]["IsIssue"] == 1  # no 1.2/1.3


@pytest.mark.unit
def test_parse_returns_exactly_three_tls_checks():
    """parse_nmap_tls_output() must always return exactly 3 TLS check objects."""
    results = parse_nmap_tls_output(NMAP_MODERN_ONLY)
    assert len(results) == 3
    check_names = {r["Check"] for r in results}
    assert check_names == {"AnyTlsSupported", "WeakProtocolsEnabled", "ModernTlsPresent"}


# ---------------------------------------------------------------------------
# State file (JSON) loader tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_load_state_file_returns_dict(tmp_path):
    """load_state_file() must deserialize a valid JSON state file into a dict."""
    state = {
        "phase": "before",
        "capturedAt": "2026-04-24T17:13:47+03:00",
        "score": 0.0,
        "totalChecks": 10,
        "issueCount": 10,
        "checks": [],
        "rawHeaders": {},
    }
    p = tmp_path / "before.json"
    p.write_text(json.dumps(state), encoding="utf-8")

    loaded = load_state_file(str(p))
    assert isinstance(loaded, dict)
    assert loaded["phase"] == "before"
    assert loaded["score"] == 0.0


@pytest.mark.unit
def test_load_state_file_preserves_required_keys(tmp_path):
    """Loaded state must contain all keys expected by the dashboard frontend."""
    state = {
        "phase": "after",
        "capturedAt": "2026-04-24T17:30:00+03:00",
        "score": 7.0,
        "totalChecks": 10,
        "issueCount": 3,
        "checks": [],
        "rawHeaders": {},
    }
    p = tmp_path / "after.json"
    p.write_text(json.dumps(state), encoding="utf-8")

    loaded = load_state_file(str(p))
    required_keys = {"phase", "score", "totalChecks", "issueCount", "checks", "rawHeaders"}
    assert required_keys.issubset(loaded.keys())
