"""
IIS Security Check Engine
-------------------------
Python mirror of the core security evaluation logic found in:
  scripts/Start-Dashboard.ps1  (Invoke-ScanAndSave, Get-TlsChecks)
  scripts/IISLockFix_Baseline.ps1 (Get-HttpHeadersReport)

This module exists to make the business logic testable without requiring a
live IIS server, Windows PowerShell, or administrator privileges.
"""

import re
import json
from typing import Optional

# Check names match the exact strings used in the PowerShell scripts.
# Changing these would break the JSON state contract with the dashboard.
_HTTP_CHECKS = [
    {
        "name": "HSTS",
        "header": "strict-transport-security",
        "reverse": False,
        "good": "Enabled",
        "bad": "Not configured",
    },
    {
        # Satisfied by X-Frame-Options OR CSP frame-ancestors directive
        "name": "Clickjacking",
        "header": None,  # multi-source — handled in evaluate_http_headers
        "reverse": False,
        "good": "Protected",
        "bad": "Vulnerable",
    },
    {
        "name": "X-Content-Type-Options",
        "header": "x-content-type-options",
        "value_check": "nosniff",
        "reverse": False,
        "good": "Enabled (nosniff)",
        "bad": "Missing",
    },
    {
        "name": "Referrer-Policy",
        "header": "referrer-policy",
        "reverse": False,
        "good": "Configured",
        "bad": "Missing",
    },
    {
        "name": "Content-Security-Policy",
        "header": "content-security-policy",
        "reverse": False,
        "good": "Enabled",
        "bad": "Missing",
    },
    {
        # Server header should be ABSENT — reverse=True means present→issue
        "name": "Server header",
        "header": "server",
        "reverse": True,
        "good": "Hidden",
        "bad_template": "Visible ({value})",
    },
    {
        # X-Powered-By should be ABSENT — same reverse logic
        "name": "X-Powered-By",
        "header": "x-powered-by",
        "reverse": True,
        "good": "Hidden",
        "bad_template": "Visible ({value})",
    },
]


def evaluate_http_headers(headers: dict) -> list:
    """
    Evaluate HTTP response headers against IIS security best practices.

    Mirrors the check array in Start-Dashboard.ps1 → Invoke-ScanAndSave().
    Returns a list of check-result dicts matching the JSON state schema:
      {"Check", "Category", "Status", "IsIssue", "Details"}
    """
    norm = {k.lower(): v for k, v in headers.items()}
    results = []

    for cfg in _HTTP_CHECKS:
        name = cfg["name"]

        if name == "Clickjacking":
            # Protected if X-Frame-Options is set OR CSP contains frame-ancestors
            condition = bool(norm.get("x-frame-options")) or (
                "frame-ancestors" in norm.get("content-security-policy", "")
            )
            is_issue = 0 if condition else 1
            details = cfg["good"] if is_issue == 0 else cfg["bad"]

        elif cfg.get("value_check"):
            # Header must be present AND contain specific value
            condition = cfg["value_check"] in norm.get(cfg["header"], "")
            is_issue = 0 if condition else 1
            details = cfg["good"] if is_issue == 0 else cfg["bad"]

        elif cfg["reverse"]:
            # These headers should NOT be present (Server, X-Powered-By)
            header_value = norm.get(cfg["header"], "")
            condition = bool(header_value)   # True = header is present
            is_issue = 1 if condition else 0  # Present = issue
            if is_issue == 0:
                details = cfg["good"]
            else:
                template = cfg.get("bad_template", "Visible ({value})")
                details = template.format(value=header_value)

        else:
            # Header should be present
            condition = bool(norm.get(cfg["header"]))
            is_issue = 0 if condition else 1
            details = cfg["good"] if is_issue == 0 else cfg["bad"]

        results.append(
            {
                "Check": name,
                "Category": "HTTP",
                "Status": "OK" if is_issue == 0 else "Issue",
                "IsIssue": is_issue,
                "Details": details,
            }
        )

    return results


def calculate_score(checks: list) -> float:
    """
    Calculate the security score from a list of check results.

    Formula (matches Start-Dashboard.ps1 line ~169):
      score = round((passCount / total) * 10, 1)

    Returns 0.0 for an empty list.
    """
    if not checks:
        return 0.0
    total = len(checks)
    passed = sum(1 for c in checks if c.get("IsIssue", 1) == 0)
    return round((passed / total) * 10, 1)


def parse_nmap_tls_output(nmap_output: str) -> list:
    """
    Parse nmap ssl-enum-ciphers output to determine TLS protocol support.

    Mirrors Get-TlsChecks() in Start-Dashboard.ps1 (lines ~203-221).
    Regex patterns are kept identical to the PowerShell originals.

    Returns a list of three TLS check-result dicts:
      AnyTlsSupported, WeakProtocolsEnabled, ModernTlsPresent
    """
    any_tls = bool(re.search(r"TLSv1\.[0123]|SSLv[23]", nmap_output, re.IGNORECASE))
    modern = bool(re.search(r"TLSv1\.2|TLSv1\.3", nmap_output, re.IGNORECASE))
    weak = bool(re.search(r"SSLv2|SSLv3|TLSv1\.0|TLSv1\.1", nmap_output, re.IGNORECASE))

    # No TLS at all = plain text = WeakProtocols is also an issue
    weak_issue = (not any_tls) or weak

    if not any_tls:
        weak_details = "CRITICAL: Plain Text (No Encryption)"
    elif weak:
        weak_details = "Weak protocols enabled"
    else:
        weak_details = "No weak protocols detected"

    return [
        {
            "Check": "AnyTlsSupported",
            "Category": "TLS",
            "Status": "OK" if any_tls else "Issue",
            "IsIssue": 0 if any_tls else 1,
            "Details": "TLS detected" if any_tls else "No TLS (plain HTTP)",
        },
        {
            "Check": "WeakProtocolsEnabled",
            "Category": "TLS",
            "Status": "Issue" if weak_issue else "OK",
            "IsIssue": 1 if weak_issue else 0,
            "Details": weak_details,
        },
        {
            "Check": "ModernTlsPresent",
            "Category": "TLS",
            "Status": "OK" if modern else "Issue",
            "IsIssue": 0 if modern else 1,
            "Details": "Modern TLS available" if modern else "Modern TLS missing",
        },
    ]


def load_state_file(path: str) -> dict:
    """Load a JSON scan state file (before.json / after.json)."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def count_issues(checks: list, category: Optional[str] = None) -> int:
    """Count checks flagged as issues, optionally filtered by category."""
    return sum(
        1
        for c in checks
        if c.get("IsIssue") == 1
        and (category is None or c.get("Category") == category)
    )
