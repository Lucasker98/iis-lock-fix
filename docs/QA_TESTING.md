# QA & Testing — IISLock&Fix

This document explains the test suite added to support the IISLock&Fix project.  
All tests run **locally without a real Windows Server, IIS installation, or administrator privileges.**

---

## Overview

The project uses **pytest** (Python) to test the core security evaluation logic.  
The PowerShell scripts (`Start-Dashboard.ps1`, `IISLockFix_Baseline.ps1`) implement the live scanning engine.  
The Python module `src/iis_check_engine.py` mirrors the key functions from those scripts, making them testable in isolation using JSON fixtures.

---

## Three Levels of Testing

### 1. Unit Testing

**What it means here:**  
Testing a single function in complete isolation — no files, no network, no IIS.

**Examples in this project:**
- Does `evaluate_http_headers()` correctly flag a missing HSTS header?
- Does a server with `Server: Microsoft-IIS/10.0` get flagged?
- Does `calculate_score()` produce `7.0` when 7 out of 10 checks pass?
- Does `parse_nmap_tls_output()` detect `SSLv3` as a weak protocol?

**Why it matters:**  
If a single check classification is wrong, every report derived from it is wrong.  
Unit tests catch these mistakes before they reach the dashboard.

---

### 2. Integration Testing

**What it means here:**  
Testing that two or more components work correctly together.

**Examples in this project:**
- Raw HTTP headers → `evaluate_http_headers()` → `calculate_score()` → structured state object  
  (the full scan pipeline, minus the live HTTP call)
- The state object produced by the pipeline survives JSON serialization and deserialization  
  (the data contract between the scanner and the dashboard)
- The mock API responses match the field names and types that `dashboard/index.html` expects

**Why it matters:**  
The dashboard reads specific JSON field names (`score`, `issueCount`, `checks[].IsIssue`).  
If any field is renamed or removed during refactoring, the dashboard silently breaks.  
Integration tests catch contract drift.

---

### 3. Regression Testing

**What it means here:**  
Locking in known behaviour so it cannot accidentally change.

**Examples in this project:**
- A specific real scan snapshot (`before.json` from 2026-04-24) must always produce `score=0.0`
- After hardening, the hardened snapshot must always score `7.0`
- `hardened.score > vulnerable.score` must always be true
- `WeakProtocolsEnabled` must always be flagged for a specific nmap output pattern  
- The score formula `(passCount / totalChecks) * 10` must remain stable

**Why it matters:**  
Changes to rule logic or scoring often seem safe in isolation but break previously validated outputs.  
Regression tests detect this before the change is deployed.

---

## File Structure

```
tests/
├── conftest.py                          # Shared pytest fixtures
├── fixtures/
│   ├── vulnerable_iis_snapshot.json     # Real before-scan state (all 10 checks failing)
│   ├── hardened_iis_snapshot.json       # Expected after-hardening state (7.0 score)
│   └── powershell_sample_output.json    # Mocked partial-hardening state
├── unit/
│   ├── test_rule_engine.py              # HTTP header classification logic
│   ├── test_score_calculation.py        # Score formula correctness
│   └── test_parsers.py                  # nmap TLS output + JSON state parsing
├── integration/
│   ├── test_scan_flow.py                # Raw headers → engine → score pipeline
│   └── test_api_scan_endpoint.py        # API response contract validation
└── regression/
    └── test_known_configurations.py     # Known input → expected output stability

src/
└── iis_check_engine.py                  # Python mirror of PS check logic (test target)

pytest.ini                               # Markers, test paths, options
requirements-test.txt                    # Test dependencies (pytest)
```

---

## Setup

Install test dependencies (Python 3.8+ required):

```bash
pip install -r requirements-test.txt
```

---

## How to Run Tests

### Run all tests

```bash
pytest
```

### Run only Unit Tests

```bash
pytest -m unit
```

### Run only Integration Tests

```bash
pytest -m integration
```

### Run only Regression Tests

```bash
pytest -m regression
```

### Run a specific file

```bash
pytest tests/unit/test_rule_engine.py
pytest tests/regression/test_known_configurations.py
```

### Run with summary (no verbose per-test output)

```bash
pytest -q
```

---

## Expected Output (all tests passing)

```
====================== test session starts ======================
platform win32 -- Python 3.x, pytest-8.x
rootdir: C:\dev\iis-lock-fix
configfile: pytest.ini

tests/integration/test_api_scan_endpoint.py::test_scan_response_contains_required_fields PASSED
tests/integration/test_api_scan_endpoint.py::test_scan_response_field_types PASSED
tests/integration/test_api_scan_endpoint.py::test_scan_response_issue_count_equals_checks_sum PASSED
tests/integration/test_api_scan_endpoint.py::test_scan_response_total_checks_equals_checks_length PASSED
tests/integration/test_api_scan_endpoint.py::test_scan_response_score_consistent_with_issue_count PASSED
tests/integration/test_api_scan_endpoint.py::test_status_response_contains_required_fields PASSED
tests/integration/test_api_scan_endpoint.py::test_status_response_before_after_scores_correct PASSED
tests/integration/test_api_scan_endpoint.py::test_each_check_in_response_has_dashboard_required_fields PASSED
tests/integration/test_scan_flow.py::test_vulnerable_fixture_loads_and_has_required_keys PASSED
tests/integration/test_scan_flow.py::test_hardened_fixture_loads_and_has_required_keys PASSED
...
tests/unit/test_rule_engine.py::TestHSTSCheck::test_hsts_missing_is_issue PASSED
tests/unit/test_rule_engine.py::TestHSTSCheck::test_hsts_present_is_ok PASSED
...
====================== 45 passed in 0.XXs =======================
```

---

## What Each Test Layer Validates

| Layer | Tests | Key Check |
|-------|-------|-----------|
| Unit | `test_rule_engine.py` | Each header classified correctly |
| Unit | `test_score_calculation.py` | Score formula is mathematically correct |
| Unit | `test_parsers.py` | nmap TLS regex + JSON state loading |
| Integration | `test_scan_flow.py` | Full pipeline: headers → checks → score → JSON |
| Integration | `test_api_scan_endpoint.py` | API response contract matches dashboard |
| Regression | `test_known_configurations.py` | Real scan data always produces same findings |

---

## How These Tests Support the Project Presentation

| Claim | Test Evidence |
|-------|---------------|
| "HSTS missing is detected" | `test_hsts_missing_is_issue` |
| "Score goes from 0 to 7 after hardening" | `test_score_formula_7_out_of_10_is_seven`, `test_hardened_score_always_exceeds_vulnerable_score` |
| "Server header exposure is flagged" | `test_server_header_present_is_issue` |
| "Weak TLS protocols are detected" | `test_weak_protocols_detected_when_sslv3_present` |
| "Dashboard gets correct data" | `test_scan_response_contains_required_fields`, `test_each_check_in_response_has_dashboard_required_fields` |
| "Hardening fixes are stable" | All regression tests |

---

## Notes / Manual Validation Required

The following behaviours **cannot be validated by automated tests** and require a real Windows Server + IIS environment:

| Item | Why Manual |
|------|-----------|
| Live HTTP scan via `Invoke-WebRequest` | Requires a running IIS site at the target URL |
| `Invoke-ApplyFixes` writing `web.config` | Requires filesystem write access to the IIS site directory |
| `iisreset /noforce` after rollback | Requires IIS service + administrator privileges |
| Snapshot backup of `applicationHost.config` | Requires admin access to `%SystemRoot%\System32\inetsrv\config\` |
| TLS scan via `nmap ssl-enum-ciphers` | Requires nmap in PATH and a TLS-enabled IIS endpoint |
| Dashboard HTTP server (`Start-Dashboard.ps1`) | Requires PowerShell 5.1 and port 9090 available |

These are all tested manually during a demo session against the `iislock.localtest.me:8080` environment.

---

## Engine Design Note

`src/iis_check_engine.py` is a Python implementation of the check logic from `scripts/Start-Dashboard.ps1`.  
It does not replace the PowerShell scripts — it mirrors them for testability.  
If the PowerShell scripts change their check logic, the Python engine must be updated to match.  
The regression tests will catch any divergence between the two.
