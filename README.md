# IISLock&Fix

IISLock&Fix is an automated security auditing tool designed to analyze Microsoft IIS servers and generate a detailed security assessment report.

The system scans a target server and identifies common security misconfigurations, missing HTTP security headers, and TLS-related vulnerabilities.

---

## Overview

The tool evaluates the security posture of a web server and produces a structured HTML report summarizing detected issues.

The report includes:
- A security score (0�10)
- A list of detected vulnerabilities
- Status indicators for each check
- Technical explanations for each finding

---

## Security Checks

### HTTP Security

**HSTS (HTTP Strict Transport Security)**  
Ensures that clients connect using HTTPS only, preventing downgrade attacks.

**Clickjacking Protection**  
Checks whether the application is protected against UI redressing attacks using frame restrictions.

**X-Content-Type-Options**  
Prevents MIME type sniffing, reducing the risk of executing malicious files.

**Referrer Policy**  
Controls how much information is shared with external domains during navigation.

**Content Security Policy (CSP)**  
Mitigates cross-site scripting (XSS) by restricting allowed content sources.

**Server Header Exposure**  
Detects whether the server reveals version information that could assist attackers.

**X-Powered-By Header**  
Identifies exposure of backend technologies such as ASP.NET.

### TLS / Encryption

**TLS Support**  
Verifies whether HTTPS is enabled. Without encryption, data is transmitted in plain text.

**Weak Protocols**  
Detects the use of deprecated protocols such as SSL or TLS 1.0.

**Modern TLS Support**  
Ensures availability of secure protocols such as TLS 1.2 or TLS 1.3.

---

## Risk Implications

Improper server configuration may expose systems to:
- Unauthorized data access
- Man-in-the-Middle attacks
- Exploitation of known vulnerabilities
- Information disclosure

---

## Output

After execution, the tool generates an HTML report located at:

`/reports/SecurityReport.html`

The report provides a clear and structured view of the server's security posture.

---

## Technologies

- Python
- SSLyze
- TLS analysis libraries
- HTML-based reporting

---

## Usage Notes

- The tool can be used to analyze IIS-based servers.
- If no target is explicitly defined, the scan may default to localhost.

---

## QA & Testing

The project includes a three-layer automated test suite covering unit, integration, and regression scenarios.  
Tests run without a real IIS server or Windows administrator privileges.

### Quick start

```bash
pip install -r requirements-test.txt
pytest
```

### Run by layer

```bash
pytest -m unit          # isolated logic tests
pytest -m integration   # component pipeline tests
pytest -m regression    # known-input stability tests
```

For full documentation see [docs/QA_TESTING.md](docs/QA_TESTING.md).
