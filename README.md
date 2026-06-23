# OWASP Top 10 Payload Dataset

A comprehensive, structured collection of **123,918 unique payload strings** covering all OWASP Top 10 (2025) vulnerability categories, curated from industry-standard security testing wordlists, exploit databases, and CWE mappings.

> **Interactive Dashboard:** Explore the dataset visually at [`index.html`](index.html) — a professional static dashboard built with HTML, CSS, and JavaScript. Served automatically via GitHub Pages from the root.

## Dataset Overview

| Metric | Value |
|--------|-------|
| Total Payloads | 123,918 |
| Vulnerability Categories | 65 |
| Organized Files | 141 |
| Total Size (JSON) | ~48 MB |
| OWASP Version | 2025 (all 10 categories covered) |

## Format

Each payload entry follows a consistent schema:

```json
{
  "payload_id": "OWP-0001",
  "vulnerability_category": "Injection (SQLi)",
  "target_technology": "Generic",
  "injection_point": "query_parameter",
  "payload_string": "' OR '1'='1",
  "validation": {
    "expected_status_code": 200,
    "success_regex": "error|sql"
  }
}
```

## Structure

The dataset is available in two forms:

### Unified JSON
- **`owasp_top10_payloads.json`** — single file containing all 123,918 entries

### Organized Directory

The `payloads/` directory groups payloads by vulnerability category and injection point:

```
payloads/
├── <category>/
│   ├── <injection_point>.json
│   └── ...
└── _manifest.json
```

Example: `payloads/injection_(sqli)/query_parameter.json` contains SQL injection payloads targeting query parameters.

## Categories

### OWASP Top 10 (2025) — Primary Classes

| OWASP 2025 | Category | Payloads |
|------------|----------|----------|
| A01 | Broken Access Control | 1,020 |
| A01 | Broken Access Control (IDOR) | 1,276 |
| A02 | Security Misconfiguration | 5,029 |
| A02 | Web Cache Deception | 1,020 |
| A03 | Software Supply Chain Failures | 1,020 |
| A03 | Vulnerable & Outdated Components | 1,020 |
| A04 | Cryptographic Failures | 1,020 |
| A05 | Injection (LFI/RFI) | 25,873 |
| A05 | Injection (XSS) | 12,462 |
| A05 | Injection (Command Injection) | 9,391 |
| A05 | Injection (SQLi) | 5,348 |
| A05 | Injection (SSRF) | 1,354 |
| A05 | Injection (Open Redirect) | 1,020 |
| A05 | Injection (NoSQLi) | 1,020 |
| A05 | Injection (LDAP) | 1,020 |
| A05 | Injection (SSTI) | 1,020 |
| A05 | Injection (XXE) | 1,020 |
| A05 | Injection (Unrestricted File Upload) | 1,020 |
| A05 | Injection (Prototype Pollution) | 1,020 |
| A05 | Injection (GraphQL) | 1,020 |
| A05 | Injection (SSI) | 1,020 |
| A05 | Injection (CRLF) | 1,020 |
| A05 | Injection (Format String) | 1,020 |
| A05 | Injection (Request Smuggling) | 1,020 |
| A05 | Injection (LaTeX) | 1,020 |
| A05 | Injection (SMTP) | 1,020 |
| A05 | Injection (DOM Clobbering) | 1,020 |
| A05 | Injection (CSS Injection) | 1,020 |
| A05 | Injection (CSV Injection) | 1,020 |
| A05 | Injection (Type Juggling) | 1,020 |
| A05 | Injection (XSLT) | 1,020 |
| A05 | Injection (XPATH) | 1,020 |
| A05 | HTTP Parameter Pollution | 1,020 |
| A06 | Insecure Design | 1,020 |
| A07 | Identification & Authentication Failures | 1,099 |
| A08 | Software & Data Integrity Failures (Deserialization) | 3,766 |
| A09 | Security Logging & Monitoring Failures | 1,020 |
| A10 | Mishandling of Exceptional Conditions | 1,020 |

### Sub-Categories (Secondary Classification)

| Category | Payloads |
|----------|----------|
| Cryptographic Failures (Info Disclosure Headers) | 1,020 |
| Cryptographic Failures (JWT None Alg) | 1,020 |
| Cryptographic Failures (JWT Kid Injection) | 1,020 |
| Cryptographic Failures (Weak Crypto Algos) | 1,020 |
| Cryptographic Failures (Weak TLS Probes) | 1,020 |
| HTTP Parameter Pollution (Duplicate Params) | 1,020 |
| Identification & Authentication Failures (Username Enum) | 1,020 |
| Identification & Authentication Failures (Weak Passwords) | 1,020 |
| Identification & Authentication Failures (Weak Session IDs) | 1,020 |
| Insecure Design (Coupon Abuse) | 1,020 |
| Insecure Design (Price Manipulation) | 1,020 |
| Insecure Design (Race Condition) | 1,020 |
| Insecure Design (Race Condition Tests) | 1,020 |
| Insecure Design (Rate Limit Bypass) | 1,020 |
| Mishandling of Exceptional Conditions (Debug Code Disclosure) | 1,020 |
| Mishandling of Exceptional Conditions (Error Info Disclosure) | 1,020 |
| Mishandling of Exceptional Conditions (Failing Open / Priv Esc) | 1,020 |
| Mishandling of Exceptional Conditions (Missing Error Page) | 1,020 |
| Mishandling of Exceptional Conditions (Missing/Extra Parameters) | 1,020 |
| Mishandling of Exceptional Conditions (Null/Type/Zero Errors) | 1,020 |
| Mishandling of Exceptional Conditions (Unchecked Exceptions) | 1,020 |
| Security Logging & Monitoring Failures (Log Injection) | 1,020 |
| Software Supply Chain Failures (Private Package Confusion) | 2,220 |
| Software Supply Chain Failures (Vuln Dependency Versions) | 1,020 |
| Vulnerable & Outdated Components (CVE Paths) | 1,020 |
| Vulnerable & Outdated Components (Vulnerable Versions) | 1,020 |
| Web Cache Deception (Cache Poisoning) | 1,020 |
| Web Cache Deception (Cache Poisoning Headers) | 1,020 |

## Injection Points

Payloads are classified by where they are injected:

- `query_parameter` — URL query string
- `form_parameter` — POST form body
- `path_parameter` — URL path segments
- `header` — HTTP headers
- `body_json` — JSON request body
- `body_xml` — XML request body
- `body_html` — HTML body
- `body_binary` — Binary body
- `body_yaml` — YAML body
- `cookie` — HTTP cookies
- `file_upload` — File upload fields
- `response_body` — Response body expectations
- `response_header` — Response header expectations
- `hash_parameter` — URL hash/fragment

## Usage

```python
import json

# Load a specific category/injection point
with open("payloads/injection_(sqli)/query_parameter.json") as f:
    payloads = json.load(f)

for p in payloads:
    print(p["payload_string"])
```

## Tool

The included **`organize_payloads.py`** script reads the unified JSON and re-generates the organized `payloads/` directory structure. Run it whenever the master file is updated:

```bash
python organize_payloads.py
```

## Sources

This dataset was compiled from the following open-source security research repositories and wordlists:

### Primary Repositories
- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** — Community-driven payload repository covering all major vulnerability categories. Extracted: XSS, SQLi, LFI, SSRF, SSTI, CMD injection, Open Redirect, SSI, XXE, CRLF, NoSQLi, LDAP, Prototype Pollution, SMTP injection, File Upload, CSV Injection, CSS Injection, DOM Clobbering, GraphQL, HTTP Parameter Pollution, LaTeX, Type Juggling, XPATH, XSLT, Request Smuggling, JWT attacks, Race Conditions, Web Cache Deception, Zip Slip, Mass Assignment.
- **[SecLists](https://github.com/danielmiessler/SecLists)** — The ultimate collection of security testing wordlists (by Daniel Miessler and Jason Haddix). Extracted: Fuzzing strings, XSS vectors (PortSwigger Cheat Sheet, OFJAAAH, PayloadBox, Jhaddix, MarioVectors), LFI paths (Jhaddix, LFISuite, gracefulsecurity, Linux packages, Windows paths), SQLi payloads (Generic, Oracle, auth bypass, sqlmap risk-classified), Command Injection (Commix), LDAP fuzzing, format strings, template expressions, XXE, SSI, login bypass, naughty strings, full Java class paths, numeric amounts.
- **[Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)** — Community-contributed vulnerability templates (by ProjectDiscovery). Extracted: WAF bypass, CORS misconfig, cache poisoning, LFI fuzzing, SSRF proxying, header injection, 403 bypass, open redirect, XSS fuzz, SQL injection, CRLF injection, generic LFI, environment disclosure.

### Specialized Wordlists
- **[PayloadBox XSS Payload List](https://github.com/payload-box/xss-payload-list)** — Cross-site scripting payload repository
- **[PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)** — Cross-site scripting evasion and filter bypass techniques
- **[Commix](https://github.com/commixproject/commix)** — Automated command injection testing
- **[sqlmap](https://github.com/sqlmapproject/sqlmap)** — Automatic SQL injection and database takeover
- **[LFISuite](https://github.com/D35m0nd142/LFISuite)** — Local File Inclusion exploitation toolkit
- **[fuzzdb](https://github.com/fuzzdb-project/fuzzdb)** — Attack pattern and fuzzing resource database
- **[Exploit Database](https://gitlab.com/exploit-database/exploitdb)** — The definitive archive of publicly disclosed exploits. Extracted: 9,327 PoC payload strings from 13,605 webapp exploit scripts covering SQLi, XSS, LFI, CMD injection, auth bypass, and more.
- **[Naughty Strings](https://github.com/minimaxir/big-list-of-naughty-strings)** — Edge case strings for input validation testing

### Cloud & Container References
- **AWS IMDS** — Instance Metadata Service endpoints (docs.aws.amazon.com)
- **GCP Metadata** — Google Compute Engine metadata server (cloud.google.com)
- **Azure IMDS** — Azure Instance Metadata Service (docs.microsoft.com)
- **Alibaba Cloud ECS Metadata** — ECS instance metadata (aliyun.com)
- **DigitalOcean Metadata** — Droplet metadata service (docs.digitalocean.com)
- **OpenStack Metadata** — OpenStack metadata API (docs.openstack.org)
- **Kubernetes** — Pod security context and service account secrets (kubernetes.io)

## License

This dataset is compiled from publicly available security research and open-source wordlists. It is intended for authorized security testing and educational use only. Each source repository retains its own license. See individual repositories for detailed licensing information.
