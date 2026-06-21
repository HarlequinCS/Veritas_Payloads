# OWASP Top 10 Payload Dataset

A comprehensive, structured collection of **51,752 unique payload strings** covering all OWASP Top 10 (2021) vulnerability categories, curated from industry-standard security testing wordlists.

## Dataset Overview

| Metric | Value |
|--------|-------|
| Total Payloads | 51,752 |
| Vulnerability Categories | 36 |
| Organized Files | 58 |
| Total Size (JSON) | ~17 MB |

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
- **`owasp_top10_payloads.json`** — single file containing all 51,752 entries

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

| Category | Payloads |
|----------|----------|
| Injection (LFI/RFI) | 24,572 |
| Injection (XSS) | 10,086 |
| Injection (Command Injection) | 8,707 |
| Security Misconfiguration | 4,964 |
| Identification & Authentication Failures | 824 |
| Injection (SQLi) | 556 |
| Injection (Open Redirect) | 259 |
| Cryptographic Failures | 166 |
| Injection (NoSQLi) | 147 |
| Injection (LDAP) | 123 |
| Broken Access Control (IDOR) | 114 |
| Injection (XXE) | 99 |
| Injection (SSTI) | 79 |
| Injection (SSRF) | 74 |
| Injection (Prototype Pollution) | 73 |
| Vulnerable & Outdated Components | 57 |
| Security Logging & Monitoring Failures | 56 |
| Injection (Format String) | 55 |
| Insecure Design | 50 |
| Injection (Request Smuggling) | 43 |
| Software & Data Integrity Failures (Deserialization) | 42 |
| Injection (LaTeX) | 36 |
| Injection (CRLF) | 33 |
| Injection (SMTP) | 30 |
| Injection (DOM Clobbering) | 25 |
| Injection (CSS Injection) | 23 |
| Injection (Type Juggling) | 19 |
| Web Cache Deception | 14 |
| Injection (CSV Injection) | 12 |
| Injection (XSLT) | 12 |
| HTTP Parameter Pollution | 11 |
| Injection (XPATH) | 11 |

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

This dataset was compiled from:
- **PayloadsAllTheThings** — community-driven payload repository
- **SecLists / Fuzzing** — by Daniel Miessler, Jason Haddix
- **Nuclei Templates** — by ProjectDiscovery
- **OWASP PayloadBox** — XSS payload collection
- **PortSwigger XSS Cheat Sheet**
- **Commix** — command injection test vectors
- **LFISuite** — local file inclusion paths
- **sqlmap** — SQL injection risk-classified payloads

## License

This dataset is compiled from publicly available security research and open-source wordlists. It is intended for authorized security testing and educational use only.
