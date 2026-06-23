# OWASP Top 10 Payload Dataset

A comprehensive, structured collection of **65,781 unique payload strings** covering all OWASP Top 10 (2025) vulnerability categories, curated from industry-standard security testing wordlists, exploit databases, and CWE mappings.

> **Interactive Dashboard:** Explore the dataset visually at [`index.html`](index.html) — a professional static dashboard built with HTML, CSS, and JavaScript. Served automatically via GitHub Pages from the root.

## Dataset Overview

| Metric | Value |
|--------|-------|
| Total Payloads | 65,781 |
| Vulnerability Categories | 45 |
| Organized Files | 95 |
| Total Size (JSON) | ~24 MB |
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
- **`owasp_top10_payloads.json`** — single file containing all 55,994 entries

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

| Category | OWASP 2025 Map | Payloads |
|----------|-|----------|
| Injection (LFI/RFI) | A05 | 25,873 |
| Injection (XSS) | A05 | 12,462 |
| Injection (Command Injection) | A05 | 9,391 |
| Injection (SQLi) | A05 | 5,348 |
| Security Misconfiguration | A02 | 5,029 |
| Software & Data Integrity Failures (Deserialization) | A08 | 3,766 |
| Identification & Authentication Failures | A07 | 899 |
| Insecure Design | A06 | 473 |
| Injection (Open Redirect) | A05 | 272 |
| Cryptographic Failures | A04 | 166 |
| Injection (NoSQLi) | A05 | 147 |
| Broken Access Control (IDOR) | A01 | 138 |
| Software Supply Chain Failures | **A03** | 131 |
| Injection (SSRF) | A01 | 125 |
| Injection (LDAP) | A05 | 123 |
| Injection (Unrestricted File Upload) | A05 | 114 |
| Injection (XXE) | A05 | 110 |
| Injection (GraphQL) | A05 | 100 |
| Injection (SSI) | A05 | 100 |
| Broken Access Control | **A01** | 89 |
| Injection (SSTI) | A05 | 86 |
| Insecure Design (Race Condition) | A06 | 80 |
| Injection (Prototype Pollution) | A05 | 73 |
| Mishandling of Exceptional Conditions | **A10** | 240 |
| Vulnerable & Outdated Components | A03 | 57 |
| Security Logging & Alerting Failures | A09 | 56 |
| Injection (Format String) | A05 | 55 |
| Injection (Request Smuggling) | A05 | 43 |
| Injection (CRLF) | A05 | 42 |
| Injection (LaTeX) | A05 | 36 |
| Injection (SMTP) | A05 | 30 |
| Injection (DOM Clobbering) | A05 | 25 |
| Injection (CSS Injection) | A05 | 23 |
| Injection (Type Juggling) | A05 | 19 |
| Web Cache Deception | A02 | 14 |
| Injection (CSV Injection) | A05 | 12 |
| Injection (XSLT) | A05 | 12 |
| HTTP Parameter Pollution | A05 | 11 |
| Injection (XPATH) | A05 | 11 |

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
