# OWASP Top 10 Payload Dataset

A comprehensive, structured collection of **345,994 unique payload strings** covering all OWASP Top 10 (2025) vulnerability categories, curated from industry-standard security testing wordlists, exploit databases, and CWE mappings.

> **Interactive Dashboard:** Explore the dataset visually at [`index.html`](index.html) — a professional static dashboard built with HTML, CSS, and JavaScript. Served automatically via GitHub Pages from the root.

## Dataset Overview

| Metric | Value |
|--------|-------|
| Total Payloads | 345,994 |
| Vulnerability Categories | 65 |
| Organized Files | 187 |
| Total Size (JSON) | ~119 MB |
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
- **`owasp_top10_payloads.json`** — single file containing all 345,994 entries

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

### Categories

| Category | OWASP 2025 | Payloads |
|----------|------------|----------|
| _Identification & Authentication Failures (Weak Passwords)_ | — | 78,776 |
| **Injection (LFI/RFI)** | A05 | 54,180 |
| **Injection (XSS)** | A05 | 15,899 |
| **Security Misconfiguration** | A02 | 12,353 |
| **Injection (Command Injection)** | A05 | 11,985 |
| **Injection (SQLi)** | A05 | 7,885 |
| **Injection (Unrestricted File Upload)** | A05 | 6,131 |
| **Injection (LDAP)** | A05 | 5,949 |
| _Mishandling of Exceptional Conditions (Null/Type/Zero Errors)_ | — | 5,071 |
| **Web Cache Deception** | A02 | 4,583 |
| _Identification & Authentication Failures (Weak Session IDs)_ | — | 4,465 |
| _Insecure Design (Price Manipulation)_ | — | 4,282 |
| **Insecure Design** | A06 | 4,144 |
| **Injection (SSTI)** | A05 | 4,062 |
| **Software & Data Integrity Failures (Deserialization)** | A08 | 4,026 |
| **Injection (CRLF)** | A05 | 3,915 |
| **Injection (XXE)** | A05 | 3,850 |
| **Cryptographic Failures** | A04 | 3,804 |
| **Vulnerable & Outdated Components** | A03 | 3,721 |
| **Injection (SSI)** | A05 | 3,696 |
| _Vulnerable & Outdated Components (CVE Paths)_ | — | 3,693 |
| _Web Cache Deception (Cache Poisoning)_ | — | 3,680 |
| _Insecure Design (Race Condition Tests)_ | — | 3,625 |
| _Insecure Design (Coupon Abuse)_ | — | 3,618 |
| **HTTP Parameter Pollution** | A05 | 3,600 |
| **Injection (CSV Injection)** | A05 | 3,593 |
| **Software Supply Chain Failures** | A03 | 3,576 |
| _Insecure Design (Race Condition)_ | — | 3,525 |
| **Security Logging & Monitoring Failures** | A09 | 3,519 |
| _Mishandling of Exceptional Conditions (Error Info Disclosure)_ | — | 3,515 |
| _Mishandling of Exceptional Conditions (Missing/Extra Parameters)_ | — | 3,505 |
| _Cryptographic Failures (Weak Crypto Algos)_ | — | 3,487 |
| **Injection (XPATH)** | A05 | 3,487 |
| _Mishandling of Exceptional Conditions (Failing Open / Priv Esc)_ | — | 3,485 |
| _Mishandling of Exceptional Conditions (Debug Code Disclosure)_ | — | 3,481 |
| _Mishandling of Exceptional Conditions (Unchecked Exceptions)_ | — | 3,479 |
| _Vulnerable & Outdated Components (Vulnerable Versions)_ | — | 3,473 |
| _Cryptographic Failures (JWT None Alg)_ | — | 3,472 |
| _Cryptographic Failures (Weak TLS Probes)_ | — | 3,466 |
| _Cryptographic Failures (Info Disclosure Headers)_ | — | 3,461 |
| _Software Supply Chain Failures (Private Package Confusion)_ | — | 2,220 |
| _Identification & Authentication Failures (Username Enum)_ | — | 2,046 |
| **Injection (Open Redirect)** | A05 | 1,635 |
| **Injection (SSRF)** | A05 | 1,618 |
| **Injection (NoSQLi)** | A05 | 1,616 |
| **Injection (Prototype Pollution)** | A05 | 1,427 |
| **Identification & Authentication Failures** | A07 | 1,371 |
| **Injection (Format String)** | A05 | 1,356 |
| **Broken Access Control** | A01 | 1,298 |
| **Broken Access Control (IDOR)** | A01 | 1,281 |
| **Injection (GraphQL)** | A05 | 1,205 |
| **Injection (DOM Clobbering)** | A05 | 1,192 |
| _HTTP Parameter Pollution (Duplicate Params)_ | — | 1,172 |
| **Injection (LaTeX)** | A05 | 1,149 |
| **Injection (XSLT)** | A05 | 1,133 |
| _Software Supply Chain Failures (Vuln Dependency Versions)_ | — | 1,116 |
| _Insecure Design (Rate Limit Bypass)_ | — | 1,115 |
| **Injection (SMTP)** | A05 | 1,104 |
| **Injection (CSS Injection)** | A05 | 1,099 |
| **Injection (Request Smuggling)** | A05 | 1,088 |
| **Injection (Type Juggling)** | A05 | 1,087 |
| _Mishandling of Exceptional Conditions (Missing Error Page)_ | — | 1,050 |
| _Security Logging & Monitoring Failures (Log Injection)_ | — | 1,037 |
| _Web Cache Deception (Cache Poisoning Headers)_ | — | 1,034 |
| _Cryptographic Failures (JWT Kid Injection)_ | — | 1,028 |
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

## HTTP API

GitHub hosts the files, so the API is a set of JSON documents other systems fetch with GET. There is no query-string search: pick a category, then follow `next` until the pages run out. Rebuild the files with `python build_api.py` after the dataset changes.

Base URL after this repo is on GitHub:

```text
https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1
```

GitHub Pages, if enabled for the repository, serves the same tree at `https://harlequincs.github.io/Veritas_Payloads/api/v1`.

| Endpoint | What it returns |
|---|---|
| `index.json` | Dataset totals and the endpoint map |
| `categories.json` | All 65 categories, counts, and the first page link |
| `categories/{slug}.json` | One category, its injection points, and its page count |
| `categories/{slug}/page/{n}.json` | Up to 1,000 payloads, plus `next` and `prev` |
| `id-map/{bucket}.json` | Payload id to `[slug, page]`. `bucket` is the id number divided by 100000 |
| `sync-log.json` | Each upstream sync: when it ran, how many new payloads it added, and which source they came from |

```bash
curl https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1/categories/injection_sqli/page/1.json
```

```python
import requests

base = "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1"
page = requests.get(f"{base}/categories/injection_xss/page/1.json", timeout=60).json()
for item in page["results"]:
    print(item["payload_id"], item["payload_string"])

# Look up one id: OWP-0055 is bucket 0
slug, page_no = requests.get(f"{base}/id-map/0.json", timeout=60).json()["OWP-0055"]
```

Slugs drop spaces and parentheses, so `Injection (SQLi)` is `injection_sqli`. Each result still carries `vulnerability_category`, `injection_point`, and `payload_string`.

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
