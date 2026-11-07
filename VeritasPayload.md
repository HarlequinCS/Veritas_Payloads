# Veritas Payloads API

Another system can call this API now. Use it to pull OWASP Top 10 payload strings into a scanner, fuzzer, or test harness. Every call is an HTTP GET. There is no API key and no `?q=` search. Choose a category, then follow `next` until the pages end. Filter `injection_point` in your own code.

The live paged files currently serve **345,994** payloads in **65** categories. That is the number in `index.json`. The dataset and `sync-log.json` are at **346,081**. The extra **87** are web paths kept from the 7 November 2026 sync (traversal, Swagger and key paths, and authentication-file paths). They are not in the category pages yet, so a client that only walks `categories/.../page/` does not receive those 87 until the pages are rebuilt.

## Base URL

```text
https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1
```

If GitHub Pages is enabled for the repository, the same files are also at:

```text
https://harlequincs.github.io/Veritas_Payloads/api/v1
```

The examples below use the raw GitHub URL.

## Endpoints

| GET | Returns |
|---|---|
| `/index.json` | Totals, page size, and the endpoint map |
| `/categories.json` | Every category, its slug, count, page count, and first page |
| `/categories/{slug}.json` | One category and its injection-point counts |
| `/categories/{slug}/page/{n}.json` | Up to 1,000 payloads, plus `next` and `prev` |
| `/id-map/{bucket}.json` | Payload id mapped to `[slug, page]` |
| `/sync-log.json` | Every upstream sync, newest first. `runs[0].added` is how many web payloads that run kept |

Pages are numbered from 1. `next` and `prev` are paths relative to the base URL. When `next` is `null`, you are on the last page.

A missing slug or page returns HTTP 404.

## Payload object

```json
{
  "payload_id": "OWP-0055",
  "vulnerability_category": "Injection (SQLi)",
  "target_technology": "MySQL",
  "injection_point": "query_parameter",
  "payload_string": "' UNION SELECT 1,2,3--",
  "validation": {
    "expected_status_code": 200,
    "success_regex": "2.*3"
  }
}
```

| Field | Meaning |
|---|---|
| `payload_id` | Stable id, `OWP-` plus a number |
| `vulnerability_category` | OWASP category name |
| `target_technology` | Stack the string is aimed at, or `Generic` |
| `injection_point` | Where to place the string |
| `payload_string` | The value to send |
| `validation.expected_status_code` | Status that suggests the check fired |
| `validation.success_regex` | Response pattern that suggests the check fired. Empty when there is no pattern |

Injection points used in the dataset:

`query_parameter`, `form_parameter`, `path_parameter`, `header`, `body_json`, `body_xml`, `body_html`, `body_binary`, `body_yaml`, `cookie`, `file_upload`, `response_body`, `response_header`, `hash_parameter`

## Slugs

A slug is the category name in lowercase, with spaces changed to `_` and parentheses removed. An ampersand stays in the slug, so encode it as `%26` in the URL.

| Category | Slug |
|---|---|
| Injection (SQLi) | `injection_sqli` |
| Injection (XSS) | `injection_xss` |
| Injection (LFI/RFI) | `injection_lfi_rfi` |
| Weak passwords | `identification_%26_authentication_failures_weak_passwords` |

Do not build slugs by hand for the long names. Read `categories.json` and URL-encode the `slug` field.

## 1. List categories

```bash
curl "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1/categories.json"
```

```python
import requests

base = "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1"
catalog = requests.get(f"{base}/categories.json", timeout=60).json()

for category in catalog["categories"]:
    print(category["count"], category["slug"], category["category"])
```

Each entry includes `count`, `pages`, `page_size`, `injection_points`, and `first_page`.

## 2. Read one category, page by page

```bash
curl "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1/categories/injection_sqli.json"
curl "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1/categories/injection_sqli/page/1.json"
```

```python
import requests
from urllib.parse import quote

base = "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1"

def api_url(path):
    return f"{base}/{quote(path, safe='/')}"

url = api_url("categories/injection_sqli/page/1.json")

while url:
    page = requests.get(url, timeout=60).json()
    for item in page["results"]:
        if item["injection_point"] != "query_parameter":
            continue
        print(item["payload_id"], item["payload_string"])
    url = api_url(page["next"]) if page["next"] else None
```

`injection_sqli` has 7,885 payloads across 8 pages. Stop when `next` is `null`.

The same loop in JavaScript:

```javascript
const base = "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1";
let path = "categories/injection_xss/page/1.json";

while (path) {
  const page = await fetch(`${base}/${path}`).then((response) => {
    if (!response.ok) throw new Error(`${response.status} ${path}`);
    return response.json();
  });
  for (const item of page.results) {
    console.log(item.payload_id, item.payload_string);
  }
  path = page.next;
}
```

## 3. Keep only one injection point

Pages mix injection points. Filter `results` after download.

```python
def payloads_for(slug, injection_point):
    from urllib.parse import quote
    import requests

    base = "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1"

    def api_url(path):
        return f"{base}/{quote(path, safe='/')}"

    url = api_url(f"categories/{slug}/page/1.json")
    found = []
    while url:
        page = requests.get(url, timeout=60).json()
        found.extend(
            item["payload_string"]
            for item in page["results"]
            if item["injection_point"] == injection_point
        )
        url = api_url(page["next"]) if page["next"] else None
    return found
```

To avoid downloading pages that contain none of that injection point, read `categories/{slug}.json` first. Its `injection_points` array tells you whether that point exists and how many strings it has. The strings themselves are still inside the shared category pages.

## 4. Look up one payload id

Divide the number in the id by 100000. That integer is the bucket file.

| Payload id | Bucket file |
|---|---|
| `OWP-0055` | `id-map/0.json` |
| `OWP-210845` | `id-map/2.json` |
| `OWP-392921` | `id-map/3.json` |

```python
import requests

base = "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1"
payload_id = "OWP-0055"
bucket = int(payload_id.split("-")[1]) // 100000

slug, page_no = requests.get(f"{base}/id-map/{bucket}.json", timeout=60).json()[payload_id]
page = requests.get(
    f"{base}/categories/{slug}/page/{page_no}.json",
    timeout=60,
).json()
record = next(item for item in page["results"] if item["payload_id"] == payload_id)
print(record["payload_string"])
```

The id map value is `[slug, page]`. Open that page and match `payload_id`. A missing id means the key is not in the bucket file.

Cache `id-map/0.json` and the other bucket files if you resolve many ids. Those files are the large downloads.

## 5. Call it from another service

```python
import requests
from urllib.parse import quote

class VeritasPayloads:
    def __init__(self):
        self.base = "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1"
        self.session = requests.Session()

    def url(self, path):
        return f"{self.base}/{quote(path, safe='/')}"

    def categories(self):
        return self.session.get(self.url("categories.json"), timeout=60).json()["categories"]

    def pages(self, slug):
        url = self.url(f"categories/{slug}/page/1.json")
        while url:
            page = self.session.get(url, timeout=60).json()
            yield from page["results"]
            url = self.url(page["next"]) if page["next"] else None

client = VeritasPayloads()
for payload in client.pages("injection_xss"):
    send_to_scanner(payload["payload_string"], payload["injection_point"])
```

Replace `send_to_scanner` with the call your system already uses. Send `payload_string` in the location named by `injection_point`. Compare the HTTP status with `validation.expected_status_code`, and the body with `validation.success_regex` when that field is not empty.

Set a timeout of at least 60 seconds. The first page of a large category is a few hundred kilobytes. `categories.json` and the id maps are larger.

## Category index

Counts are the full category, across every injection point.

| Category | Slug | Payloads | Pages |
|---|---|---:|---:|
| Identification & Authentication Failures (Weak Passwords) | `identification_&_authentication_failures_weak_passwords` | 78,776 | 79 |
| Injection (LFI/RFI) | `injection_lfi_rfi` | 54,180 | 55 |
| Injection (XSS) | `injection_xss` | 15,899 | 16 |
| Security Misconfiguration | `security_misconfiguration` | 12,353 | 13 |
| Injection (Command Injection) | `injection_command_injection` | 11,985 | 12 |
| Injection (SQLi) | `injection_sqli` | 7,885 | 8 |
| Injection (Unrestricted File Upload) | `injection_unrestricted_file_upload` | 6,131 | 7 |
| Injection (LDAP) | `injection_ldap` | 5,949 | 6 |
| Mishandling of Exceptional Conditions (Null/Type/Zero Errors) | `mishandling_of_exceptional_conditions_null_type_zero_errors` | 5,071 | 6 |
| Web Cache Deception | `web_cache_deception` | 4,583 | 5 |
| Identification & Authentication Failures (Weak Session IDs) | `identification_&_authentication_failures_weak_session_ids` | 4,465 | 5 |
| Insecure Design (Price Manipulation) | `insecure_design_price_manipulation` | 4,282 | 5 |
| Insecure Design | `insecure_design` | 4,144 | 5 |
| Injection (SSTI) | `injection_ssti` | 4,062 | 5 |
| Software & Data Integrity Failures (Deserialization) | `software_&_data_integrity_failures_deserialization` | 4,026 | 5 |
| Injection (CRLF) | `injection_crlf` | 3,915 | 4 |
| Injection (XXE) | `injection_xxe` | 3,850 | 4 |
| Cryptographic Failures | `cryptographic_failures` | 3,804 | 4 |
| Vulnerable & Outdated Components | `vulnerable_&_outdated_components` | 3,721 | 4 |
| Injection (SSI) | `injection_ssi` | 3,696 | 4 |
| Vulnerable & Outdated Components (CVE Paths) | `vulnerable_&_outdated_components_cve_paths` | 3,693 | 4 |
| Web Cache Deception (Cache Poisoning) | `web_cache_deception_cache_poisoning` | 3,680 | 4 |
| Insecure Design (Race Condition Tests) | `insecure_design_race_condition_tests` | 3,625 | 4 |
| Insecure Design (Coupon Abuse) | `insecure_design_coupon_abuse` | 3,618 | 4 |
| HTTP Parameter Pollution | `http_parameter_pollution` | 3,600 | 4 |
| Injection (CSV Injection) | `injection_csv_injection` | 3,593 | 4 |
| Software Supply Chain Failures | `software_supply_chain_failures` | 3,576 | 4 |
| Insecure Design (Race Condition) | `insecure_design_race_condition` | 3,525 | 4 |
| Security Logging & Monitoring Failures | `security_logging_&_monitoring_failures` | 3,519 | 4 |
| Mishandling of Exceptional Conditions (Error Info Disclosure) | `mishandling_of_exceptional_conditions_error_info_disclosure` | 3,515 | 4 |
| Mishandling of Exceptional Conditions (Missing/Extra Parameters) | `mishandling_of_exceptional_conditions_missing_extra_parameters` | 3,505 | 4 |
| Cryptographic Failures (Weak Crypto Algos) | `cryptographic_failures_weak_crypto_algos` | 3,487 | 4 |
| Injection (XPATH) | `injection_xpath` | 3,487 | 4 |
| Mishandling of Exceptional Conditions (Failing Open / Priv Esc) | `mishandling_of_exceptional_conditions_failing_open_priv_esc` | 3,485 | 4 |
| Mishandling of Exceptional Conditions (Debug Code Disclosure) | `mishandling_of_exceptional_conditions_debug_code_disclosure` | 3,481 | 4 |
| Mishandling of Exceptional Conditions (Unchecked Exceptions) | `mishandling_of_exceptional_conditions_unchecked_exceptions` | 3,479 | 4 |
| Vulnerable & Outdated Components (Vulnerable Versions) | `vulnerable_&_outdated_components_vulnerable_versions` | 3,473 | 4 |
| Cryptographic Failures (JWT None Alg) | `cryptographic_failures_jwt_none_alg` | 3,472 | 4 |
| Cryptographic Failures (Weak TLS Probes) | `cryptographic_failures_weak_tls_probes` | 3,466 | 4 |
| Cryptographic Failures (Info Disclosure Headers) | `cryptographic_failures_info_disclosure_headers` | 3,461 | 4 |
| Software Supply Chain Failures (Private Package Confusion) | `software_supply_chain_failures_private_package_confusion` | 2,220 | 3 |
| Identification & Authentication Failures (Username Enum) | `identification_&_authentication_failures_username_enum` | 2,046 | 3 |
| Injection (Open Redirect) | `injection_open_redirect` | 1,635 | 2 |
| Injection (SSRF) | `injection_ssrf` | 1,618 | 2 |
| Injection (NoSQLi) | `injection_nosqli` | 1,616 | 2 |
| Injection (Prototype Pollution) | `injection_prototype_pollution` | 1,427 | 2 |
| Identification & Authentication Failures | `identification_&_authentication_failures` | 1,371 | 2 |
| Injection (Format String) | `injection_format_string` | 1,356 | 2 |
| Broken Access Control | `broken_access_control` | 1,298 | 2 |
| Broken Access Control (IDOR) | `broken_access_control_idor` | 1,281 | 2 |
| Injection (GraphQL) | `injection_graphql` | 1,205 | 2 |
| Injection (DOM Clobbering) | `injection_dom_clobbering` | 1,192 | 2 |
| HTTP Parameter Pollution (Duplicate Params) | `http_parameter_pollution_duplicate_params` | 1,172 | 2 |
| Injection (LaTeX) | `injection_latex` | 1,149 | 2 |
| Injection (XSLT) | `injection_xslt` | 1,133 | 2 |
| Software Supply Chain Failures (Vuln Dependency Versions) | `software_supply_chain_failures_vuln_dependency_versions` | 1,116 | 2 |
| Insecure Design (Rate Limit Bypass) | `insecure_design_rate_limit_bypass` | 1,115 | 2 |
| Injection (SMTP) | `injection_smtp` | 1,104 | 2 |
| Injection (CSS Injection) | `injection_css_injection` | 1,099 | 2 |
| Injection (Request Smuggling) | `injection_request_smuggling` | 1,088 | 2 |
| Injection (Type Juggling) | `injection_type_juggling` | 1,087 | 2 |
| Mishandling of Exceptional Conditions (Missing Error Page) | `mishandling_of_exceptional_conditions_missing_error_page` | 1,050 | 2 |
| Security Logging & Monitoring Failures (Log Injection) | `security_logging_&_monitoring_failures_log_injection` | 1,037 | 2 |
| Web Cache Deception (Cache Poisoning Headers) | `web_cache_deception_cache_poisoning_headers` | 1,034 | 2 |
| Cryptographic Failures (JWT Kid Injection) | `cryptographic_failures_jwt_kid_injection` | 1,028 | 2 |

The table matches the live category pages. In the dataset files, three of those counts are already higher: LFI/RFI **54,205**, Security Misconfiguration **12,399**, and Identification & Authentication Failures **1,387**. Page counts do not change. Read `categories.json` at request time instead of copying this table into the other system.

## Daily updates

This repository checks the upstream wordlists every day at **02:00 Malaysia time** (18:00 UTC). The site clock counts down to that time. The job is GitHub Actions workflow `Sync upstream payloads`. GitHub may start it a little later than 02:00. GitHub Pages cannot run the job. Actions runs it, and a push to `master` is what publishes the new JSON.

A new string is kept only when it is a web-application payload and it is not already in the dataset. Percent-encoding dumps, shellcode, sticker notes, unresolved `{{placeholders}}`, and an exact copy of a stored string are skipped. Case is kept, so `<ScRiPt>` and `<script>` are different payloads.

Every run writes a row to `sync-log.json`, including a run that adds nothing. `runs[0]` is the newest run.

```text
https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1/sync-log.json
```

```json
{
  "dataset_total": 346081,
  "runs": [
    {
      "ran_at": "2026-11-07T01:32:08Z",
      "trigger": "workflow_dispatch",
      "added": 87,
      "skipped_non_web": 65549,
      "total_after": 346081,
      "sources": [
        {"name": "nuclei-templates", "added": 85},
        {"name": "commix", "added": 2}
      ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `added` | Web payloads kept on that run |
| `skipped_non_web` | Strings seen and dropped because they were not web payloads |
| `total_after` | Dataset total after that run |
| `sources` | Which upstream project the kept strings came from |

The site page **Sync Log** (`#sync`) reads the same file. You can also start a run from the Actions tab with **Run workflow**.

The 7 November run kept 87 web payloads and skipped 65,549 non-web strings. Those 87 are in the dataset and in this log. They are not in the paged category files yet.

### Cron on the other system

Run that job later than 02:00, after this repository has had time to push. **04:00 Asia/Kuala_Lumpur** (20:00 UTC) is a safe slot. The job only downloads when `master` has a new commit.

```bash
0 20 * * * cd /opt/veritas-consumer && git fetch origin master && git diff --quiet HEAD origin/master || git pull --ff-only origin master
```

If that system does not keep a git clone and only calls the HTTP API, it does not need a cron. The next GET to the raw URL returns whatever is on `master`. Use the raw base URL. The `github.io` copy can keep a previous file for a few minutes after a push.

To see whether a sync kept anything, without downloading the category pages:

```python
import requests

base = "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1"
latest = requests.get(f"{base}/sync-log.json", timeout=60).json()["runs"][0]
print(latest["ran_at"], "kept", latest["added"])
```

Download the category pages again only when `added` is greater than 0, or when `index.json` `total_payloads` has changed.

To refresh a saved copy of the API without cloning the whole repository:

```python
import json
import urllib.request
from pathlib import Path

REPO = "https://api.github.com/repos/HarlequinCS/Veritas_Payloads/commits/master"
STAMP = Path(".veritas-commit")

def sync_needed():
    with urllib.request.urlopen(REPO, timeout=60) as response:
        sha = json.load(response)["sha"]
    previous = STAMP.read_text(encoding="utf-8").strip() if STAMP.exists() else ""
    if sha == previous:
        return False
    STAMP.write_text(sha + "\n", encoding="utf-8")
    return True
```

When `sync_needed()` is true, download the category pages again from the base URL in this guide.

## Limits

- No authentication. Anyone who can reach the repository can read the files.
- No search parameter. Page through a category, or resolve one id through `id-map`.
- Page size is fixed at 1,000.
- Responses are JSON, not NDJSON.
- Browser pages on another domain can call `raw.githubusercontent.com`. Server-side clients do not need CORS.
- Use the payloads only against systems you are allowed to test.

Repository: [https://github.com/HarlequinCS/Veritas_Payloads](https://github.com/HarlequinCS/Veritas_Payloads)
