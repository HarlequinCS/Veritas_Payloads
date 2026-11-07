"""
Pull additional unique payload strings from the public sources already
listed for this dataset and append them to payloads/.

Checkouts live in _sources/ (gitignored). Existing entries are left byte-for-byte
intact; only new objects are appended. Payload strings already present are skipped.
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PAYLOADS = ROOT / "payloads"
SOURCES = ROOT / "_sources"
PY = sys.executable

MAX_LINE = 4000
MAX_FILE_BYTES = 25 * 1024 * 1024
WORDLIST_LINE_CAP = 80000
PASSWORD_LINE_CAP = 4000
NUCLEI_PER_FILE = 40
EXPLOIT_PER_FILE = 20
EXPLOIT_MAX_BYTES = 400_000

SKIP_DIRS = {
    ".git", ".github", "images", "img", "pictures", "assets", "node_modules",
    "__pycache__", "test", "tests",
}

OWASP = {
    "Broken Access Control": "A01",
    "Broken Access Control (IDOR)": "A01",
    "Security Misconfiguration": "A02",
    "Web Cache Deception": "A02",
    "Software Supply Chain Failures": "A03",
    "Vulnerable & Outdated Components": "A03",
    "Cryptographic Failures": "A04",
    "Injection (Command Injection)": "A05",
    "Injection (CRLF)": "A05",
    "Injection (CSS Injection)": "A05",
    "Injection (CSV Injection)": "A05",
    "Injection (DOM Clobbering)": "A05",
    "Injection (Format String)": "A05",
    "Injection (GraphQL)": "A05",
    "Injection (LFI/RFI)": "A05",
    "Injection (LDAP)": "A05",
    "Injection (LaTeX)": "A05",
    "Injection (NoSQLi)": "A05",
    "Injection (Open Redirect)": "A05",
    "Injection (Prototype Pollution)": "A05",
    "Injection (Request Smuggling)": "A05",
    "Injection (SMTP)": "A05",
    "Injection (SQLi)": "A05",
    "Injection (SSI)": "A05",
    "Injection (SSRF)": "A05",
    "Injection (SSTI)": "A05",
    "Injection (Type Juggling)": "A05",
    "Injection (Unrestricted File Upload)": "A05",
    "Injection (XPATH)": "A05",
    "Injection (XXE)": "A05",
    "Injection (XSLT)": "A05",
    "Injection (XSS)": "A05",
    "HTTP Parameter Pollution": "A05",
    "Insecure Design": "A06",
    "Identification & Authentication Failures": "A07",
    "Software & Data Integrity Failures (Deserialization)": "A08",
    "Security Logging & Monitoring Failures": "A09",
}

VALIDATION = {
    "Injection (SQLi)": (200, "sql|syntax|mysql|oracle|postgres|sqlite|odbc"),
    "Injection (XSS)": (200, "<script|onerror|onload|alert\\(|javascript:"),
    "Injection (LFI/RFI)": (200, "root:|boot\\.ini|\\[extensions\\]"),
    "Injection (Command Injection)": (200, "uid=|gid=|Microsoft Windows|Volume Serial"),
    "Injection (SSTI)": (200, "49|7777777"),
    "Injection (XXE)": (200, "root:|ENTITY|xml"),
    "Injection (SSRF)": (200, "ami-id|computeMetadata|meta-data|instance"),
    "Injection (NoSQLi)": (200, "MongoError|bson|\\$where|\\$gt"),
    "Injection (LDAP)": (200, "ldap|naming|exception"),
    "Injection (CRLF)": (200, "Set-Cookie|injected"),
    "Injection (Open Redirect)": (302, "^https?://"),
    "Injection (Prototype Pollution)": (200, "__proto__|constructor"),
    "Injection (CSV Injection)": (200, "^[=+\\-@]"),
    "Injection (SSI)": (200, "<!--#|date"),
    "Software & Data Integrity Failures (Deserialization)": (200, "unserialize|ObjectInputStream|pickle"),
    "Cryptographic Failures (JWT None Alg)": (200, "alg|none|kid"),
    "Broken Access Control (IDOR)": (200, "id|user"),
    "Identification & Authentication Failures": (200, "welcome|dashboard|invalid|login"),
    "Identification & Authentication Failures (Weak Passwords)": (200, "welcome|dashboard|success"),
    "Identification & Authentication Failures (Username Enum)": (200, "user|exist|invalid"),
    "Security Misconfiguration": (200, "Index of|exception|debug|server"),
    "Vulnerable & Outdated Components": (200, "version|Server:"),
    "Vulnerable & Outdated Components (CVE Paths)": (200, "version|vulnerable"),
    "Mishandling of Exceptional Conditions (Null/Type/Zero Errors)": (500, "exception|error|type"),
    "Insecure Design": (200, ""),
    "Insecure Design (Race Condition)": (200, ""),
    "Web Cache Deception": (200, ""),
    "Web Cache Deception (Cache Poisoning)": (200, ""),
    "HTTP Parameter Pollution": (200, ""),
    "Injection (GraphQL)": (200, "errors|data"),
    "Injection (Request Smuggling)": (200, ""),
    "Injection (Unrestricted File Upload)": (200, ""),
    "Injection (Format String)": (200, "%[0-9]*[xspn]"),
    "Injection (XPATH)": (200, "xpath|xml"),
    "Injection (XSLT)": (200, "xslt|xml"),
    "Security Logging & Monitoring Failures": (200, ""),
    "Security Logging & Monitoring Failures (Log Injection)": (200, ""),
    "Cryptographic Failures": (200, ""),
    "Broken Access Control": (200, ""),
    "Software Supply Chain Failures": (200, ""),
    "Software Supply Chain Failures (Private Package Confusion)": (200, ""),
}

TECH_RULES = [
    (re.compile(r"mysql|information_schema|\bsleep\s*\(|\bbenchmark\s*\(", re.I), "MySQL"),
    (re.compile(r"pg_sleep|postgres", re.I), "PostgreSQL"),
    (re.compile(r"dbms_pipe|utl_inaddr|\boracle\b", re.I), "Oracle"),
    (re.compile(r"waitfor\s+delay|xp_cmdshell|\bmssql\b", re.I), "MSSQL"),
    (re.compile(r"sqlite_version|\bsqlite\b", re.I), "SQLite"),
    (re.compile(r"\$where|\$gt|\$ne|mongodb", re.I), "MongoDB"),
    (re.compile(r"jinja|\{\{\s*7\s*\*\s*7\s*\}\}", re.I), "Jinja2"),
    (re.compile(r"\btwig\b", re.I), "Twig"),
    (re.compile(r"freemarker", re.I), "FreeMarker"),
    (re.compile(r"\bjwt\b|^eyJ", re.I), "JWT"),
    (re.compile(r"graphql", re.I), "GraphQL"),
    (re.compile(r"wp-content|wordpress", re.I), "WordPress"),
    (re.compile(r"cmd\.exe|powershell|win\.ini", re.I), "Windows"),
    (re.compile(r"/etc/passwd|/bin/sh", re.I), "Linux"),
]

DOC_HOSTS = (
    "github.com", "wikipedia.org", "owasp.org", "developer.mozilla.org",
    "docs.microsoft.com", "learn.microsoft.com", "portswigger.net/web-security",
)

ATTACK_HINT = re.compile(
    r"(<\s*script|</|union\s+select|\.\./|%2e%2e|/etc/passwd|%00|"
    r"sleep\s*\(|onerror\s*=|onload\s*=|javascript:|file://|gopher://|php://|data://|"
    r"<\?xml|<!DOCTYPE|\$\{jndi|__proto__|;\s*(id|whoami|cat|ls)\b|`id`|\|\s*id\b|"
    r"alert\s*\(|\bor\b\s+['\"]?1['\"]?\s*=|%0d%0a|%0a|\\r\\n)",
    re.I,
)

QUOTED_LINE_RE = re.compile(r"""['\"]([^'\"\r\n]{2,400})['\"]""")


def sanitize_filename(name: str) -> str:
    result = (
        name.replace("/", "_").replace("\\", "_").replace(":", "_")
        .replace("*", "_").replace("?", "_").replace('"', "_")
        .replace("<", "_").replace(">", "_").replace("|", "_")
        .replace(" ", "_").lower()
    )
    while "__" in result:
        result = result.replace("__", "_")
    return result.strip("_")


def bounded(path: str, token: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", path) is not None


def classify(path: str) -> str | None:
    p = path.replace("\\", "/").lower()
    if any(part in p for part in (
        "prompt-injection", "prompt injection",
        "denial of service", "denial-of-service",
        "regular expression", "user-agents", "user-agent",
        "methodology and resources",
    )):
        return None
    if any(x in p for x in ("/passwords/", "common-credentials", "default-credentials", "default_credentials")):
        if "username" in p and "password" not in p and "credential" not in p:
            return "Identification & Authentication Failures (Username Enum)"
        return "Identification & Authentication Failures (Weak Passwords)"
    if "naughty" in p or "blns" in p:
        return "Mishandling of Exceptional Conditions (Null/Type/Zero Errors)"

    rules: list[tuple] = [
        (lambda s: "nosql" in s or "no-sql" in s or "no_sql" in s, "Injection (NoSQLi)"),
        (lambda s: "prototype" in s, "Injection (Prototype Pollution)"),
        (lambda s: "ssti" in s or "template-injection" in s or "template injection" in s or "template-engine" in s or "server-side-template" in s or "server side template" in s, "Injection (SSTI)"),
        (lambda s: "server-side-include" in s or "server side include" in s or "ssi-injection" in s or bounded(s, "ssi"), "Injection (SSI)"),
        (lambda s: "xxe" in s or "xml-external" in s or "xml external" in s or "/attack/xml/" in s, "Injection (XXE)"),
        (lambda s: "ssrf" in s or "server-side-request" in s or "server side request" in s or "dns-rebind" in s or "dns rebind" in s or "curl-protocol" in s, "Injection (SSRF)"),
        (lambda s: "xss" in s or "cross-site-scripting" in s or "cross-site scripting" in s or "cross site scripting" in s or "html_js" in s or "html5sec" in s, "Injection (XSS)"),
        (lambda s: "sqli" in s or "sql-injection" in s or "sql injection" in s or "/sql/" in s or bounded(s, "sql"), "Injection (SQLi)"),
        (lambda s: "command-injection" in s or "command injection" in s or "os-cmd" in s or "cmd-injection" in s or "shellshock" in s or "commix" in s or "unixattack" in s or "windows-attack" in s, "Injection (Command Injection)"),
        (lambda s: "lfi" in s or "rfi" in s or "file-inclusion" in s or "file inclusion" in s or "directory-traversal" in s or "directory traversal" in s or "path-traversal" in s or "path traversal" in s or "dotdot" in s or "traversal" in s, "Injection (LFI/RFI)"),
        (lambda s: "crlf" in s or "response-split" in s or "response splitting" in s or "/http-protocol/" in s, "Injection (CRLF)"),
        (lambda s: "open-redirect" in s or "open redirect" in s or "/redirect" in s or "redirect" in s, "Injection (Open Redirect)"),
        (lambda s: "ldap" in s, "Injection (LDAP)"),
        (lambda s: "xpath" in s, "Injection (XPATH)"),
        (lambda s: "xslt" in s, "Injection (XSLT)"),
        (lambda s: "csv-injection" in s or "csv injection" in s or "/csv" in s or bounded(s, "csv"), "Injection (CSV Injection)"),
        (lambda s: "css-injection" in s or "css injection" in s, "Injection (CSS Injection)"),
        (lambda s: "dom-clobber" in s or "dom clobber" in s or "domclobber" in s, "Injection (DOM Clobbering)"),
        (lambda s: "graphql" in s, "Injection (GraphQL)"),
        (lambda s: "parameter-pollution" in s or "parameter pollution" in s or bounded(s, "hpp"), "HTTP Parameter Pollution"),
        (lambda s: "latex" in s, "Injection (LaTeX)"),
        (lambda s: "type-juggl" in s or "type juggl" in s or "magic-hash" in s or "magic_hash" in s or "typejuggl" in s, "Injection (Type Juggling)"),
        (lambda s: "smuggling" in s, "Injection (Request Smuggling)"),
        (lambda s: bounded(s, "smtp") or "smtp-injection" in s or "smtp injection" in s, "Injection (SMTP)"),
        (lambda s: "format-string" in s or "format string" in s or "formatstring" in s, "Injection (Format String)"),
        (lambda s: "deserial" in s or "pickle" in s or "ysoserial" in s or "unserialize" in s or "java-class" in s or "java rmi" in s or "magic-method" in s or "magic_method" in s, "Software & Data Integrity Failures (Deserialization)"),
        (lambda s: "jwt" in s or "/jwk" in s or "json web token" in s or "json-web-token" in s, "Cryptographic Failures (JWT None Alg)"),
        (lambda s: "idor" in s or "insecure-direct" in s or "insecure direct" in s, "Broken Access Control (IDOR)"),
        (lambda s: "race-condition" in s or "race condition" in s, "Insecure Design (Race Condition)"),
        (lambda s: "cache-poison" in s or "cache poison" in s, "Web Cache Deception (Cache Poisoning)"),
        (lambda s: "cache-deception" in s or "cache deception" in s or "web-cache" in s or "web cache" in s, "Web Cache Deception"),
        (lambda s: "cors" in s, "Security Misconfiguration"),
        (lambda s: "dependency-confusion" in s or "dependency confusion" in s or "package-confusion" in s, "Software Supply Chain Failures (Private Package Confusion)"),
        (lambda s: "supply-chain" in s or "supply chain" in s, "Software Supply Chain Failures"),
        (lambda s: "rate limit" in s or "rate-limit" in s, "Insecure Design (Rate Limit Bypass)"),
        (lambda s: "/amounts/" in s or "price-manipulation" in s or "price manipulation" in s, "Insecure Design (Price Manipulation)"),
        (lambda s: "mass-assignment" in s or "mass assignment" in s or "business-logic" in s or "business logic" in s or "external variable" in s, "Insecure Design"),
        (lambda s: "file-upload" in s or "file upload" in s or "unrestricted-upload" in s or "/upload" in s or "mimetype" in s or "file-extension" in s or "extensions-" in s, "Injection (Unrestricted File Upload)"),
        (lambda s: "log-injection" in s or "log injection" in s or "log-forging" in s, "Security Logging & Monitoring Failures (Log Injection)"),
        (lambda s: "account-takeover" in s or "account takeover" in s or "oauth" in s or "default-login" in s or "auth-bypass" in s or "authentication" in s or "login_bypass" in s or "login-bypass" in s or "saml" in s, "Identification & Authentication Failures"),
        (lambda s: "integer-overflow" in s or "control-char" in s or "special-char" in s or "metacharacter" in s or "fuzz-bo0om" in s or "fuzzingstrings" in s or "json.fuzz" in s or bounded(s, "unicode"), "Mishandling of Exceptional Conditions (Null/Type/Zero Errors)"),
        (lambda s: "/cves/" in s or "cve-" in s or "cve exploits" in s, "Vulnerable & Outdated Components (CVE Paths)"),
        (lambda s: "misconfig" in s or "/exposures/" in s or "hidden-parameter" in s or "hidden parameter" in s or "clickjacking" in s or "api key" in s or "management interface" in s or "source code management" in s or "virtual host" in s or "reverse proxy" in s or "environment-identifier" in s or "xs-leak" in s or "xs leak" in s, "Security Misconfiguration"),
        (lambda s: "access-control" in s or "access control" in s or "privilege" in s or "/403/" in s or "\\403\\" in s, "Broken Access Control"),
        (lambda s: bounded(s, "csrf"), "Broken Access Control"),
        (lambda s: "polyglot" in s or "headless browser" in s or "encoding transformation" in s or "google web toolkit" in s, "Injection (XSS)"),
        (lambda s: "zip slip" in s or "zip-slip" in s, "Injection (LFI/RFI)"),
        (lambda s: "randomness" in s, "Cryptographic Failures"),
        (lambda s: "xml-fuzz" in s or "xml.fuzz" in s, "Injection (XXE)"),
    ]
    for pred, cat in rules:
        if pred(p):
            return cat
    return None


def classify_text(text: str) -> str | None:
    return classify(text.lower())


def technology(payload: str) -> str:
    for pattern, name in TECH_RULES:
        if pattern.search(payload):
            return name
    return "Generic"


def injection_point(payload: str, category: str) -> str:
    p = payload.strip()
    low = p.lower()
    if low.startswith((
        "user-agent:", "x-", "cookie:", "referer:", "origin:", "authorization:",
        "content-type:", "transfer-encoding:", "accept:", "cache-control:",
        "metadata:", "metadata-flavor:", "x-forwarded", "x-original", "x-rewrite",
        "x-host", "x-custom", "forwarded:",
    )):
        return "header"
    if p.startswith("<?xml") or p.startswith("<!DOCTYPE") or p.startswith("<!doctype") or p.startswith("<xsl") or category in ("Injection (XXE)", "Injection (XSLT)"):
        if p.startswith("<") or p.startswith("<?"):
            return "body_xml"
    if p[:1] in "{[":
        return "body_json"
    if category == "Injection (Unrestricted File Upload)":
        if p.startswith("/") or p.startswith(".."):
            return "path_parameter"
        return "file_upload"
    if p.startswith("/") or p.startswith("..") or p.startswith("....") or "%2e%2e" in low or "..\\" in p:
        return "path_parameter"
    if category in ("Injection (CSV Injection)",) and p[:1] in "=+-@":
        return "form_parameter"
    if re.match(r"^[A-Za-z0-9_%.\-]+=\S", p) and " " not in p and not p.startswith("/"):
        return "form_parameter"
    return "query_parameter"


def quoted_fragments(text: str):
    for line in text.splitlines():
        if len(line) < 2 or len(line) > 1500:
            continue
        for match in QUOTED_LINE_RE.finditer(line):
            yield match.group(1)


def looks_like_prose(s: str) -> bool:
    words = s.split()
    if len(words) > 14 and not any(c in s for c in "<>'\"`${}|\\;()[]*%#&="):
        return True
    return False


def is_doc_url(s: str) -> bool:
    stripped = s.strip()
    if not re.match(r"https?://\S+$", stripped):
        return False
    low = stripped.lower()
    return any(host in low for host in DOC_HOSTS)


def usable(s: str) -> bool:
    if not s or not s.strip():
        return False
    if len(s) > MAX_LINE or len(s.strip()) < 1:
        return False
    if re.fullmatch(r"\{\{[^}]+\}\}", s.strip()):
        return False
    if re.fullmatch(r"[A-Za-z0-9+/=]{80,}", s.strip()):
        return False
    if re.fullmatch(r"[a-fA-F0-9]{32,128}", s.strip()):
        return False
    low = s.strip().lower()
    if low.startswith(("<?php", "<%", "#!/")) and len(s) > 180:
        return False
    if s.strip() in {"*", "*/", "/*", "{", "}", "[", "]", "---", "...", "```", "FUZZ"}:
        return False
    if looks_like_prose(s):
        return False
    if is_doc_url(s):
        return False
    if re.match(r"^(git |pip[0-9]? |npm |cd |curl |wget |sudo |python3? |gem |docker |cd\s)", s.strip()):
        return False
    return True


def normalize_nuclei(s: str) -> str:
    repls = {
        "{{randstr}}": "veritas",
        "{{rand_int}}": "1337",
        "{{rand_base(6)}}": "abc123",
        "{{interactsh-url}}": "example.invalid",
        "{{Hostname}}": "localhost",
        "{{BaseURL}}": "",
        "{{RootURL}}": "",
        "{{url}}": "",
    }
    for a, b in repls.items():
        s = s.replace(a, b)
    return s.strip().strip('"').strip("'").rstrip(",")


CLOUD_PAYLOADS = [
    ("Injection (SSRF)", "http://169.254.169.254/latest/meta-data/"),
    ("Injection (SSRF)", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("Injection (SSRF)", "http://169.254.169.254/latest/user-data"),
    ("Injection (SSRF)", "http://169.254.169.254/latest/dynamic/instance-identity/document"),
    ("Injection (SSRF)", "http://[fd00:ec2::254]/latest/meta-data/"),
    ("Injection (SSRF)", "http://169.254.170.2/v2/credentials/"),
    ("Injection (SSRF)", "http://169.254.170.2/v2/metadata"),
    ("Injection (SSRF)", "http://metadata.google.internal/computeMetadata/v1/"),
    ("Injection (SSRF)", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("Injection (SSRF)", "http://169.254.169.254/computeMetadata/v1/"),
    ("Injection (SSRF)", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("Injection (SSRF)", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ("Injection (SSRF)", "http://100.100.100.200/latest/meta-data/"),
    ("Injection (SSRF)", "http://100.100.100.200/latest/meta-data/ram/security-credentials/"),
    ("Injection (SSRF)", "http://169.254.169.254/metadata/v1/"),
    ("Injection (SSRF)", "http://169.254.169.254/metadata/v1.json"),
    ("Injection (SSRF)", "http://169.254.169.254/openstack/latest/meta_data.json"),
    ("Injection (SSRF)", "http://169.254.169.254/openstack/latest/user_data"),
    ("Injection (SSRF)", "http://169.254.169.254/opc/v1/instance/"),
    ("Injection (SSRF)", "http://169.254.169.254/opc/v2/instance/"),
    ("Injection (SSRF)", "http://169.254.169.254/opc/v2/instance/metadata/"),
    ("Injection (SSRF)", "http://169.254.169.254/latest/meta-data/placement/availability-zone"),
    ("Injection (SSRF)", "http://169.254.169.254/latest/meta-data/hostname"),
    ("Injection (SSRF)", "http://169.254.169.254/latest/meta-data/public-keys/"),
    ("Injection (SSRF)", "http://metadata.tencentyun.com/latest/meta-data/"),
    ("Injection (SSRF)", "http://169.254.169.254/metadata/instance/compute?api-version=2021-01-01"),
    ("Injection (LFI/RFI)", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
    ("Injection (LFI/RFI)", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
    ("Injection (LFI/RFI)", "/var/run/secrets/kubernetes.io/serviceaccount/namespace"),
    ("Injection (LFI/RFI)", "/proc/1/root/var/run/secrets/kubernetes.io/serviceaccount/token"),
    ("Injection (LFI/RFI)", "/run/secrets/kubernetes.io/serviceaccount/token"),
    ("Injection (SSRF)", "Metadata-Flavor: Google"),
    ("Injection (SSRF)", "Metadata: true"),
    ("Injection (SSRF)", "X-aws-ec2-metadata-token-ttl-seconds: 21600"),
]


class Builder:
    def __init__(self) -> None:
        self.seen: set[str] = set()
        self.max_id = 0
        self.meta: dict[tuple[str, str], dict] = {}
        self.new_items: dict[tuple[str, str], list] = defaultdict(list)
        self.added_by_source: dict[str, int] = defaultdict(int)
        self.skipped_files: list[tuple[str, int]] = []
        self.source = ""

    def load_existing(self) -> None:
        files = [p for p in PAYLOADS.rglob("*.json") if p.name != "_manifest.json"]
        print(f"Indexing {len(files)} existing payload files...", flush=True)
        for path in files:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            rel = path.relative_to(PAYLOADS).as_posix()
            for entry in data:
                raw = entry.get("payload_string")
                if isinstance(raw, str):
                    self.seen.add(raw)
                pid = str(entry.get("payload_id", ""))
                match = re.search(r"(\d+)$", pid)
                if match:
                    self.max_id = max(self.max_id, int(match.group(1)))
                key = (entry["vulnerability_category"], entry["injection_point"])
                slot = self.meta.get(key)
                if slot is None:
                    self.meta[key] = {"count": 0, "rel": rel}
                elif slot["rel"] != rel:
                    # Same category/point must live in one file. Keep the first.
                    pass
            if data:
                key = (data[0]["vulnerability_category"], data[0]["injection_point"])
                self.meta[key]["count"] = len(data)
                self.meta[key]["rel"] = rel
            del data
        print(f"  existing strings: {len(self.seen):,}  next id after OWP-{self.max_id}", flush=True)

    def add(self, category: str, payload: str) -> bool:
        if category is None or not usable(payload):
            return False
        if payload in self.seen:
            return False
        point = injection_point(payload, category)
        key = (category, point)
        if key not in self.meta:
            folder = sanitize_filename(category)
            fname = sanitize_filename(point) + ".json"
            self.meta[key] = {"count": 0, "rel": f"{folder}/{fname}"}
        code, regex = VALIDATION.get(category, (200, ""))
        self.max_id += 1
        number = self.max_id
        payload_id = f"OWP-{number:04d}" if number < 10000 else f"OWP-{number}"
        entry = {
            "payload_id": payload_id,
            "vulnerability_category": category,
            "target_technology": technology(payload),
            "injection_point": point,
            "payload_string": payload,
            "validation": {
                "expected_status_code": code,
                "success_regex": regex,
            },
        }
        self.new_items[key].append(entry)
        self.meta[key]["count"] += 1
        self.seen.add(payload)
        self.added_by_source[self.source] += 1
        return True

    def consider_line(self, line: str, category: str | None, from_markdown: bool = False) -> None:
        if category is None:
            return
        if from_markdown:
            line = line.strip()
        else:
            line = line.rstrip("\r\n").rstrip(" \t")
        if not line or line.lstrip().startswith(("//", "/*", "*")):
            return
        stripped = line.lstrip()
        if stripped.startswith("#") and not any(c in stripped for c in "<>'\"`${}|\\;()[]%="):
            return
        self.add(category, line)

    def flush(self) -> int:
        total = 0
        for key, entries in self.new_items.items():
            rel = self.meta[key]["rel"]
            path = PAYLOADS / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.stat().st_size > 0:
                _append_json_array(path, entries)
            else:
                text = json.dumps(entries, indent=2, ensure_ascii=False) + "\n"
                path.write_text(text, encoding="utf-8", newline="\n")
            total += len(entries)
            print(f"  +{len(entries):>6}  {rel}", flush=True)
        if total:
            self._write_manifest()
        return total

    def _write_manifest(self) -> None:
        categories: dict[str, dict] = {}
        for (cat, point), slot in self.meta.items():
            bucket = categories.setdefault(cat, {"files": {}})
            bucket["files"][point] = {"file": slot["rel"], "count": slot["count"]}
        summary_cats = {}
        for cat in sorted(categories):
            files = categories[cat]["files"]
            folder = sanitize_filename(cat)
            summary_cats[cat] = {
                "folder": folder,
                "total": sum(item["count"] for item in files.values()),
                "files": {point: files[point] for point in sorted(files)},
            }
        total_payloads = sum(cat["total"] for cat in summary_cats.values())
        total_files = sum(len(cat["files"]) for cat in summary_cats.values())
        summary = {
            "total_payloads": total_payloads,
            "total_categories": len(summary_cats),
            "total_files": total_files,
            "categories": summary_cats,
        }
        manifest = PAYLOADS / "_manifest.json"
        manifest.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        print(f"\nManifest: {total_payloads:,} payloads, {len(summary_cats)} categories, {total_files} files", flush=True)


def _append_json_array(path: Path, entries: list) -> None:
    data = path.read_bytes()
    nl = b"\r\n" if b"\r\n" in data[:800] else b"\n"
    stripped = data.rstrip()
    if not stripped.endswith(b"]"):
        raise SystemExit(f"Refusing to append to non-array JSON: {path}")
    inner = stripped[:-1].rstrip()
    encoded = []
    for entry in entries:
        obj = json.dumps(entry, indent=2, ensure_ascii=False)
        indented = "\n".join("  " + line for line in obj.split("\n"))
        if nl == b"\r\n":
            indented = indented.replace("\n", "\r\n")
        encoded.append(indented.encode("utf-8"))
    blob = (b"," + nl).join(encoded)
    if inner.endswith(b"["):
        out = b"[" + nl + blob + nl + b"]" + nl
    else:
        out = inner + b"," + nl + blob + nl + b"]" + nl
    path.write_bytes(out)


def _skip_dir(name: str) -> bool:
    low = name.lower()
    if low.startswith(".") or low in SKIP_DIRS:
        return True
    return low in {
        "denial of service", "prompt injection", "regular expression",
        "user-agents", "methodology and resources", "_learning_and_socials",
        "_template_vuln",
    }


def _interesting_file(path: Path) -> bool:
    name = path.name.lower()
    if name in {"license", "license.md", "notice", "authors", "changelog.md", "contributing.md"}:
        return False
    if any(part in name for part in ("user-agent", "useragent", "rockyou")):
        return False
    if re.search(r"(\d-digits-|all_letters|regional_|os-names|email-top|country-code)", name):
        return False
    ext = path.suffix.lower()
    if ext in {
        ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".7z", ".exe", ".dll",
        ".so", ".class", ".jar", ".svg", ".woff", ".mp4", ".pyc", ".webp", ".ico",
        ".bin", ".pcap", ".docx", ".xlsx", ".swf", ".wasm", ".psd", ".tif", ".gifv",
    }:
        return False
    if ext in {".txt", ".lst", ".fuzz", ".wordlist", ".payload", ".dic", ".dict", ".md", ".csv"}:
        return True
    if ext == "" and any(part.lower() in {"intruder", "intruders", "wordlists", "payloads", "lists"} for part in path.parts):
        return True
    return False


def _binary(path: Path) -> bool:
    with path.open("rb") as handle:
        chunk = handle.read(2048)
    return b"\x00" in chunk


def walk_wordlists(builder: Builder, root: Path, forced: str | None = None) -> None:
    if not root.exists():
        print(f"  skip missing {root}", flush=True)
        return
    files = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        for filename in filenames:
            path = Path(dirpath) / filename
            if not _interesting_file(path):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            low_path = str(path).lower()
            password_file = "password" in low_path or "credential" in low_path
            if size == 0 or (size > MAX_FILE_BYTES and not password_file):
                continue
            if _binary(path):
                continue
            rel = path.relative_to(root).as_posix()
            category = forced or classify(str(path))
            if category is None:
                builder.skipped_files.append((str(path), size))
                continue
            files += 1
            cap = PASSWORD_LINE_CAP if "Weak Passwords" in category or "Username Enum" in category else WORDLIST_LINE_CAP
            try:
                text_lines = _read_lines(path, cap, markdown=path.suffix.lower() == ".md")
            except OSError:
                continue
            if path.suffix.lower() == ".md":
                for line in _markdown_lines(text_lines):
                    builder.consider_line(line, category, from_markdown=True)
            else:
                header = True
                for line in text_lines:
                    if header and path.suffix.lower() == ".csv" and line.lower().startswith(("payload", "name,", "string,")):
                        header = False
                        continue
                    header = False
                    builder.consider_line(line, category, from_markdown=False)
    print(f"  classified files: {files}", flush=True)


def _read_lines(path: Path, cap: int, markdown: bool) -> list[str]:
    lines = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for i, line in enumerate(handle):
            if i >= cap:
                break
            lines.append(line)
    return lines


def _markdown_lines(lines: list[str]) -> list[str]:
    text = "".join(lines)
    out = []
    for block in re.findall(r"```[^\n]*\n(.*?)```", text, flags=re.S):
        out.extend(block.splitlines())
    return out


def walk_nuclei(builder: Builder, root: Path) -> None:
    if not root.exists():
        print(f"  skip missing {root}", flush=True)
        return
    count_files = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        for filename in filenames:
            if not filename.endswith((".yaml", ".yml")):
                continue
            path = Path(dirpath) / filename
            try:
                if path.stat().st_size > 400_000:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(path)
            tags = ""
            tag_match = re.search(r"(?mi)^tags:\s*(.+)$", text)
            if tag_match:
                tags = tag_match.group(1)
            if re.search(r"(?i)(^|[^a-z])(dos|redos|denial-of-service)([^a-z]|$)", tags) or "/dos/" in rel.lower():
                continue
            category = classify(tags) or classify(rel) or _nuclei_fallback(rel, text)
            if category is None:
                continue
            count_files += 1
            taken = 0
            for payload in _nuclei_payloads(text):
                if taken >= NUCLEI_PER_FILE:
                    break
                if builder.add(category, payload):
                    taken += 1
    print(f"  template files read: {count_files}", flush=True)


def _nuclei_fallback(rel: str, text: str) -> str | None:
    low = (rel + "\n" + text[:1500]).lower()
    tagged = classify(low)
    if tagged:
        return tagged
    if "/cves/" in rel.lower() or "cve-" in rel.lower():
        return "Vulnerable & Outdated Components (CVE Paths)"
    if "/exposures/" in rel.lower() or "/misconfiguration/" in rel.lower():
        return "Security Misconfiguration"
    if "default-login" in rel.lower():
        return "Identification & Authentication Failures"
    return "Vulnerable & Outdated Components"


def _nuclei_payloads(text: str) -> list[str]:
    found: list[str] = []
    seen_local = set()

    def push(raw: str) -> None:
        value = normalize_nuclei(raw)
        if not value or value in seen_local:
            return
        if value in {"/", "?", "localhost"}:
            return
        seen_local.add(value)
        found.append(value)

    for match in re.finditer(r"\{\{(?:BaseURL|RootURL|Hostname)\}\}([^\s\"'<>]{1,300})", text):
        push(match.group(1))
    for match in re.finditer(r"(?m)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/", text):
        target = normalize_nuclei(match.group(2))
        if target.startswith("/") or target.startswith("?"):
            push(target)
    for match in re.finditer(r"(?m)^\s*-\s+[\"'](/[^\"'\n]{1,300})[\"']", text):
        push(match.group(1))
    for match in re.finditer(
        r"(?m)^((?:X-[A-Za-z0-9\-]+|Cookie|Referer|Origin|Authorization|Metadata|Metadata-Flavor|Transfer-Encoding|Content-Type):\s*\S[^\n]{0,240})$",
        text,
    ):
        push(match.group(1).strip())
    return found


def walk_sqlmap(builder: Builder, root: Path) -> None:
    xml_root = root / "data" / "xml"
    if not xml_root.exists():
        print(f"  skip missing {xml_root}", flush=True)
        return
    files = 0
    for path in xml_root.rglob("*.xml"):
        files += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        values = re.findall(r"<vector>(.*?)</vector>", text, flags=re.S)
        values += re.findall(r"<payload>(.*?)</payload>", text, flags=re.S)
        if "boundaries" in path.name:
            values += re.findall(r"<prefix>(.*?)</prefix>", text, flags=re.S)
            values += re.findall(r"<suffix>(.*?)</suffix>", text, flags=re.S)
        for raw in values:
            value = html.unescape(re.sub(r"\s+", " ", raw)).strip()
            if re.fullmatch(r"(\[[A-Z0-9_]+\]\s*)+", value or ""):
                continue
            builder.add("Injection (SQLi)", value)
    print(f"  xml files read: {files}", flush=True)


def walk_commix_modules(builder: Builder, root: Path) -> None:
    if not root.exists():
        print(f"  skip missing {root}", flush=True)
        return
    files = 0
    for path in root.rglob("*.py"):
        if "payload" not in path.as_posix().lower():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files += 1
        for raw in quoted_fragments(text):
            raw = raw.strip()
            for token in ("{payload}", "{cmd}", "[PAYLOAD]", "INJECT_HERE"):
                raw = raw.replace(token, "id")
            if not any(tok in raw for tok in (";", "|", "&", "`", "$(", "%0a", "\n")):
                continue
            if raw.startswith(("import ", "def ", "class ", "return ", "self.", "from ")):
                continue
            builder.add("Injection (Command Injection)", raw)
    mapping = {
        "common-files.txt": "Injection (LFI/RFI)",
        "shocker-cgi_list.txt": "Injection (Command Injection)",
        "default_passwords.txt": "Identification & Authentication Failures (Weak Passwords)",
        "default_usernames.txt": "Identification & Authentication Failures (Username Enum)",
        "common-parameters.txt": "Security Misconfiguration",
    }
    data = root / "data" / "txt"
    if data.exists():
        for name, category in mapping.items():
            path = data / name
            if not path.exists():
                continue
            files += 1
            cap = PASSWORD_LINE_CAP if "Password" in category or "Username" in category else WORDLIST_LINE_CAP
            try:
                lines = _read_lines(path, cap, markdown=False)
            except OSError:
                continue
            for line in lines:
                builder.consider_line(line, category, from_markdown=False)
    print(f"  commix payload files read: {files}", flush=True)


def walk_exploits(builder: Builder, root: Path) -> None:
    exploits = root / "exploits"
    if not exploits.exists():
        print(f"  skip missing {exploits}", flush=True)
        return
    files = 0
    for dirpath, dirnames, filenames in os.walk(exploits):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() not in {".php", ".asp", ".aspx", ".jsp", ".txt", ".pl", ".py", ".rb", ".cfm"}:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size == 0 or size > EXPLOIT_MAX_BYTES:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files += 1
            if files % 4000 == 0:
                print(f"  ...{files} exploit files", flush=True)
            taken = 0
            path_cat = classify(str(path))
            for raw in quoted_fragments(text):
                if taken >= EXPLOIT_PER_FILE:
                    break
                raw = raw.replace("\x00", "").strip()
                if not ATTACK_HINT.search(raw):
                    continue
                category = path_cat or classify_text(raw)
                if category and builder.add(category, raw):
                    taken += 1
    print(f"  exploit files read: {files}", flush=True)


def fetch_portswigger(builder: Builder) -> None:
    url = "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
    req = urllib.request.Request(url, headers={"User-Agent": "VeritasDatasetResearch/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=40) as response:
            body = response.read().decode("utf-8", errors="replace")
    except Exception as exc:
        print(f"  portswigger fetch failed: {exc}", flush=True)
        return
    chunks = re.findall(r"<code[^>]*>(.*?)</code>", body, flags=re.S | re.I)
    chunks += re.findall(r"<td[^>]*>(.*?)</td>", body, flags=re.S | re.I)
    added_here = 0
    for chunk in chunks:
        text = re.sub(r"<[^>]+>", "", chunk)
        text = html.unescape(text).strip()
        if not text or len(text) > 800:
            continue
        if ATTACK_HINT.search(text) or any(tok in text.lower() for tok in ("<svg", "<img", "<iframe", "onerror", "onload", "javascript:", "<math", "<details", "<body", "<xss")):
            if builder.add("Injection (XSS)", text):
                added_here += 1
    print(f"  candidate tags parsed, new strings this step tracked in source total ({added_here} accepted before global dedup already applied)", flush=True)


def add_cloud(builder: Builder) -> None:
    for category, payload in CLOUD_PAYLOADS:
        builder.add(category, payload)


def update_dashboard(total: int, categories: list[tuple[str, int]]) -> None:
    script = ROOT / "script.js"
    text = script.read_text(encoding="utf-8")
    found = re.search(r"const TOTAL_PAYLOADS = (\d+);", text)
    old = int(found.group(1)) if found else total
    text = re.sub(r"const TOTAL_PAYLOADS = \d+;", f"const TOTAL_PAYLOADS = {total};", text, count=1)
    block = "const CATEGORIES = [\n" + "".join(
        f"    {{ name: {json.dumps(name)}, count: {count} }},\n" for name, count in categories
    ) + "  ];"
    text, n = re.subn(r"const CATEGORIES = \[.*?\n  \];", block, text, count=1, flags=re.S)
    if n != 1:
        raise SystemExit("Could not update CATEGORIES in script.js")
    text = text.replace(f"{old:,}", f"{total:,}")
    text = text.replace(str(old), str(total))
    script.write_text(text, encoding="utf-8", newline="\n")

    index = ROOT / "index.html"
    html_text = index.read_text(encoding="utf-8")
    html_text = html_text.replace(f"{old:,}", f"{total:,}")
    html_text = html_text.replace(f"{old / 1000:.1f}K", f"{total / 1000:.1f}K")
    index.write_text(html_text, encoding="utf-8", newline="\n")

    readme = ROOT / "README.md"
    md = readme.read_text(encoding="utf-8")
    md = md.replace(f"**{old:,} unique", f"**{total:,} unique")
    md = re.sub(r"(\| Total Payloads \| )[\d,]+", rf"\g<1>{total:,}", md, count=1)
    file_count = sum(1 for p in PAYLOADS.rglob("*.json") if p.name != "_manifest.json")
    cat_count = len(categories)
    size_mb = max(1, round(sum(p.stat().st_size for p in PAYLOADS.rglob("*.json")) / (1024 * 1024)))
    md = re.sub(r"(\| Vulnerability Categories \| )\d+", rf"\g<1>{cat_count}", md, count=1)
    md = re.sub(r"(\| Organized Files \| )\d+", rf"\g<1>{file_count}", md, count=1)
    md = re.sub(r"(\| Total Size \(JSON\) \| )~?[\d.]+ MB", rf"\g<1>~{size_mb} MB", md, count=1)
    rows = []
    for name, count in categories:
        code = OWASP.get(name, "—")
        label = f"**{name}**" if code != "—" else f"_{name}_"
        rows.append(f"| {label} | {code} | {count:,} |")
    table = "\n".join(rows)
    md, n = re.subn(
        r"(\| Category \| OWASP 2025 \| Payloads \|\n\|[-| ]+\|\n).*?(\n## Injection Points)",
        rf"\g<1>{table}\g<2>",
        md,
        count=1,
        flags=re.S,
    )
    if n != 1:
        raise SystemExit("Could not update README category table")
    md = md.replace(
        f"single file containing all {old:,} entries",
        f"single file containing all {total:,} entries",
    )
    readme.write_text(md, encoding="utf-8", newline="\n")
    print(f"Updated README, index.html, and script.js to {total:,} payloads (~{size_mb} MB, {file_count} files).", flush=True)


def prune() -> None:
    """Drop generated encoding pairs and credential-file descriptions."""
    percent_only = re.compile(r"(?:%[0-9A-Fa-f]{2}){2,}\Z")
    descriptions = (
        "printed on the",
        "created during",
        "same as ",
        "stored base-64",
        "stored base64",
        "this secret is stored",
    )
    jobs = [
        (
            PAYLOADS / "mishandling_of_exceptional_conditions_(null_type_zero_errors)" / "query_parameter.json",
            lambda value: percent_only.fullmatch(value) is not None,
        ),
        (
            PAYLOADS / "identification_&_authentication_failures_(weak_passwords)" / "query_parameter.json",
            lambda value: any(bit in value.lower() for bit in descriptions),
        ),
    ]
    for path, reject in jobs:
        raw = path.read_bytes()
        newline = "\r\n" if b"\r\n" in raw[:800] else "\n"
        entries = json.loads(raw.decode("utf-8"))
        kept = [entry for entry in entries if not reject(entry.get("payload_string", ""))]
        removed = len(entries) - len(kept)
        text = json.dumps(kept, indent=2, ensure_ascii=False)
        if newline == "\r\n":
            text = text.replace("\n", "\r\n")
        path.write_bytes((text + newline).encode("utf-8"))
        print(f"removed {removed:,} from {path.name} ({len(kept):,} remain)", flush=True)

    groups: dict[str, dict[str, dict]] = defaultdict(dict)
    for path in sorted(PAYLOADS.rglob("*.json")):
        if path.name == "_manifest.json":
            continue
        entries = json.loads(path.read_text(encoding="utf-8"))
        if not entries:
            continue
        cat = entries[0]["vulnerability_category"]
        point = entries[0]["injection_point"]
        groups[cat][point] = {
            "file": path.relative_to(PAYLOADS).as_posix(),
            "count": len(entries),
        }
    summary_cats = {}
    for cat in sorted(groups):
        files = groups[cat]
        summary_cats[cat] = {
            "folder": sanitize_filename(cat),
            "total": sum(item["count"] for item in files.values()),
            "files": {point: files[point] for point in sorted(files)},
        }
    total = sum(cat["total"] for cat in summary_cats.values())
    summary = {
        "total_payloads": total,
        "total_categories": len(summary_cats),
        "total_files": sum(len(cat["files"]) for cat in summary_cats.values()),
        "categories": summary_cats,
    }
    (PAYLOADS / "_manifest.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    ranked = sorted(
        ((cat, info["total"]) for cat, info in summary_cats.items()),
        key=lambda item: (-item[1], item[0]),
    )
    update_dashboard(total, ranked)
    print(f"pruned dataset total: {total:,}", flush=True)


def _current_total() -> int:
    manifest = PAYLOADS / "_manifest.json"
    if not manifest.exists():
        return 0
    data = json.loads(manifest.read_text(encoding="utf-8"))
    return int(data.get("total_payloads") or 0)


def write_sync_result(added: int, by_source: dict[str, int], total_after: int, elapsed: int) -> None:
    """Machine-readable summary for the sync log. Not published on its own."""
    payload = {
        "added": added,
        "total_after": total_after,
        "elapsed_seconds": elapsed,
        "sources": [
            {"name": name, "added": count}
            for name, count in sorted(by_source.items(), key=lambda item: (-item[1], item[0]))
            if count
        ],
    }
    path = ROOT / "_sync_result.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    started = time.time()
    builder = Builder()
    builder.load_existing()

    jobs = [
        ("PayloadsAllTheThings", lambda: walk_wordlists(builder, SOURCES / "PayloadsAllTheThings")),
        ("SecLists", lambda: walk_wordlists(builder, SOURCES / "SecLists")),
        ("fuzzdb", lambda: walk_wordlists(builder, SOURCES / "fuzzdb")),
        ("xss-payload-list", lambda: walk_wordlists(builder, SOURCES / "xss-payload-list")),
        ("LFISuite", lambda: walk_wordlists(builder, SOURCES / "LFISuite")),
        ("naughty-strings", lambda: walk_wordlists(builder, SOURCES / "naughty-strings")),
        ("commix", lambda: (walk_wordlists(builder, SOURCES / "commix"), walk_commix_modules(builder, SOURCES / "commix"))),
        ("nuclei-templates", lambda: walk_nuclei(builder, SOURCES / "nuclei-templates")),
        ("sqlmap", lambda: walk_sqlmap(builder, SOURCES / "sqlmap")),
        ("exploitdb", lambda: walk_exploits(builder, SOURCES / "exploitdb")),
        ("PortSwigger XSS Cheat Sheet", lambda: fetch_portswigger(builder)),
        ("Cloud & Container References", lambda: add_cloud(builder)),
    ]

    for name, fn in jobs:
        print(f"\n== {name} ==", flush=True)
        before = sum(builder.added_by_source.values())
        builder.source = name
        fn()
        after = sum(builder.added_by_source.values())
        print(f"  new unique payloads: {after - before:,}", flush=True)

    print("\nWriting payload files...", flush=True)
    added = builder.flush()
    elapsed = int(time.time() - started)
    print(f"\nAdded {added:,} payloads in {elapsed}s", flush=True)
    for name, count in builder.added_by_source.items():
        print(f"  {name}: {count:,}", flush=True)

    if added == 0:
        write_sync_result(0, {}, _current_total(), elapsed)
        print("No new payloads. Leaving the published files unchanged.", flush=True)
        return

    if builder.skipped_files:
        builder.skipped_files.sort(key=lambda item: item[1], reverse=True)
        print("\nLargest unclassified wordlist files (not imported):")
        for path, size in builder.skipped_files[:25]:
            print(f"  {size/1024:.0f} KB  {path}")

    totals: dict[str, int] = defaultdict(int)
    for (cat, _point), slot in builder.meta.items():
        totals[cat] += slot["count"]
    ranked = sorted(totals.items(), key=lambda item: (-item[1], item[0]))
    grand = sum(totals.values())
    update_dashboard(grand, ranked)
    write_sync_result(added, dict(builder.added_by_source), grand, elapsed)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "prune":
        prune()
    else:
        main()
